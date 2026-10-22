// Package usbdev claims the Kindle MTP interface with gousb and exposes bulk
// IN/OUT plus the interrupt drain as a small packet API.
package usbdev

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gousb"
)

const (
	inBufSize  = 16384
	evtBufSize = 64

	// drainTimeout is how long a bulk IN read waits before being reissued;
	// the daemon only answers when it has data, so idle reads time out.
	drainTimeout = 300 * time.Millisecond
	evtTimeout   = 500 * time.Millisecond

	// writeTimeout bounds a single bulk OUT transfer.
	writeTimeout = 3 * time.Second

	writeTries = 3
)

// LogFunc receives verbose trace lines; nil is a no-op.
type LogFunc func(format string, args ...any)

// Transport is a claimed Kindle MTP interface.
type Transport struct {
	ctx   *gousb.Context
	dev   *gousb.Device
	cfg   *gousb.Config
	intf  *gousb.Interface
	epIn  *gousb.InEndpoint
	epOut *gousb.OutEndpoint
	epEvt *gousb.InEndpoint

	vid   uint16
	pid   uint16
	intfN int

	mu     sync.Mutex
	inData []byte

	stop chan struct{}
	wg   sync.WaitGroup

	Log LogFunc
}

// Open finds, claims and starts draining the first Kindle matching vid/pids.
func Open(vid uint16, pids []uint16, log LogFunc) (*Transport, error) {
	ctx := gousb.NewContext()
	devs, err := ctx.OpenDevices(matchDesc(vid, pids))
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("usb enumeration: %w", err)
	}
	if len(devs) == 0 {
		ctx.Close()
		return nil, fmt.Errorf("no Kindle found (vid 0x%04x, pid %s)", vid, PIDList(pids))
	}
	dev := devs[0]
	for _, extra := range devs[1:] {
		extra.Close()
	}

	t := &Transport{ctx: ctx, dev: dev, vid: uint16(dev.Desc.Vendor), pid: uint16(dev.Desc.Product), Log: log}
	t.stop = make(chan struct{})

	if err := t.claim(); err != nil {
		t.release()
		return nil, claimHint(err)
	}
	t.start()
	return t, nil
}

// claimHint names the program that usually holds the interface when a claim
// fails as busy (see busyhint.go).
func claimHint(err error) error {
	if IsBusy(err) {
		return fmt.Errorf("%w; %s", err, busyHint())
	}
	return err
}

// PIDList renders PIDs as a comma-separated "0x1234" list.
func PIDList(pids []uint16) string {
	out := make([]string, 0, len(pids))
	for _, p := range pids {
		out = append(out, fmt.Sprintf("%#04x", p))
	}
	return strings.Join(out, ", ")
}

// Present reports whether a matching device is currently enumerated. It only
// opens the USB handle, so it is safe to poll while waiting for a replug.
func Present(vid uint16, pids []uint16) bool {
	ctx := gousb.NewContext()
	defer ctx.Close()
	devs, err := ctx.OpenDevices(matchDesc(vid, pids))
	if err != nil {
		return false
	}
	for _, d := range devs {
		d.Close()
	}
	return len(devs) > 0
}

func matchDesc(vid uint16, pids []uint16) func(*gousb.DeviceDesc) bool {
	return func(d *gousb.DeviceDesc) bool {
		if uint16(d.Vendor) != vid {
			return false
		}
		for _, p := range pids {
			if uint16(d.Product) == p {
				return true
			}
		}
		return false
	}
}

func (t *Transport) claim() error {
	if err := t.dev.SetAutoDetach(true); err != nil {
		return fmt.Errorf("usb autodetect: %w", err)
	}
	cfgNum, err := t.dev.ActiveConfigNum()
	if err != nil || cfgNum == 0 {
		cfgNum = 1
	}
	cfg, err := t.dev.Config(cfgNum)
	if err != nil {
		return fmt.Errorf("usb config %d: %w", cfgNum, err)
	}
	t.cfg = cfg

	setting := chooseSetting(cfg)
	if setting == nil {
		return fmt.Errorf("usb: no usable interface")
	}
	intf, err := cfg.Interface(setting.Number, setting.Alternate)
	if err != nil {
		return fmt.Errorf("usb claim interface %d: %w", setting.Number, err)
	}
	t.intf = intf
	t.intfN = setting.Number

	eps, err := chooseEndpoints(*setting)
	if err != nil {
		return err
	}
	if t.epIn, err = intf.InEndpoint(int(eps.in) & 0x0F); err != nil {
		return fmt.Errorf("usb bulk IN %#x: %w", eps.in, err)
	}
	if t.epOut, err = intf.OutEndpoint(int(eps.out) & 0x0F); err != nil {
		return fmt.Errorf("usb bulk OUT %#x: %w", eps.out, err)
	}
	if eps.evt != 0 {
		if t.epEvt, err = intf.InEndpoint(int(eps.evt) & 0x0F); err != nil {
			t.epEvt = nil
		}
	}
	// Clear any stale halt condition before use.
	for _, addr := range []gousb.EndpointAddress{eps.in, eps.out, eps.evt} {
		if addr != 0 {
			t.clearHalt(addr)
		}
	}
	if t.Log != nil {
		t.Log("usb: %04x:%04x intf=%#x ep_in=%#x ep_out=%#x", t.vid, t.pid, t.intfN, eps.in, eps.out)
	}
	return nil
}

// chooseSettingDesc picks the interface and alternate setting claim uses: the
// class-6 still-image (PTP/MTP) interface when present, else the first. doctor
// reports through it too, so the report cannot describe a different setting
// than the claim.
func chooseSettingDesc(cfg *gousb.ConfigDesc) (intf, alt int) {
	for i := range cfg.Interfaces {
		id := &cfg.Interfaces[i]
		if len(id.AltSettings) == 0 {
			continue
		}
		if id.AltSettings[0].Class == gousb.Class(6) {
			return i, 0
		}
	}
	if len(cfg.Interfaces) == 0 || len(cfg.Interfaces[0].AltSettings) == 0 {
		return -1, -1
	}
	return 0, 0
}

// chooseSetting returns the alternate setting claim uses, or nil when the
// configuration has no usable interface.
func chooseSetting(cfg *gousb.Config) *gousb.InterfaceSetting {
	i, j := chooseSettingDesc(&cfg.Desc)
	if i < 0 {
		return nil
	}
	return &cfg.Desc.Interfaces[i].AltSettings[j]
}

type endpointChoice struct {
	in, out, evt gousb.EndpointAddress
}

// sortedEndpoints returns s's endpoint addresses in ascending order, the order
// the transport and doctor walk them.
func sortedEndpoints(s gousb.InterfaceSetting) []gousb.EndpointAddress {
	addrs := make([]gousb.EndpointAddress, 0, len(s.Endpoints))
	for a := range s.Endpoints {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	return addrs
}

// chooseEndpoints picks the first interrupt IN, bulk IN and bulk OUT in
// endpoint-address order.
func chooseEndpoints(s gousb.InterfaceSetting) (endpointChoice, error) {
	var c endpointChoice
	for _, a := range sortedEndpoints(s) {
		ep := s.Endpoints[a]
		in := ep.Direction == gousb.EndpointDirectionIn
		switch ep.TransferType {
		case gousb.TransferTypeInterrupt:
			if in && c.evt == 0 {
				c.evt = a
			}
		case gousb.TransferTypeBulk:
			switch {
			case in && c.in == 0:
				c.in = a
			case !in && c.out == 0:
				c.out = a
			}
		}
	}
	if c.in == 0 || c.out == 0 {
		return c, fmt.Errorf("usb: no bulk pair on interface %d", s.Number)
	}
	return c, nil
}

func (t *Transport) start() {
	t.wg.Add(1)
	go t.inLoop()
	if t.epEvt != nil {
		t.wg.Add(1)
		go t.evtLoop()
	}
}

// inLoop keeps the bulk IN endpoint drained so the daemon never blocks writing.
func (t *Transport) inLoop() {
	defer t.wg.Done()
	buf := make([]byte, inBufSize)
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		n, err := t.epIn.ReadContext(ctx, buf)
		cancel()
		if n > 0 {
			t.mu.Lock()
			t.inData = append(t.inData, buf[:n]...)
			t.mu.Unlock()
		}
		if err != nil && !isIdle(err) {
			select {
			case <-t.stop:
				return
			default:
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// evtLoop drains the interrupt endpoint (device events).
func (t *Transport) evtLoop() {
	defer t.wg.Done()
	buf := make([]byte, evtBufSize)
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), evtTimeout)
		_, err := t.epEvt.ReadContext(ctx, buf)
		cancel()
		if err != nil && !isIdle(err) {
			return
		}
	}
}

func isIdle(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, gousb.TransferCancelled) ||
		errors.Is(err, gousb.TransferTimedOut)
}

// Send writes a packet to bulk OUT with retries and halt recovery.
func (t *Transport) Send(pkt []byte) error {
	var last error
	for i := 0; i < writeTries; i++ {
		if err := t.writeAll(pkt); err != nil {
			last = err
			if t.Log != nil {
				t.Log("bulk OUT %v; clear_halt+retry", err)
			}
			t.clearHalts()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return nil
	}
	return last
}

func (t *Transport) writeAll(pkt []byte) error {
	for len(pkt) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		n, err := t.epOut.WriteContext(ctx, pkt)
		cancel()
		if n == 0 && err == nil {
			return fmt.Errorf("bulk OUT stalled")
		}
		pkt = pkt[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

// ReadPkt returns the buffered IN bytes, or nil if none arrive in time.
func (t *Transport) ReadPkt(timeout time.Duration) []byte {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		t.mu.Lock()
		if len(t.inData) > 0 {
			out := t.inData
			t.inData = nil
			t.mu.Unlock()
			return out
		}
		t.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// clearHalt sends the standard CLEAR_FEATURE(ENDPOINT_HALT) request.
func (t *Transport) clearHalt(addr gousb.EndpointAddress) {
	if t.dev != nil {
		t.dev.Control(0x02, 0x01, 0x0000, uint16(addr), nil)
	}
}

func (t *Transport) clearHalts() {
	for _, ep := range []gousb.EndpointAddress{t.epIn.Desc.Address, t.epOut.Desc.Address} {
		t.clearHalt(ep)
	}
	if t.epEvt != nil {
		t.clearHalt(t.epEvt.Desc.Address)
	}
}

// Describe returns the vid:pid identity for progress output.
func (t *Transport) Describe() string {
	return fmt.Sprintf("%04x:%04x", t.vid, t.pid)
}

// Close stops the drain goroutines and releases all USB resources.
func (t *Transport) Close() {
	if t.stop != nil {
		select {
		case <-t.stop:
		default:
			close(t.stop)
		}
	}
	t.wg.Wait()
	t.release()
}

func (t *Transport) release() {
	if t.intf != nil {
		t.intf.Close()
		t.intf = nil
	}
	if t.cfg != nil {
		t.cfg.Close()
		t.cfg = nil
	}
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	if t.ctx != nil {
		t.ctx.Close()
		t.ctx = nil
	}
}
