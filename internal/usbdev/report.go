package usbdev

import (
	"fmt"

	"github.com/google/gousb"
)

// Device is one Kindle device libusb can see, described for `shadow doctor`.
type Device struct {
	Bus, Addr  int
	VID, PID   uint16
	Serial     string
	Config     int
	Interfaces []Interface
}

// Interface is one alternate setting of one interface.
type Interface struct {
	Number    int
	Alternate int
	Class     uint8
	SubClass  uint8
	Protocol  uint8
	Selected  bool
	Endpoints []Endpoint
}

// Endpoint is one endpoint of an interface alternate setting; Chosen marks the
// endpoints the transport uses.
type Endpoint struct {
	Address   gousb.EndpointAddress
	Transfer  string
	Input     bool
	MaxPacket int
	Chosen    bool
}

func (e Endpoint) String() string {
	// gousb.EndpointAddress is a Stringer that already renders "0x83"; %x would
	// hex-encode that string instead of the address.
	dir := "OUT"
	if e.Input {
		dir = "IN"
	}
	return fmt.Sprintf("%s %s %s maxpacket %d", e.Address, e.Transfer, dir, e.MaxPacket)
}

// ClassString renders class/subclass/protocol, naming the classes the Kindle
// uses.
func (i Interface) ClassString() string {
	s := fmt.Sprintf("%d/%d/%d", i.Class, i.SubClass, i.Protocol)
	switch i.Class {
	case 6:
		return s + " (still image/MTP)"
	case 255:
		return s + " (vendor specific)"
	case 0:
		return s + " (per interface)"
	}
	return s
}

// Enumerate lists the devices libusb can see for vid/pids, with the descriptors
// the transport would use. On Windows only devnodes bound to a libusb-compatible
// driver appear here; Linux and macOS detach or bind the kernel driver
// themselves.
func Enumerate(vid uint16, pids []uint16) ([]Device, error) {
	ctx := gousb.NewContext()
	defer ctx.Close()
	devs, err := ctx.OpenDevices(matchDesc(vid, pids))
	if err != nil {
		return nil, fmt.Errorf("usb enumeration: %w", err)
	}
	out := make([]Device, 0, len(devs))
	for _, dev := range devs {
		out = append(out, describe(dev))
		dev.Close()
	}
	return out, nil
}

// describe mirrors claim()'s choices, so the report cannot describe a different
// setting than the transport claims.
func describe(dev *gousb.Device) Device {
	d := Device{
		Bus:  dev.Desc.Bus,
		Addr: dev.Desc.Address,
		VID:  uint16(dev.Desc.Vendor),
		PID:  uint16(dev.Desc.Product),
	}
	if serial, err := dev.SerialNumber(); err == nil {
		d.Serial = serial
	}
	cfgNum := 1
	if n, err := dev.ActiveConfigNum(); err == nil && n != 0 {
		cfgNum = n
	}
	d.Config = cfgNum
	cfg, ok := dev.Desc.Configs[cfgNum]
	if !ok {
		return d
	}
	intfIdx, altIdx := chooseSettingDesc(&cfg)
	for i := range cfg.Interfaces {
		id := &cfg.Interfaces[i]
		for j := range id.AltSettings {
			set := &id.AltSettings[j]
			iface := Interface{
				Number:    set.Number,
				Alternate: set.Alternate,
				Class:     uint8(set.Class),
				SubClass:  uint8(set.SubClass),
				Protocol:  uint8(set.Protocol),
				Selected:  i == intfIdx && j == altIdx,
			}
			used, _ := chooseEndpoints(*set)
			for _, a := range sortedEndpoints(*set) {
				ep := set.Endpoints[a]
				iface.Endpoints = append(iface.Endpoints, Endpoint{
					Address:   ep.Address,
					Transfer:  transferName(ep.TransferType),
					Input:     ep.Direction == gousb.EndpointDirectionIn,
					MaxPacket: ep.MaxPacketSize,
					Chosen:    a == used.in || a == used.out || a == used.evt,
				})
			}
			d.Interfaces = append(d.Interfaces, iface)
		}
	}
	return d
}

// transferName labels an endpoint transfer type; control endpoints never appear
// in a descriptor, so the default is isochronous.
func transferName(t gousb.TransferType) string {
	switch t {
	case gousb.TransferTypeBulk:
		return "bulk"
	case gousb.TransferTypeInterrupt:
		return "interrupt"
	default:
		return "isochronous"
	}
}
