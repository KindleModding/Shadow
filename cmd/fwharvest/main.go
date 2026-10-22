//go:build linux

// Command fwharvest turns a Kindle firmware image into the offsets JSON that
// shadow embeds. It is Linux-only by nature: the measurement stages run the
// firmware's own responder under qemu-arm inside `unshare -rm`, and stage
// timeouts kill the whole process group (syscall.SysProcAttr.Setpgid), which
// has no direct Windows equivalent. Run it on Linux (or WSL) and commit the
// firmware/*.json it produces.
package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	statusOK       = "ok"
	statusPartial  = "partial"
	statusSkipped  = "skipped"
	statusError    = "error"
	schemaVersion  = 1
	harvestVersion = "0.2.0"
)

type offsets struct {
	System              int64  `json:"system"`
	SystemARM           int64  `json:"system_arm"`
	PopGadget           int64  `json:"pop_gadget"`
	PopGadgetMask       int64  `json:"pop_gadget_mask"`
	LdrBlxGadget        int64  `json:"ldr_blx_gadget"`
	GotBase             int64  `json:"got_base"`
	StackDelta          *int64 `json:"stack_delta"`
	StackDeltaSupported bool   `json:"stack_delta_supported"`
	StackDeltaVerified  bool   `json:"stack_delta_verified"`
}

type leakInfo struct {
	Slot4RawOff     int    `json:"slot4_raw_off"`
	Slot16RawOff    int    `json:"slot16_raw_off"`
	AnchorLow12     *int64 `json:"anchor_low12,omitempty"`
	RecipeSupported *bool  `json:"recipe_supported,omitempty"`
	RecipeDetail    string `json:"recipe_detail,omitempty"`
}

type usbInfo struct {
	VID  string   `json:"vid"`
	PIDs []string `json:"pids"`
}

type record struct {
	SchemaVersion int               `json:"schema_version"`
	HarvestedAt   string            `json:"harvested_at"`
	BuildKey      string            `json:"build_key"`
	VersionString string            `json:"version_string"`
	PrettyVersion string            `json:"pretty_version,omitempty"`
	Version       string            `json:"version,omitempty"`
	Models        []string          `json:"models"`
	Source        map[string]any    `json:"source"`
	TizenMTP      string            `json:"tizen_mtp_sha256"`
	Offsets       offsets           `json:"offsets"`
	Leak          leakInfo          `json:"leak"`
	USB           usbInfo           `json:"usb"`
	Tools         map[string]string `json:"tools"`
	Fwderive      json.RawMessage   `json:"fwderive,omitempty"`
	Stackdelta    json.RawMessage   `json:"stackdelta_measurement,omitempty"`
	ChainVerify   json.RawMessage   `json:"chain_verification,omitempty"`
	Evidence      json.RawMessage   `json:"elfscan_evidence,omitempty"`
	Limitations   []string          `json:"limitations,omitempty"`
	Notes         string            `json:"notes"`
}

type elfscanResult struct {
	SHA256      string          `json:"sha256"`
	Offsets     offsets         `json:"offsets"`
	Evidence    json.RawMessage `json:"evidence"`
	Limitations []string        `json:"limitations"`
}

type stackdeltaResult struct {
	StackDelta         *int64          `json:"stack_delta"`
	StackDeltaVerified bool            `json:"stack_delta_verified"`
	AnchorLow12        int64           `json:"anchor_low12"`
	AnchorHex          string          `json:"anchor_hex"`
	ReceiverSPHex      string          `json:"receiver_sp_hex"`
	Checks             map[string]bool `json:"checks"`
}

type chainResult struct {
	Verified      bool `json:"verified"`
	MarkerPresent bool `json:"marker_present"`
}

type fwderiveResult struct {
	Anchors map[string]struct {
		Addr *string `json:"addr"`
	} `json:"anchors"`
}

type itemResult struct {
	Bin    string
	Key    string
	Status string
	Stage  string
	Reason string
}

type options struct {
	bin, rootfs, workdir, firmwareDir, toolDir string
	files                                      string
	all, force, failFast                       bool
	skipStack, skipChain                       bool
	stackdeltaPy, chainverifyPy, fwderivePy    string
	references                                 string
}

var (
	versionRe     = regexp.MustCompile(`^\s*System Software Version:\s*(\d+)-[^\s]*-(\d{6})\s*$`)
	targetOTARe   = regexp.MustCompile(`(?m)^\s*Target OTA\s+(\S+)\s*$`)
	activeWorkdir string
)

func main() {
	var op options
	flag.StringVar(&op.bin, "bin", "", "Amazon update_kindle_*.bin")
	flag.StringVar(&op.rootfs, "rootfs", "", "pre-extracted rootfs.img (skips kindletool+gunzip)")
	flag.StringVar(&op.workdir, "workdir", "", "working directory (default build/fw/<bin name>)")
	flag.StringVar(&op.firmwareDir, "firmware-dir", "firmware", "output directory for JSON records")
	flag.StringVar(&op.toolDir, "tool-dir", "", "directory containing ext4get/elfscan/fwharvest")
	flag.StringVar(&op.files, "files", "", "comma-separated bins to re-check (bypasses already-harvested skip)")
	flag.BoolVar(&op.all, "all", false, "process every firmwares/*/*.bin")
	flag.BoolVar(&op.force, "force", false, "re-run every stage and replace existing records (archives the old JSON)")
	flag.BoolVar(&op.failFast, "fail-fast", false, "stop the batch on the first error")
	flag.BoolVar(&op.skipStack, "skip-stackdelta", false, "do not run the stackdelta measurement")
	flag.BoolVar(&op.skipChain, "skip-chainverify", false, "do not run the chain verification")
	flag.StringVar(&op.stackdeltaPy, "stackdelta", "", "path to tools/stackdelta/measure.py")
	flag.StringVar(&op.chainverifyPy, "chainverify", "", "path to tools/chainverify/verify.py")
	flag.StringVar(&op.fwderivePy, "fwderive", "", "path to tools/fwderive/derive.py")
	flag.StringVar(&op.references, "references", "", "fwderive reference directory (default tools/fwderive/references)")
	flag.Parse()

	var results []itemResult
	switch {
	case op.all && op.files != "":
		fatal("--all and --files are mutually exclusive")
	case op.all:
		bins, err := filepath.Glob(filepath.Join("firmwares", "*", "*.bin"))
		if err != nil || len(bins) == 0 {
			fatal("no firmwares/*/*.bin found")
		}
		for _, b := range bins {
			r := runOne(op, b, "", false)
			results = append(results, r)
			if r.Status == statusError && op.failFast {
				break
			}
		}
	case op.files != "":
		for _, f := range strings.Split(op.files, ",") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			r := runOne(op, f, "", true)
			results = append(results, r)
			if r.Status == statusError && op.failFast {
				break
			}
		}
	case op.bin != "":
		results = append(results, runOne(op, op.bin, "", false))
	case op.rootfs != "":
		results = append(results, runOne(op, "", op.rootfs, false))
	default:
		fmt.Fprintln(os.Stderr, "usage: fwharvest --bin <update.bin> [--workdir dir] [--skip-stackdelta]")
		fmt.Fprintln(os.Stderr, "       fwharvest --rootfs <rootfs.img>")
		fmt.Fprintln(os.Stderr, "       fwharvest --all [--force] [--fail-fast]")
		fmt.Fprintln(os.Stderr, "       fwharvest --files a.bin,b.bin")
		os.Exit(2)
	}

	{
		fmt.Printf("\n== summary (%d item(s)) ==\n", len(results))
		errors := 0
		for _, r := range results {
			fmt.Printf("  %-8s %-12s %s", r.Status, r.Key, r.Bin)
			if r.Stage != "" {
				fmt.Printf(" [%s]", r.Stage)
			}
			if r.Reason != "" {
				fmt.Printf(" %s", r.Reason)
			}
			fmt.Println()
			if r.Status == statusError {
				errors++
			}
		}
		if errors > 0 {
			fmt.Printf("  %d error(s)\n", errors)
		}
	}
	for _, r := range results {
		if r.Status == statusError {
			os.Exit(1)
		}
	}
}

func runOne(op options, bin, rootfsIn string, recheck bool) itemResult {
	res := itemResult{Bin: firstNonEmpty(bin, rootfsIn), Status: statusError}
	workdir := op.workdir
	if workdir == "" {
		stem := strings.TrimSuffix(filepath.Base(firstNonEmpty(bin, rootfsIn)), filepath.Ext(bin))
		if bin == "" {
			stem = strings.TrimSuffix(filepath.Base(rootfsIn), ".img")
		}
		workdir = filepath.Join("build", "fw", stem)
	}
	if err := preCleanWorkdir(workdir); err != nil {
		res.Reason = err.Error()
		return res
	}
	activeWorkdir = workdir
	defer func() {
		if err := cleanupWorkdir(workdir); err != nil {
			fmt.Fprintln(os.Stderr, "fwharvest: cleanup:", err)
		}
		activeWorkdir = ""
	}()
	for _, d := range []string{workdir, filepath.Join(workdir, "logs"), op.firmwareDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			res.Reason = err.Error()
			return res
		}
	}
	fmt.Printf("== fwharvest: %s\n   workdir %s\n", res.Bin, workdir)

	source := map[string]any{}
	prettyVersion := ""
	var binSHA string
	if bin != "" {
		sum, size, err := fileHash(bin)
		if err != nil {
			res.Reason = err.Error()
			return res
		}
		binSHA = sum
		source["file"] = filepath.Base(bin)
		source["size"] = size
		source["sha256"] = sum
		if !op.force && !recheck {
			if key, ok := harvestedIndex(op.firmwareDir)[sum]; ok {
				res.Status = statusSkipped
				res.Key = key
				res.Reason = "already harvested"
				fmt.Printf("   skipped: already harvested as %s\n", key)
				return res
			}
		}
	}

	rootfsImg := rootfsIn
	if bin != "" {
		unpacked := filepath.Join(workdir, "unpacked")
		gz := filepath.Join(unpacked, "rootfs.img.gz")
		if op.force || !exists(gz) {
			kt, err := tool(op, "kindletool")
			if err != nil {
				res.Reason = err.Error()
				return res
			}
			code, logPath, err := runStage(kt, []string{"extract", bin, unpacked}, workdir, "kindletool")
			if err != nil {
				res.Stage, res.Reason = "kindletool", err.Error()
				return res
			}
			if code != 0 {
				res.Status, res.Stage = statusSkipped, "kindletool"
				res.Reason = "not an extractable update package: " + tailLog(logPath, 3)
				return res
			}
			if devices := parseDevices(logPath); len(devices) > 0 {
				_ = os.WriteFile(filepath.Join(workdir, "kindletool_devices.txt"),
					[]byte(strings.Join(devices, "\n")+"\n"), 0o644)
			}
		}
		if devices := loadDevices(workdir); len(devices) > 0 {
			source["kindletool_devices"] = devices
		}
		rootfsImg = filepath.Join(workdir, "rootfs.img")
		if op.force || !exists(rootfsImg) {
			if err := gunzipFile(gz, rootfsImg); err != nil {
				res.Stage, res.Reason = "gunzip", err.Error()
				return res
			}
		}
	}
	sum, size, err := fileHash(rootfsImg)
	if err != nil {
		res.Stage, res.Reason = "rootfs", err.Error()
		return res
	}
	source["rootfs_sha256"] = sum
	source["rootfs_size"] = size

	rootfsDir := filepath.Join(workdir, "rootfs")
	if op.force || !exists(filepath.Join(rootfsDir, "etc/version.txt")) {
		eg, err := tool(op, "ext4get")
		if err != nil {
			res.Reason = err.Error()
			return res
		}
		code, logPath, err := runStage(eg, []string{"-image", rootfsImg, "-extract-all", rootfsDir}, workdir, "ext4get")
		if err != nil {
			res.Stage, res.Reason = "ext4get", err.Error()
			return res
		}
		if code == 3 {
			res.Status, res.Stage = statusSkipped, "ext4get"
			res.Reason = tailLog(logPath, 2)
			return res
		}
		if code != 0 {
			res.Stage, res.Reason = "ext4get", fmt.Sprintf("exit %d: %s", code, tailLog(logPath, 2))
			return res
		}
	}

	versionString, key, err := parseVersion(filepath.Join(rootfsDir, "etc/version.txt"))
	if err != nil {
		res.Status, res.Stage = statusSkipped, "version"
		res.Reason = err.Error()
		return res
	}
	res.Key = key
	if target := parseTargetOTA(filepath.Join(workdir, "logs", "kindletool.log")); target != "" {
		source["kindletool_target_ota"] = target
		if target != key {
			res.Stage = "key-check"
			res.Reason = fmt.Sprintf("build key mismatch: version.txt -> %s, kindletool Target OTA -> %s", key, target)
			return res
		}
	}
	if binSHA != "" {
		if err := checkCollision(op, key, binSHA); err != nil {
			res.Stage, res.Reason = "collision", err.Error()
			return res
		}
	}
	if pv, err := os.ReadFile(filepath.Join(rootfsDir, "etc/prettyversion.txt")); err == nil {
		if s := strings.TrimSpace(string(pv)); s != "" {
			prettyVersion = s
		}
	}
	if glibSum, _, err := fileHash(filepath.Join(rootfsDir, "usr/lib/libglib-2.0.so.0")); err == nil {
		source["libglib_sha256"] = glibSum
	}
	tizenPath := filepath.Join(rootfsDir, "usr/bin/tizen-mtp")
	tizenSum, _, err := fileHash(tizenPath)
	if err != nil {
		res.Status, res.Stage = statusSkipped, "tizen-mtp"
		res.Reason = "responder binary not present"
		return res
	}
	fmt.Printf("   build key %s, tizen-mtp %s\n", key, tizenSum[:16])

	rec := record{
		SchemaVersion: schemaVersion,
		HarvestedAt:   time.Now().UTC().Format(time.RFC3339),
		BuildKey:      key,
		VersionString: versionString,
		PrettyVersion: prettyVersion,
		Version:       guessVersion(bin),
		Models:        modelsFromKindletool(source),
		Source:        source,
		TizenMTP:      tizenSum,
		Leak:          leakInfo{Slot4RawOff: 2, Slot16RawOff: 14},
		USB:           usbInfo{VID: "1949", PIDs: []string{"9981"}},
		Tools:         map[string]string{"fwharvest": harvestVersion},
	}
	if kt, err := tool(op, "kindletool"); err == nil {
		if out, err := exec.Command(kt, "--version").Output(); err == nil {
			rec.Tools["kindletool"] = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		}
	}

	es, err := tool(op, "elfscan")
	if err != nil {
		res.Reason = err.Error()
		return res
	}
	elfJSON := filepath.Join(workdir, "elfscan.json")
	if op.force || !exists(elfJSON) {
		code, logPath, err := runStage(es, []string{"-elf", tizenPath, "-o", elfJSON}, workdir, "elfscan")
		if err != nil {
			res.Stage, res.Reason = "elfscan", err.Error()
			return res
		}
		if code != 0 {
			res.Status, res.Stage = statusSkipped, "elfscan"
			res.Reason = "unrecognized build: " + tailLog(logPath, 2)
			return res
		}
	}
	var scan elfscanResult
	if err := readJSON(elfJSON, &scan); err != nil {
		res.Stage, res.Reason = "elfscan", err.Error()
		return res
	}
	if scan.SHA256 != tizenSum {
		res.Stage = "elfscan"
		res.Reason = fmt.Sprintf("sha256 mismatch: elfscan %s != %s", scan.SHA256, tizenSum)
		return res
	}
	rec.Offsets = offsets{
		System:        scan.Offsets.System,
		SystemARM:     scan.Offsets.SystemARM,
		PopGadget:     scan.Offsets.PopGadget,
		PopGadgetMask: scan.Offsets.PopGadgetMask,
		LdrBlxGadget:  scan.Offsets.LdrBlxGadget,
		GotBase:       scan.Offsets.GotBase,
	}
	rec.Evidence = scan.Evidence
	for _, l := range scan.Limitations {
		rec.Limitations = append(rec.Limitations, "elfscan: "+l)
	}

	if !op.skipStack || !op.skipChain {
		fd, err := resolveScript(op.fwderivePy, "tools/fwderive/derive.py")
		refs := op.references
		if refs == "" {
			refs = filepath.Join(filepath.Dir(filepath.Dir(fd)), "fwderive", "references")
			if exe, err := os.Executable(); err == nil {
				refs = filepath.Join(filepath.Dir(filepath.Dir(exe)), "tools", "fwderive", "references")
			}
		}
		if err != nil {
			rec.Limitations = append(rec.Limitations, "derivation unavailable: "+err.Error())
		} else {
			derivedJSON := filepath.Join(workdir, "derived.json")
			code, logPath, err := runStage("python3", []string{fd, "match",
				"--elf", tizenPath, "--refs", refs, "--out", derivedJSON}, workdir, "fwderive")
			if err != nil {
				res.Stage, res.Reason = "fwderive", err.Error()
				return res
			}
			if code == 3 {
				rec.Limitations = append(rec.Limitations, "unsupported build: "+tailLog(logPath, 2))
			} else if code != 0 {
				res.Stage, res.Reason = "fwderive", fmt.Sprintf("exit %d: %s", code, tailLog(logPath, 2))
				return res
			} else {
				if raw, err := os.ReadFile(derivedJSON); err == nil {
					rec.Fwderive = raw
				}
				var derived fwderiveResult
				if err := readJSON(derivedJSON, &derived); err != nil {
					res.Stage, res.Reason = "fwderive", err.Error()
					return res
				}
				rx, inj := anchorAddr(derived, "rx_copy"), anchorAddr(derived, "inject_event")
				if rx == "" || inj == "" {
					rec.Limitations = append(rec.Limitations, "derived build anchors missing")
				} else if runStackAndChain(op, &rec, &res, workdir, rootfsDir, tizenPath, elfJSON, rx, inj) {
					return res
				}
			}
		}
	}

	rec.Notes = "offsets decimal; build key = <last6 of version line>+0+<leading build number>; " +
		"stack_delta measured under qemu with the firmware's own libc; chain_verification fires the " +
		"offline ROP built from derived constants and requires the observable side effect"

	if op.skipStack || op.skipChain {
		rec.Limitations = append(rec.Limitations, "measurement stages skipped by flag")
	}
	if len(rec.Limitations) > 0 {
		res.Status = statusPartial
	} else {
		res.Status = statusOK
	}

	if err := writeRecord(op, rec, binSHA); err != nil {
		res.Status, res.Stage, res.Reason = statusError, "record", err.Error()
		return res
	}
	fmt.Printf("   wrote %s (%s)\n", filepath.Join(op.firmwareDir, key+".json"), res.Status)
	return res
}

func runStackAndChain(op options, rec *record, res *itemResult, workdir, rootfsDir, tizenPath, elfJSON, rx, inj string) (abort bool) {
	if !op.skipStack {
		sd, err := resolveScript(op.stackdeltaPy, "tools/stackdelta/measure.py")
		if err != nil {
			rec.Limitations = append(rec.Limitations, "stackdelta unavailable: "+err.Error())
		} else {
			stackJSON := filepath.Join(workdir, "stackdelta.json")
			code, logPath, err := runStage("python3", []string{sd,
				"--mtp", tizenPath, "--rootfs", rootfsDir,
				"--workdir", filepath.Join(workdir, "stackdelta"),
				"--out", stackJSON,
				"--rx-copy-site", rx, "--inject-event-fn", inj}, workdir, "stackdelta")
			if err != nil {
				res.Stage, res.Reason = "stackdelta", err.Error()
				return true
			}
			var sdRes stackdeltaResult
			haveJSON := readJSON(stackJSON, &sdRes) == nil
			if haveJSON {
				if raw, err := os.ReadFile(stackJSON); err == nil {
					rec.Stackdelta = raw
				}
				rec.Offsets.StackDelta = sdRes.StackDelta
				rec.Offsets.StackDeltaSupported = code == 0
				rec.Offsets.StackDeltaVerified = sdRes.StackDeltaVerified
				anchor := sdRes.AnchorLow12
				rec.Leak.AnchorLow12 = &anchor
				rec.Tools["stackdelta"] = fmt.Sprintf("delta=%s anchor=%s sp=%s verified=%t",
					formatHexPtr(sdRes.StackDelta), sdRes.AnchorHex, sdRes.ReceiverSPHex,
					sdRes.StackDeltaVerified)
			}
			detail := tailLog(logPath, 2)
			supported := code == 0
			if haveJSON && sdRes.StackDelta != nil {
				rec.Leak.RecipeSupported = &supported
			}
			switch {
			case code == 3 && strings.Contains(detail, "no n>=8 leak"):
				rec.Leak.RecipeSupported = &supported
				rec.Leak.RecipeDetail = detail
				rec.Limitations = append(rec.Limitations,
					"bug-2 timestring leak does not reproduce on this branch: "+detail)
			case code == 3:
				rec.Limitations = append(rec.Limitations, "stackdelta unsupported: "+detail)
			case code == 1 && haveJSON:
				rec.Limitations = append(rec.Limitations, "stackdelta measurement not verified")
			case code != 0:
				res.Stage, res.Reason = "stackdelta", fmt.Sprintf("exit %d: %s", code, detail)
				return true
			}
			if code == 0 {
				t := true
				rec.Leak.RecipeSupported = &t
			}
		}
	}

	if op.skipChain || rec.Offsets.StackDelta == nil {
		return false
	}
	cv, err := resolveScript(op.chainverifyPy, "tools/chainverify/verify.py")
	if err != nil {
		rec.Limitations = append(rec.Limitations, "chainverify unavailable: "+err.Error())
		return false
	}
	chainJSON := filepath.Join(workdir, "chainverify.json")
	code, logPath, err := runStage("python3", []string{cv,
		"--mtp", tizenPath, "--rootfs", rootfsDir,
		"--workdir", filepath.Join(workdir, "chainverify"),
		"--elfscan", elfJSON, "--out", chainJSON,
		"--rx-copy-site", rx, "--inject-event-fn", inj}, workdir, "chainverify")
	if err != nil {
		res.Stage, res.Reason = "chainverify", err.Error()
		return true
	}
	var chRes chainResult
	haveJSON := readJSON(chainJSON, &chRes) == nil
	if raw, err := os.ReadFile(chainJSON); err == nil && haveJSON {
		rec.ChainVerify = raw
	}
	if code == 0 && chRes.Verified {
		rec.Offsets.StackDeltaVerified = true
		rec.Tools["chainverify"] = "verified (marker side effect observed)"
	} else {
		rec.Offsets.StackDeltaVerified = false
		rec.Tools["chainverify"] = fmt.Sprintf("not verified (exit %d)", code)
		rec.Limitations = append(rec.Limitations, "chain verification failed: "+tailLog(logPath, 2))
	}
	return false
}

func writeRecord(op options, rec record, binSHA string) error {
	outPath := filepath.Join(op.firmwareDir, rec.BuildKey+".json")
	if exists(outPath) {
		var prev record
		prevSHA := ""
		if err := readJSON(outPath, &prev); err == nil {
			if v, ok := prev.Source["sha256"].(string); ok {
				prevSHA = v
			}
		}
		if z, ok := prev.Source["rootfs_sha256"]; ok && binSHA == "" {
			prevSHA, _ = z.(string)
		}
		newSHA := binSHA
		if newSHA == "" {
			newSHA, _ = rec.Source["rootfs_sha256"].(string)
		}
		if prevSHA != "" && newSHA != "" && prevSHA != newSHA {
			if !op.force {
				return fmt.Errorf("build key collision: %s already harvested from a different source (%s...); use --force to replace",
					rec.BuildKey, prevSHA[:12])
			}
			if err := archiveRecord(op.firmwareDir, rec.BuildKey); err != nil {
				return fmt.Errorf("archive previous record: %w", err)
			}
			fmt.Printf("   archived previous %s.json\n", rec.BuildKey)
		}
	}
	if err := writeJSON(outPath, rec); err != nil {
		return err
	}
	return writeIndex(op.firmwareDir)
}

func checkCollision(op options, key, binSHA string) error {
	outPath := filepath.Join(op.firmwareDir, key+".json")
	if !exists(outPath) || op.force {
		return nil
	}
	var prev record
	if err := readJSON(outPath, &prev); err != nil {
		return nil
	}
	if prevSHA, ok := prev.Source["sha256"].(string); ok && prevSHA != "" && prevSHA != binSHA {
		return fmt.Errorf("build key collision: %s already harvested from a different source (%s...); use --force to replace",
			key, prevSHA[:12])
	}
	return nil
}

func archiveRecord(dir, key string) error {
	data, err := os.ReadFile(filepath.Join(dir, key+".json"))
	if err != nil {
		return err
	}
	archive := filepath.Join(dir, "archive")
	if err := os.MkdirAll(archive, 0o755); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	return os.WriteFile(filepath.Join(archive, fmt.Sprintf("%s-%s.json", key, stamp)), data, 0o644)
}

func harvestedIndex(dir string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "db.json" {
			continue
		}
		var rec record
		if err := readJSON(filepath.Join(dir, e.Name()), &rec); err != nil {
			continue
		}
		if sha, ok := rec.Source["sha256"].(string); ok && sha != "" {
			out[sha] = rec.BuildKey
		}
	}
	return out
}

func anchorAddr(d fwderiveResult, name string) string {
	a, ok := d.Anchors[name]
	if !ok || a.Addr == nil {
		return ""
	}
	return *a.Addr
}

func resolveScript(override, rel string) (string, error) {
	if override != "" {
		if !exists(override) {
			return "", fmt.Errorf("%s not found", override)
		}
		return override, nil
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(filepath.Dir(exe)), rel)
		if exists(cand) {
			return cand, nil
		}
	}
	if exists(rel) {
		return rel, nil
	}
	return "", fmt.Errorf("%s not found", rel)
}

func stageTimeout(stage string) time.Duration {
	switch stage {
	case "kindletool":
		return 20 * time.Minute
	case "stackdelta", "chainverify":
		return 5 * time.Minute
	case "elfscan", "fwderive":
		return 3 * time.Minute
	default:
		return 10 * time.Minute
	}
}

func runStage(name string, args []string, workdir, stage string) (int, string, error) {
	timeout := stageTimeout(stage)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	logPath := filepath.Join(workdir, "logs", stage+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		return -1, logPath, err
	}
	defer lf.Close()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.MultiWriter(lf, os.Stdout)
	cmd.Stderr = io.MultiWriter(lf, os.Stderr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, logPath, fmt.Errorf("stage %s timed out after %s", stage, timeout)
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), logPath, nil
		}
		return -1, logPath, err
	}
	return 0, logPath, nil
}

func tailLog(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var out []string
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			out = append([]string{strings.TrimSpace(lines[i])}, out...)
		}
	}
	return strings.Join(out, " | ")
}

func parseDevices(logPath string) []string {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Device ") {
			out = append(out, line)
		}
	}
	return out
}

func loadDevices(workdir string) []string {
	data, err := os.ReadFile(filepath.Join(workdir, "kindletool_devices.txt"))
	if err != nil {
		return nil
	}
	var devices []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			devices = append(devices, strings.TrimSpace(line))
		}
	}
	return devices
}

func modelsFromKindletool(source map[string]any) []string {
	var models []string
	seen := map[string]bool{}
	if raw, ok := source["kindletool_devices"].([]string); ok {
		for _, line := range raw {
			m := strings.TrimSpace(strings.TrimPrefix(line, "Device"))
			if i := strings.Index(m, "(Unknown Variant"); i > 0 {
				m = strings.TrimSpace(m[:i])
			}
			if m != "" && !seen[m] {
				seen[m] = true
				models = append(models, m)
			}
		}
	}
	return models
}

func parseVersion(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return "", "", fmt.Errorf("%s is empty", path)
	}
	line := strings.TrimRight(lines[0], "\r")
	m := versionRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", fmt.Errorf("unrecognized version line: %q", line)
	}
	major := m[1]
	for len(major) < 3 {
		major = "0" + major
	}
	return line, m[2] + "0" + major, nil
}

func parseTargetOTA(logPath string) string {
	data, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	m := targetOTARe.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func guessVersion(bin string) string {
	if bin == "" {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(bin), ".bin")
	parts := strings.Split(base, "_")
	last := parts[len(parts)-1]
	for _, r := range last {
		if r != '.' && (r < '0' || r > '9') {
			return ""
		}
	}
	return last
}

func gunzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, zr); err != nil {
		return err
	}
	fmt.Printf("   gunzip -> %s\n", dst)
	return out.Sync()
}

func fileHash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeIndex(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	db := map[string]json.RawMessage{}
	var keys []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || e.Name() == "db.json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		var rec struct {
			BuildKey string `json:"build_key"`
		}
		if json.Unmarshal(data, &rec) != nil || rec.BuildKey == "" {
			return fmt.Errorf("%s: missing build_key", e.Name())
		}
		db[rec.BuildKey] = json.RawMessage(data)
		keys = append(keys, rec.BuildKey)
	}
	sort.Strings(keys)
	ordered := map[string]json.RawMessage{}
	for _, k := range keys {
		ordered[k] = db[k]
	}
	return writeJSON(filepath.Join(dir, "db.json"), ordered)
}

func tool(op options, name string) (string, error) {
	if op.toolDir != "" {
		cand := filepath.Join(op.toolDir, name)
		if exists(cand) {
			return cand, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), name)
		if exists(cand) {
			return cand, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("%s not found (build it with make, or set --tool-dir)", name)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func formatHexPtr(v *int64) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%#x", *v)
}

func cleanupWorkdir(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		return fmt.Errorf("workdir %s still exists after cleanup", dir)
	}
	return nil
}

func preCleanWorkdir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(entries) > 0 {
		marker := false
		for _, e := range entries {
			switch e.Name() {
			case "unpacked", "rootfs", "rootfs.img", "elfscan.json", "stackdelta",
				"chainverify", "stackdelta.json", "chainverify.json", "logs",
				"derived.json", "kindletool_devices.txt":
				marker = true
			}
		}
		if !marker {
			return fmt.Errorf("refusing to wipe %s: not a fwharvest workdir (use a dedicated --workdir)", dir)
		}
	}
	return cleanupWorkdir(dir)
}

func fatal(msg string) {
	if activeWorkdir != "" {
		if err := cleanupWorkdir(activeWorkdir); err != nil {
			fmt.Fprintln(os.Stderr, "fwharvest: cleanup:", err)
		}
		activeWorkdir = ""
	}
	fmt.Fprintln(os.Stderr, "fwharvest: "+msg)
	os.Exit(1)
}
