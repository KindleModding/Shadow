package usbdev

import (
	"os/exec"
	"runtime"
	"strings"
)

// busyHintFor names the program that usually holds the interface when a claim
// fails as busy, and how to get it out of the way.
func busyHintFor(goos string) string {
	switch goos {
	case "windows":
		// A stale libusb handle from another process (or a second shadow).
		return "close anything else using the Kindle (Explorer, Phone Link, another shadow), then replug it"
	case "darwin":
		// ptpcamerad grabs PTP-ish devices before anyone else.
		return "close any app using the Kindle, or run: sudo killall ptpcamerad"
	default:
		// A desktop MTP auto-mounter (kiod6 on KDE, gvfsd-mtp on GNOME).
		return "close any file-manager window showing the Kindle, or run: killall kiod6 gvfsd-mtp"
	}
}

func busyHint() string { return busyHintFor(runtime.GOOS) }

// busyClearCommand returns the command that stops the host MTP helper, or nil
// when the platform has none.
func busyClearCommand(goos string) []string {
	switch goos {
	case "linux":
		return []string{"killall", "kiod6", "gvfsd-mtp"}
	case "darwin":
		return []string{"killall", "ptpcamerad"}
	default:
		return nil
	}
}

// BusyClearCommand returns the command that stops the host MTP helper, or nil
// when the platform has none.
func BusyClearCommand() []string { return busyClearCommand(runtime.GOOS) }

// ClearBusy runs argv. A missing process is ignored; the claim retry reports
// whether the interface came free.
func ClearBusy(argv []string, log LogFunc) {
	if len(argv) == 0 {
		return
	}
	if log != nil {
		log("releasing interface: %s", strings.Join(argv, " "))
	}
	_ = exec.Command(argv[0], argv[1:]...).Run()
}

// IsBusy reports whether a claim error was caused by another program holding
// the interface.
func IsBusy(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "busy")
}
