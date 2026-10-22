//go:build windows

package banner

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// console opens the console output device, or skips when there is none.
func console(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no console available: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// A console that reports VT support must have VT processing enabled
// afterwards - that is what keeps classic conhost (Windows PowerShell 5.1) from
// printing the banner's escape codes verbatim.
func TestSupportsANSIEnablesVT(t *testing.T) {
	f := console(t)
	if !supportsANSI(f) {
		t.Skip("console cannot do VT escape codes")
	}

	var mode uint32
	if err := windows.GetConsoleMode(windows.Handle(f.Fd()), &mode); err != nil {
		t.Fatalf("GetConsoleMode: %v", err)
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		t.Error("supportsANSI reported true but VT processing is not enabled")
	}
}

// NO_COLOR must win over a VT-capable console.
func TestNoColorWinsOnConsole(t *testing.T) {
	f := console(t)
	t.Setenv("NO_COLOR", "1")
	if colors(f) {
		t.Error("colors(console) = true with NO_COLOR set, want false")
	}
}
