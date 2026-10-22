//go:build windows

package banner

import (
	"os"

	"golang.org/x/sys/windows"
)

// supportsANSI reports whether escape codes sent to f are interpreted. A
// Windows console only interprets them once ENABLE_VIRTUAL_TERMINAL_PROCESSING
// is set: Windows Terminal sets it, classic conhost (Windows PowerShell 5.1)
// does not. The flag is left set after shadow exits, as is usual for CLIs that
// style their output.
func supportsANSI(f *os.File) bool {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false // a character device that is not a console: no escapes
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
