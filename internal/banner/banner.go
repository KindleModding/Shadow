// Package banner prints the startup banner embedded at build time.
package banner

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"regexp"
)

//go:embed banner.txt
var art string

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Print writes the banner to w, stripping ANSI colors unless w is a terminal
// that will actually interpret them.
func Print(w io.Writer) {
	s := art
	if !colors(w) {
		s = ansiRE.ReplaceAllString(s, "")
	}
	fmt.Fprint(w, s)
}

// colors reports whether escape codes should be written to w: it must be a
// terminal, NO_COLOR must be unset, and it must support ANSI.
func colors(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if !isTerminal(f) {
		return false
	}
	return supportsANSI(f)
}

// isTerminal reports whether f is a character device. Consoles and Windows NUL
// are; files and pipes are not.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
