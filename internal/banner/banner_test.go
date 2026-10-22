package banner

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// The banner is shadow's only styled output, and escape codes must never reach
// a writer that cannot interpret them - a buffer, a file or a pipe.
func TestColorsOnlyForTerminals(t *testing.T) {
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer pipeR.Close()
	defer pipeW.Close()
	file, err := os.CreateTemp(t.TempDir(), "banner")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer file.Close()

	for name, w := range map[string]io.Writer{
		"buffer": &bytes.Buffer{},
		"file":   file,
		"pipe":   pipeW,
	} {
		if colors(w) {
			t.Errorf("colors(%s) = true, want false", name)
		}
	}

	var buf bytes.Buffer
	Print(&buf)
	if strings.Contains(buf.String(), "\x1b[") {
		t.Errorf("Print to a buffer emitted escape codes:\n%q", buf.String())
	}
	if !strings.Contains(buf.String(), "My name is Nobody") {
		t.Errorf("Print to a buffer dropped the banner text:\n%q", buf.String())
	}
}
