package usbdev

import (
	"errors"
	"slices"
	"testing"
)

func TestBusyClearCommand(t *testing.T) {
	cases := []struct {
		goos string
		want []string
	}{
		{"linux", []string{"killall", "kiod6", "gvfsd-mtp"}},
		{"darwin", []string{"killall", "ptpcamerad"}},
		{"windows", nil},
	}
	for _, tc := range cases {
		if got := busyClearCommand(tc.goos); !slices.Equal(got, tc.want) {
			t.Errorf("%s: got %q, want %q", tc.goos, got, tc.want)
		}
	}
}

func TestIsBusy(t *testing.T) {
	if !IsBusy(errors.New("usb claim interface 0: busy")) {
		t.Error("busy claim not detected")
	}
	if IsBusy(nil) || IsBusy(errors.New("usb claim interface 0: access denied")) {
		t.Error("non-busy error reported as busy")
	}
}
