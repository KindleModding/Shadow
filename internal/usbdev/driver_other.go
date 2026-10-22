//go:build !windows

package usbdev

// DriverNode is the Windows view of a devnode binding. Elsewhere libusb
// detaches or binds the kernel driver itself, so there is nothing to report or
// restore.
type DriverNode struct {
	InstanceID string
	Service    string
	Name       string
	InfPath    string
	MI         int
	Bound      bool
}

// DriverNodes always reports nothing off Windows.
func DriverNodes(uint16, []uint16) ([]DriverNode, error) { return nil, nil }

// RemoveDriverNodes is a no-op off Windows.
func RemoveDriverNodes(uint16, []uint16, bool) ([]DriverNode, error) { return nil, nil }
