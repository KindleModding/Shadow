//go:build windows

package usbdev

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// DriverNode is one Windows devnode: the driver service bound to it and whether
// libusb can use that service.
type DriverNode struct {
	InstanceID string
	Service    string
	Name       string
	InfPath    string
	MI         int // "&MI_xx" interface index, -1 when the node is not an interface
	Bound      bool
}

// libusbServices are the Windows services libusb can drive; Zadig binds one of
// them to the Kindle.
var libusbServices = map[string]bool{
	"winusb":  true,
	"libusbk": true,
	"libusb0": true,
}

// DriverNodes lists the Windows devnodes for vid/pids, driverless ones included
// (SetupAPI reports those with an empty service). A class-255 interface with no
// driver is invisible to libusb, so binding WinUSB is a manual step.
func DriverNodes(vid uint16, pids []uint16) ([]DriverNode, error) {
	set, err := openUSBDevInfoSet()
	if err != nil {
		return nil, err
	}
	defer windows.SetupDiDestroyDeviceInfoList(set)
	nodes, _, err := enumDriverNodes(set, vid, pids)
	return nodes, err
}

// RemoveDriverNodes uninstalls the devnodes bound to a libusb-compatible
// driver, undoing the Zadig binding so Windows falls back to its normal driver.
// purge also uninstalls the third-party driver package that provided it.
// Administrator rights are required; Windows re-enumerates immediately, so MTP
// works again without a replug.
func RemoveDriverNodes(vid uint16, pids []uint16, purge bool) ([]DriverNode, error) {
	set, err := openUSBDevInfoSet()
	if err != nil {
		return nil, err
	}
	defer windows.SetupDiDestroyDeviceInfoList(set)
	nodes, devs, err := enumDriverNodes(set, vid, pids)
	if err != nil {
		return nil, err
	}
	var removed []DriverNode
	var failures []string
	for i, n := range nodes {
		if !n.Bound {
			continue
		}
		if err := windows.SetupDiCallClassInstaller(windows.DIF_REMOVE, set, devs[i]); err != nil {
			failures = append(failures, fmt.Sprintf("remove %s: %v", n.InstanceID, err))
			continue
		}
		if purge && oemInf(n.InfPath) {
			// A driver package can only be deleted once no device uses it.
			if err := windows.SetupUninstallOEMInf(n.InfPath, 0); err != nil {
				failures = append(failures, fmt.Sprintf("uninstall %s: %v", n.InfPath, err))
			}
		}
		removed = append(removed, n)
	}
	if len(failures) > 0 {
		return removed, errors.New(strings.Join(failures, "; "))
	}
	return removed, nil
}

func openUSBDevInfoSet() (windows.DevInfo, error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, windows.DevInfo(0), "")
	if err != nil {
		return windows.DevInfo(0), fmt.Errorf("setupapi: %w", err)
	}
	return set, nil
}

// enumDriverNodes returns the matching devnodes with the DevInfoData needed to
// act on them; both stay valid until set is destroyed.
func enumDriverNodes(set windows.DevInfo, vid uint16, pids []uint16) ([]DriverNode, []*windows.DevInfoData, error) {
	var nodes []DriverNode
	var devs []*windows.DevInfoData
	for i := 0; ; i++ {
		di, err := windows.SetupDiEnumDeviceInfo(set, i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return nodes, devs, nil
		}
		if err != nil {
			return nodes, devs, fmt.Errorf("setupapi enum: %w", err)
		}
		instanceID, err := windows.SetupDiGetDeviceInstanceId(set, di)
		if err != nil || !instanceMatches(instanceID, vid, pids) {
			continue
		}
		n := DriverNode{InstanceID: instanceID, MI: interfaceIndex(instanceID)}
		if v, err := windows.SetupDiGetDeviceRegistryProperty(set, di, windows.SPDRP_SERVICE); err == nil {
			n.Service, _ = v.(string)
		}
		if v, err := windows.SetupDiGetDeviceRegistryProperty(set, di, windows.SPDRP_FRIENDLYNAME); err == nil {
			n.Name, _ = v.(string)
		}
		if v, err := windows.SetupDiGetDeviceProperty(set, di, &devpkeyDriverInfPath); err == nil {
			n.InfPath, _ = v.(string)
		}
		n.Bound = libusbServices[strings.ToLower(n.Service)]
		nodes = append(nodes, n)
		devs = append(devs, di)
	}
}

// instanceMatches reports whether an instance ID such as
// `USB\VID_1949&PID_9981&MI_00\...` matches one of pids.
func instanceMatches(instanceID string, vid uint16, pids []uint16) bool {
	upper := strings.ToUpper(instanceID)
	for _, p := range pids {
		if strings.Contains(upper, fmt.Sprintf("VID_%04X&PID_%04X", vid, p)) {
			return true
		}
	}
	return false
}

// interfaceIndex returns the "&MI_xx" interface index of a composite device
// node, or -1 when the node is not an interface.
func interfaceIndex(instanceID string) int {
	upper := strings.ToUpper(instanceID)
	i := strings.Index(upper, "&MI_")
	if i < 0 || len(upper) < i+6 {
		return -1
	}
	var n int
	if _, err := fmt.Sscanf(upper[i+4:i+6], "%02X", &n); err != nil {
		return -1
	}
	return n
}

// oemInf reports whether inf is a third-party driver package that Windows
// renamed to oemNN.inf; SetupUninstallOEMInf may only delete those.
func oemInf(inf string) bool {
	lower := strings.ToLower(inf)
	return strings.HasPrefix(lower, "oem") && strings.HasSuffix(lower, ".inf")
}

// devpkeyDriverInfPath is DEVPKEY_Device_DriverInfPath
// ({a8b865dd-2e3d-4094-ad97-e593a70c75d6}, 5): the oemNN.inf that provided the
// node's driver, if a third-party one did.
var devpkeyDriverInfPath = windows.DEVPROPKEY{
	FmtID: windows.DEVPROPGUID(windows.GUID{
		Data1: 0xa8b865dd,
		Data2: 0x2e3d,
		Data3: 0x4094,
		Data4: [8]byte{0xad, 0x97, 0xe5, 0x93, 0xa7, 0x0c, 0x75, 0xd6},
	}),
	PID: 5,
}
