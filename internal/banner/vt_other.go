//go:build !windows

package banner

import "os"

// supportsANSI is always true off Windows: every terminal there interprets the
// escape codes the banner uses.
func supportsANSI(*os.File) bool { return true }
