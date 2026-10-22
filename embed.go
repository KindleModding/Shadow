// Package shadow embeds build-time data. It lives at the module root so the
// embed directive can reach firmware/db.json.
package shadow

import _ "embed"

//go:embed firmware/db.json
var FirmwareDB []byte
