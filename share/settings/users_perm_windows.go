//go:build windows

package settings

import "github.com/jpillora/chisel/share/cio"

// warnIfAuthFilePermissive is a no-op on Windows, which has no POSX
// permission bits. Operators are expected to secure the file via ACLs.
func warnIfAuthFilePermissive(logger *cio.Logger, path string) {}
