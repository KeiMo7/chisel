//go:build !windows

package settings

import (
	"os"

	"github.com/jpillora/chisel/share/cio"
)

// warnIfAuthFilePermissive warns when the authfile is readable or writable
// by group or others. The check is advisory: a permissive file does not stop
// the server, but an operator storing credentials should know the file is
// exposed. Nothing about the file's contents is logged.
func warnIfAuthFilePermissive(logger *cio.Logger, path string) {
	info, err := os.Stat(path)
	if err != nil {
		return //the read error is reported by the caller
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		logger.Infof("authfile %s has permissive permissions %#o: restrict it to owner-only access (e.g. chmod 600)", path, uint32(mode))
	}
}
