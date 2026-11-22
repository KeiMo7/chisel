package settings

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// maxCredentialBytes bounds a credential read from stdin or a file so a
// misconfigured pipe cannot exhaust server memory.
const maxCredentialBytes = 1 << 20

// ResolveCredential reads an --auth style "<user>:<secret>" value while
// keeping the secret off the process argument list.
//
// Supported forms:
//
//	"user:pass"        literal value (legacy; visible via /proc/<pid>/cmdline)
//	"@/path/file"      the file's trimmed contents are used as the value
//	"@-"               the value is read from standard input
//
// The "@" indirection is the recommended replacement for passing the secret
// as a flag directly; the AUTH environment variable remains supported as
// well. The resolved secret is returned, never logged here.
func ResolveCredential(value string) (string, error) {
	if value == "" || value[0] != '@' {
		return value, nil
	}
	target := value[1:]
	var r io.Reader
	if target == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(target)
		if err != nil {
			return "", fmt.Errorf("failed to read credential from %q: %w", target, err)
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxCredentialBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read credential: %w", err)
	}
	if len(b) > maxCredentialBytes {
		return "", fmt.Errorf("credential input exceeds %d bytes", maxCredentialBytes)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
