package crecord

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
)

// Redactor replaces sensitive addresses with keyed-hash tokens.
// Tokens are deterministic per key, so records can be correlated,
// and an operator holding the key can map a token back to a
// candidate address by recomputing its token (keyed hash, not
// encryption: there is nothing to decrypt).
type Redactor struct {
	key []byte
}

// NewRedactor builds a Redactor from arbitrary key material. The
// material is used directly as the HMAC key (HMAC normalizes keys
// internally), so operators can reproduce tokens with standard
// tools, e.g. openssl dgst -sha256 -hmac "<key>".
func NewRedactor(key []byte) *Redactor {
	return &Redactor{key: key}
}

// Token maps s to its redaction token. The empty string stays empty
// so absent fields stay absent. Tokens carry a "h1:" prefix naming
// the redaction scheme version.
func (r *Redactor) Token(s string) string {
	if s == "" {
		return ""
	}
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(s))
	return "h1:" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:12])
}

var (
	//IPv4 with optional :port
	ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	//bracketed IPv6 with optional :port, then bare IPv6 (2+ groups)
	ipv6BracketPattern = regexp.MustCompile(`\[[0-9a-fA-F:]+\](?::\d{1,5})?`)
	ipv6Pattern        = regexp.MustCompile(`\b(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F]{0,4}\b`)
)

// Sanitize redacts every IP address (with optional port) found in a
// free-form string, typically an error message. Hostnames cannot be
// recognized reliably and are left as-is; known addresses should be
// redacted structurally (via Token) rather than via Sanitize.
func (r *Redactor) Sanitize(s string) string {
	if s == "" {
		return ""
	}
	repl := func(m string) string { return r.Token(m) }
	s = ipv4Pattern.ReplaceAllStringFunc(s, repl)
	s = ipv6BracketPattern.ReplaceAllStringFunc(s, repl)
	s = ipv6Pattern.ReplaceAllStringFunc(s, repl)
	return s
}
