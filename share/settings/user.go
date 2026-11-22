package settings

import (
	"regexp"
	"strings"
)

var UserAllowAll = regexp.MustCompile("")

func ParseAuth(auth string) (string, string) {
	if strings.Contains(auth, ":") {
		pair := strings.SplitN(auth, ":", 2)
		return pair[0], pair[1]
	}
	return "", ""
}

type User struct {
	Name string
	// Pass holds a plaintext secret only for backward-compatible legacy
	// entries. New and migrated entries leave Pass empty and store a bcrypt
	// hash in Hash instead.
	Pass string
	// Hash holds a self-describing bcrypt hash ($2a$/$2b$/$2y$). When set,
	// password verification runs through bcrypt and Pass is ignored.
	Hash  string
	Addrs []*regexp.Regexp
}

// HasHash reports whether this user's secret is stored as a hash.
func (u *User) HasHash() bool {
	return u.Hash != ""
}

// VerifyPassword checks a presented password against the user's stored
// secret. Hashed and plaintext entries are verified per-user, so a mixed
// authfile never degrades to plaintext comparison for hashed accounts.
// The result is a single boolean; no material from either operand is
// embedded in an error.
func (u *User) VerifyPassword(presented string) bool {
	if u.HasHash() {
		return CompareBcrypt(u.Hash, presented)
	}
	return ConstantTimeEqual(u.Pass, presented)
}

func (u *User) HasAccess(addr string) bool {
	m := false
	for _, r := range u.Addrs {
		if r.MatchString(addr) {
			m = true
			break
		}
	}
	return m
}
