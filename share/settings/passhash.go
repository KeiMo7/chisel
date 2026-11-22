package settings

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// BcryptMinCost is the lowest bcrypt cost accepted from configuration.
// It mirrors bcrypt.MinCost (4); lower values cannot be produced by
// bcrypt.GenerateFromPassword anyway.
const BcryptMinCost = bcrypt.MinCost

// BcryptMaxCost is the highest bcrypt cost accepted at startup. bcrypt itself
// allows up to 31, at which a single comparison takes hours and would hang the
// server during authentication. Configurations above this are rejected before
// the server accepts traffic.
const BcryptMaxCost = bcrypt.MaxCost

// DefaultBcryptCost is used when generating hashes without an explicit cost.
const DefaultBcryptCost = bcrypt.DefaultCost

// BcryptPrefix marks a stored secret as a bcrypt hash. The algorithm and its
// cost parameter are embedded in the hash itself ($2a$/$2b$/$2y$ + cost), so
// no out-of-band algorithm metadata is required.
const BcryptPrefix = "$2"

// ErrUnsupportedHash is returned for secret values that look like a hash
// (start with "$") but use an algorithm chisel does not understand. The
// server must refuse to start rather than silently treating the value as
// plaintext.
var ErrUnsupportedHash = errors.New("unrecognized password hash format")

// IsBcryptHash reports whether secret is a bcrypt hash in one of the
// standard $2a$/$2b$/$2y$ encodings.
func IsBcryptHash(secret string) bool {
	return strings.HasPrefix(secret, BcryptPrefix) &&
		(len(secret) == 2 || secret[2] == 'a' || secret[2] == 'b' || secret[2] == 'y')
}

// LooksHashed reports whether secret appears to use a modular-crypt hash
// encoding (any "$"-prefixed value), known or not.
func LooksHashed(secret string) bool {
	return strings.HasPrefix(secret, "$")
}

// ValidateStoredSecret checks a secret loaded from configuration. Bcrypt
// hashes are decoded so malformed encodings and unacceptable cost parameters
// fail at startup. Plaintext secrets are accepted as-is for backward
// compatibility. The secret itself is never included in returned errors.
func ValidateStoredSecret(secret string) error {
	switch {
	case IsBcryptHash(secret):
		cost, err := bcrypt.Cost([]byte(secret))
		if err != nil {
			return fmt.Errorf("invalid bcrypt hash: %w", err)
		}
		if cost < BcryptMinCost || cost > BcryptMaxCost {
			return fmt.Errorf("bcrypt cost %d is outside the acceptable range %d..%d",
				cost, BcryptMinCost, BcryptMaxCost)
		}
		return nil
	case LooksHashed(secret):
		return fmt.Errorf("%w (only bcrypt $2a$/$2b$/$2y$ hashes are supported)", ErrUnsupportedHash)
	default:
		return nil
	}
}

// HashPassword produces a self-describing bcrypt hash of password using the
// given cost (DefaultBcryptCost when zero). The salt and cost are generated
// by x/crypto/bcrypt; chisel never invents its own password algorithm.
func HashPassword(password string, cost int) (string, error) {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	if cost < BcryptMinCost || cost > BcryptMaxCost {
		return "", fmt.Errorf("bcrypt cost %d is outside the acceptable range %d..%d",
			cost, BcryptMinCost, BcryptMaxCost)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		// bcrypt returns an error only for over-long passwords or bad cost;
		// wrap without echoing the input.
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(h), nil
}

// CompareBcrypt verifies password against a bcrypt hash. A malformed hash or
// any mismatch yields a plain failure, never the input material.
func CompareBcrypt(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ConstantTimeEqual compares two secrets without leaking their length: the
// comparison always touches every byte of the longer operand, and subtle's
// constant-time accumulator hides how many bytes matched. This replaces
// subtle.ConstantTimeCompare, whose early length return makes length guesses
// observable through timing.
func ConstantTimeEqual(a, b string) bool {
	la, lb := len(a), len(b)
	n := la
	if lb > la {
		n = lb
	}
	// Walk the full length of the longer string so the work done does not
	// depend on the shorter operand's length. An empty operand contributes
	// nothing (zero is the XOR identity), so it is never indexed.
	var v byte
	for i := 0; i < n; i++ {
		if la != 0 {
			v ^= a[i%la]
		}
		if lb != 0 {
			v ^= b[i%lb]
		}
	}
	// Keep the length comparison itself constant-time as well.
	lengthOK := subtle.ConstantTimeEq(int32(la), int32(lb))
	contentsOK := subtle.ConstantTimeByteEq(v, 0)
	return subtle.ConstantTimeSelect(lengthOK&contentsOK, 1, 0) == 1
}
