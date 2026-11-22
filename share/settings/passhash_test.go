package settings

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestConstantTimeEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", "secret", "secret", true},
		{"different", "secret", "secrex", false},
		{"prefix-length-diff", "secret", "secret-longer", false},
		{"both-empty", "", "", true},
		{"one-empty", "", "x", false},
		{"other-empty", "x", "", false},
		{"length-diff-same-prefix", "abc", "abcd", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConstantTimeEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("ConstantTimeEqual(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestBcryptRoundTrip(t *testing.T) {
	hash, err := HashPassword("hunter2", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !IsBcryptHash(hash) {
		t.Fatalf("output is not a recognized bcrypt hash: %q", hash)
	}
	if !CompareBcrypt(hash, "hunter2") {
		t.Fatal("correct password rejected")
	}
	if CompareBcrypt(hash, "Hunter2") {
		t.Fatal("wrong password accepted")
	}
	// cost is embedded in the hash and recoverable
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatal(err)
	}
	if cost != DefaultBcryptCost {
		t.Fatalf("cost=%d want %d", cost, DefaultBcryptCost)
	}
}

func TestHashPasswordCostBounds(t *testing.T) {
	if _, err := HashPassword("x", BcryptMinCost-1); err == nil {
		t.Fatal("cost below minimum accepted")
	}
	if _, err := HashPassword("x", BcryptMaxCost+1); err == nil {
		t.Fatal("cost above maximum accepted")
	}
}

func TestValidateStoredSecret(t *testing.T) {
	good, err := HashPassword("pw", BcryptMinCost)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{"plaintext-legacy", "plain-text-password", false},
		{"bcrypt-2a", good, false},
		{"unknown-algorithm", "$6$rounds=5000$saltsaltsalt$deadbeef", true},
		{"unknown-prefix", "$argon2id$v=19$m=65536$c2FsdA$aGFzaA", true},
		{"malformed-bcrypt", "$2a$10$short", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStoredSecret(tc.secret)
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// errors must identify the unsupported format without dumping
			// the secret value itself
			if tc.wantErr && strings.Contains(err.Error(), tc.secret) {
				t.Fatalf("error leaks stored secret: %v", err)
			}
		})
	}
}

func TestValidateStoredSecretUnsupportedSentinel(t *testing.T) {
	err := ValidateStoredSecret("$6$abc$def")
	if !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("expected ErrUnsupportedHash, got %v", err)
	}
}

func TestUserVerifyPasswordMixedForms(t *testing.T) {
	hash, err := HashPassword("hashed-pw", DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	hashed := &User{Name: "h", Hash: hash}
	plain := &User{Name: "p", Pass: "plain-pw"}
	if !hashed.VerifyPassword("hashed-pw") || hashed.VerifyPassword("wrong") {
		t.Fatal("hashed user verification wrong")
	}
	if !plain.VerifyPassword("plain-pw") || plain.VerifyPassword("plain-pw-x") {
		t.Fatal("plaintext user verification wrong")
	}
	// a hashed user must never fall back to plaintext comparison even if
	// someone presents the literal hash string
	if hashed.VerifyPassword(hash) {
		t.Fatal("hashed account accepted its own hash as a password")
	}
}
