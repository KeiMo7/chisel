package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpillora/chisel/share/cio"
)

func TestParseUsersPlaintext(t *testing.T) {
	b := []byte(`{"alice:secret": [""], "bob:pw": ["socks"]}`)
	users, plaintext, warns, err := ParseUsers(b)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != 2 {
		t.Fatalf("plaintext count=%d want 2", plaintext)
	}
	if len(users) != 2 || len(warns) != 1 {
		t.Fatalf("users=%d warns=%d", len(users), len(warns))
	}
	for _, u := range users {
		if u.HasHash() {
			t.Fatalf("user %s unexpectedly hashed", u.Name)
		}
	}
}

func TestParseUsersHashed(t *testing.T) {
	hash, err := HashPassword("secret", DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"alice:` + hash + `": [""]}`)
	users, plaintext, _, err := ParseUsers(b)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != 0 || len(users) != 1 {
		t.Fatalf("plaintext=%d users=%d", plaintext, len(users))
	}
	u := users[0]
	if u.Name != "alice" || !u.HasHash() || u.Pass != "" {
		t.Fatalf("hashed entry parsed wrong: %+v", u)
	}
	if !u.VerifyPassword("secret") || u.VerifyPassword("nope") {
		t.Fatal("hashed verification mismatch")
	}
}

func TestParseUsersMixed(t *testing.T) {
	hash, err := HashPassword("hpw", DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(`{"alice:plain": [""], "bob:` + hash + `": [""]}`)
	users, plaintext, _, err := ParseUsers(b)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != 1 {
		t.Fatalf("plaintext count=%d want 1 (no whole-file downgrade)", plaintext)
	}
	byName := map[string]*User{}
	for _, u := range users {
		byName[u.Name] = u
	}
	if byName["alice"].HasHash() {
		t.Fatal("alice should stay plaintext")
	}
	if !byName["bob"].HasHash() {
		t.Fatal("bob should stay hashed")
	}
}

func TestParseUsersUnknownHashNamesUser(t *testing.T) {
	b := []byte(`{"carol:$6$rounds=5000$salt$hash": [""], "alice:pw": [""]}`)
	_, _, _, err := ParseUsers(b)
	if err == nil {
		t.Fatal("unknown hash accepted")
	}
	if !strings.Contains(err.Error(), `carol`) {
		t.Fatalf("error does not name the offending user: %v", err)
	}
	// the unknown hash material must not appear in the error
	if strings.Contains(err.Error(), "$6$rounds") {
		t.Fatalf("error leaks hash material: %v", err)
	}
}

func TestParseUsersBadJSON(t *testing.T) {
	if _, _, _, err := ParseUsers([]byte(`{"broken`)); err == nil {
		t.Fatal("corrupt JSON accepted")
	}
}

func TestLoadUsersRejectsUnknownHashAtStartup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	if err := os.WriteFile(cfg, []byte(`{"carol:$6$abc$def": [""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	index := NewUserIndex(cio.NewLogger("test"))
	err := index.LoadUsers(cfg)
	if err == nil || !strings.Contains(err.Error(), `carol`) {
		t.Fatalf("startup should refuse and name the user, got: %v", err)
	}
}

func TestLoadUsersCorruptKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	if err := os.WriteFile(cfg, []byte(`{"alice:pw": [""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	index := NewUserIndex(cio.NewLogger("test"))
	if err := index.LoadUsers(cfg); err != nil {
		t.Fatal(err)
	}
	// corrupt replacement: load must fail but leave the old index intact
	if err := os.WriteFile(cfg, []byte(`{"truncated`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := index.reloadForTest(); err == nil {
		t.Fatal("corrupt file unexpectedly loaded")
	}
	if _, found := index.Get("alice"); !found {
		t.Fatal("previous usable configuration was lost")
	}
}

func TestWarnIfAuthFilePermissive(t *testing.T) {
	dir := t.TempDir()
	wide := filepath.Join(dir, "wide.json")
	if err := os.WriteFile(wide, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tight := filepath.Join(dir, "tight.json")
	if err := os.WriteFile(tight, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := cio.NewLogger("test")
	var sink strings.Builder
	logger.SetOutput(&sink)
	logger.Info = true
	warnIfAuthFilePermissive(logger, wide)
	warnIfAuthFilePermissive(logger, tight)
	out := sink.String()
	if !strings.Contains(out, "permissive permissions") {
		t.Fatalf("expected permission warning, got: %q", out)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("tight file should not warn: %q", out)
	}
}
