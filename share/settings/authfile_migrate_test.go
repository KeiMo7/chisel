package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAuthfile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateAuthFileHappyPath(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	writeAuthfile(t, cfg, `{
  "alice:plain-pw": [""],
  "bob:other": ["^socks$", "^10\\.0\\.0\\.1:80$"]
}
`, 0o600)

	report, err := MigrateAuthFile(cfg, BcryptMinCost, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Migrated != 2 || report.Untouched != 0 {
		t.Fatalf("report=%+v", report)
	}
	if _, err := os.Stat(report.BackupPath); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	// backup keeps the original plaintext
	backup, _ := os.ReadFile(report.BackupPath)
	if !strings.Contains(string(backup), "plain-pw") {
		t.Fatal("backup does not contain original content")
	}
	// replacement parses and all entries are hashes
	replaced, _ := os.ReadFile(cfg)
	users, plaintext, _, err := ParseUsers(replaced)
	if err != nil {
		t.Fatalf("replacement invalid: %v", err)
	}
	if plaintext != 0 || len(users) != 2 {
		t.Fatalf("replacement still has plaintext: %+v plaintext=%d", users, plaintext)
	}
	for _, u := range users {
		if !u.HasHash() {
			t.Fatalf("user %s not hashed after migration", u.Name)
		}
	}
	// address semantics survive the round trip
	byName := map[string]*User{}
	for _, u := range users {
		byName[u.Name] = u
	}
	if !byName["alice"].HasAccess("anything:1") {
		t.Fatal("wildcard access lost")
	}
	if !byName["bob"].HasAccess("socks") || byName["bob"].HasAccess("1.2.3.4:80") {
		t.Fatal("address regex semantics changed")
	}
	// old passwords still verify, proving a smooth cutover
	if !byName["alice"].VerifyPassword("plain-pw") {
		t.Fatal("original password no longer works after migration")
	}
	// replacement file is owner-only
	info, _ := os.Stat(cfg)
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("replacement is world/group accessible: %#o", info.Mode().Perm())
	}
}

func TestMigrateAuthFileIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	hash, _ := HashPassword("pw", BcryptMinCost)
	writeAuthfile(t, cfg, `{"alice:`+hash+`": [""]}`, 0o600)
	report, err := MigrateAuthFile(cfg, 0, &strings.Builder{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Migrated != 0 || report.BackupPath != "" {
		t.Fatalf("already-hashed file should be a no-op, got %+v", report)
	}
}

func TestMigrateAuthFileInvalidAbortsBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	original := `{"carol:$6$abc$def": [""]}`
	writeAuthfile(t, cfg, original, 0o600)
	report, err := MigrateAuthFile(cfg, 0, &strings.Builder{})
	if err == nil {
		t.Fatal("migration over unknown hash should fail")
	}
	if report != nil {
		t.Fatal("no report expected on abort")
	}
	got, _ := os.ReadFile(cfg)
	if string(got) != original {
		t.Fatal("original file modified despite validation failure")
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "*.bak.*"))
	if len(backups) != 0 {
		t.Fatalf("backup created before validation succeeded: %v", backups)
	}
}

func TestMigrateAuthFileBadCost(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	writeAuthfile(t, cfg, `{"alice:pw": [""]}`, 0o600)
	if _, err := MigrateAuthFile(cfg, BcryptMaxCost+1, &strings.Builder{}); err == nil {
		t.Fatal("out-of-range cost accepted")
	}
}

func TestResolveCredential(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "cred")
	if err := os.WriteFile(f, []byte("alice:file-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveCredential("@" + f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "alice:file-pw" {
		t.Fatalf("got %q", got)
	}
	literal, err := ResolveCredential("bob:direct")
	if err != nil || literal != "bob:direct" {
		t.Fatalf("literal form broken: %q %v", literal, err)
	}
	if _, err := ResolveCredential("@" + filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing credential file should error")
	}
}
