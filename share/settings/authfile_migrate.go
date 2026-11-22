package settings

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MigrationReport summarizes an authfile migration. It contains counts and
// file paths only — never plaintext secrets or hashes.
type MigrationReport struct {
	Path       string
	BackupPath string
	Migrated   int // entries converted from plaintext to bcrypt
	Untouched  int // entries already stored as bcrypt
}

// MigrateAuthFile converts every plaintext entry in the authfile at path
// into a self-describing bcrypt hash and replaces the file atomically.
//
// Safety order:
//  1. the whole file is parsed and validated up front — any unknown hash
//     encoding, bad cost or broken JSON aborts before anything is written;
//  2. a timestamped backup of the original is created;
//  3. the replacement is written to a temp file in the same directory and
//     renamed over the original;
//  4. the replacement is re-read and re-parsed before success is reported.
//
// A failure at any step before the rename leaves the original file fully
// usable. cost 0 selects DefaultBcryptCost.
func MigrateAuthFile(path string, cost int, logw io.Writer) (*MigrationReport, error) {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	if cost < BcryptMinCost || cost > BcryptMaxCost {
		return nil, fmt.Errorf("bcrypt cost %d is outside the acceptable range %d..%d",
			cost, BcryptMinCost, BcryptMaxCost)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth file: %w", err)
	}

	// Step 1: full validation of the current file. ParseUsers rejects
	// unknown hash formats and invalid bcrypt parameters per entry.
	users, plaintext, _, err := ParseUsers(original)
	if err != nil {
		return nil, fmt.Errorf("pre-migration validation failed: %w", err)
	}
	if plaintext == 0 {
		return &MigrationReport{Path: path, Untouched: len(users)}, nil
	}

	// Build the replacement key -> remotes map, hashing plaintext secrets.
	replacement := make(map[string][]string, len(users))
	migrated := 0
	for _, u := range users {
		key := u.Name + ":"
		if u.HasHash() {
			key += u.Hash
		} else {
			h, err := HashPassword(u.Pass, cost)
			if err != nil {
				return nil, fmt.Errorf("failed to hash entry for user %q: %w", u.Name, err)
			}
			key += h
			migrated++
			// Drop the plaintext from memory as soon as it is no longer needed.
			u.Pass = ""
		}
		replacement[key] = remotesToPatterns(u.Addrs)
	}

	encoded, err := encodeAuthfile(replacement)
	if err != nil {
		return nil, err
	}

	// Step 2: keep a rollback copy of the exact original bytes.
	backup := fmt.Sprintf("%s.bak.%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, original, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write backup %s: %w", backup, err)
	}

	// Step 3: atomic replace via a temp file in the same directory (same
	// filesystem, so rename is atomic). Owner-only permissions from birth.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		cleanup()
		return nil, fmt.Errorf("failed to write replacement file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return nil, fmt.Errorf("failed to restrict replacement file permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to finalize replacement file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to replace auth file: %w", err)
	}

	// Step 4: re-read and re-parse the replaced file before declaring
	// success; the backup remains on disk for rollback if this ever fails.
	reRead, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("post-migration read failed (backup retained at %s): %w", backup, err)
	}
	if _, _, _, err := ParseUsers(reRead); err != nil {
		return nil, fmt.Errorf("post-migration validation failed (backup retained at %s): %w", backup, err)
	}

	report := &MigrationReport{
		Path:       path,
		BackupPath: backup,
		Migrated:   migrated,
		Untouched:  len(users) - migrated,
	}
	fmt.Fprintf(logw, "migrated %d entr%s to bcrypt (cost %d), %d already hashed; backup written to %s\n",
		report.Migrated, plural(report.Migrated, "y", "ies"), cost, report.Untouched, backup)
	return report, nil
}

// remotesToPatterns renders compiled address regexps back to their source
// patterns. UserAllowAll (an empty regex) maps back to the wildcard "".
func remotesToPatterns(addrs []*regexp.Regexp) []string {
	out := make([]string, 0, len(addrs))
	for _, re := range addrs {
		if re == UserAllowAll || re.String() == "" {
			out = append(out, "")
			continue
		}
		out = append(out, re.String())
	}
	return out
}

// encodeAuthfile serializes key -> patterns with deterministic key order and
// indentation matching the example users.json style.
func encodeAuthfile(m map[string][]string) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("{\n")
	for i, k := range keys {
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.WriteString("\t")
		b.Write(keyJSON)
		b.WriteString(": [")
		patterns := m[k]
		for j, p := range patterns {
			pj, err := json.Marshal(p)
			if err != nil {
				return nil, err
			}
			if j > 0 {
				b.WriteString(", ")
			}
			b.Write(pj)
		}
		b.WriteString("]")
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return []byte(b.String()), nil
}
