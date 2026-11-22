package chserver

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/settings"
)

func regexpAllowAll() *regexp.Regexp { return settings.UserAllowAll }

// captureLogs swaps in an in-memory logger and returns the buffer.
func captureLogs(s *Server) *bytes.Buffer {
	var b bytes.Buffer
	s.Logger = cio.NewLoggerFlag("server", 0)
	s.Logger.Info = true
	s.Logger.SetOutput(&b)
	return &b
}

func TestAuthHashedUser(t *testing.T) {
	s, err := NewServer(&Config{KeySeed: "hash-auth-test"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := settings.HashPassword("correct horse", settings.DefaultBcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	s.users.AddUser(&settings.User{Name: "alice", Hash: hash, Addrs: []*regexp.Regexp{regexpAllowAll()}})
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("correct horse")); err != nil {
		t.Fatalf("hashed login failed: %v", err)
	}
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("correct horse!")); err == nil {
		t.Fatal("wrong password accepted against hash")
	}
}

func TestAuthMixedFilePerEntry(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	hash, _ := settings.HashPassword("hpw", settings.BcryptMinCost)
	contents := `{"alice:plain": [""], "bob:` + hash + `": [""]}`
	if err := os.WriteFile(cfg, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(&Config{KeySeed: "mixed", AuthFile: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("plain")); err != nil {
		t.Fatalf("plaintext entry should still verify: %v", err)
	}
	if _, err := s.authUser(testConnMeta{user: "bob"}, []byte("hpw")); err != nil {
		t.Fatalf("hashed entry should verify: %v", err)
	}
	bob, _ := s.users.Get("bob")
	if !bob.HasHash() {
		t.Fatal("mixed file downgraded hashed entry to plaintext")
	}
}

func medianDuration(d []time.Duration) time.Duration {
	cp := append([]time.Duration(nil), d...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

// assertFailureTimingEquivalent measures the median latency of two failing
// login paths and asserts they are within a generous envelope. Both paths
// must spend one bcrypt-strength comparison regardless of storage form.
func assertFailureTimingEquivalent(t *testing.T, s *Server, existingUser, presented string) {
	t.Helper()
	// warm up so first-call allocation noise does not skew timing
	_, _ = s.authUser(testConnMeta{user: existingUser}, []byte(presented))
	_, _ = s.authUser(testConnMeta{user: "ghost"}, []byte(presented))

	const samples = 5
	bad := make([]time.Duration, samples)
	missing := make([]time.Duration, samples)
	var errBad, errMissing error
	for i := 0; i < samples; i++ {
		start := time.Now()
		_, errBad = s.authUser(testConnMeta{user: existingUser}, []byte(presented))
		bad[i] = time.Since(start)
		start = time.Now()
		_, errMissing = s.authUser(testConnMeta{user: "ghost"}, []byte(presented))
		missing[i] = time.Since(start)
	}
	// identical external error shape on both paths (username aside, which
	// mirrors the legacy message)
	if errBad == nil || errMissing == nil ||
		!strings.HasPrefix(errBad.Error(), "invalid authentication for username: ") ||
		!strings.HasPrefix(errMissing.Error(), "invalid authentication for username: ") {
		t.Fatalf("error surface diverged for %s: %v vs %v", existingUser, errBad, errMissing)
	}
	ratio := float64(medianDuration(missing)) / float64(medianDuration(bad))
	if ratio < 0.5 || ratio > 2.0 {
		t.Fatalf("timing diverges for %s: bad-password=%v unknown-user=%v ratio=%.2f",
			existingUser, medianDuration(bad), medianDuration(missing), ratio)
	}
}

func TestAuthUnknownUserMatchesHashedWrongPassword(t *testing.T) {
	s, err := NewServer(&Config{KeySeed: "equiv-hashed"})
	if err != nil {
		t.Fatal(err)
	}
	// default cost matches the dummy hash so both paths do comparable work
	hash, _ := settings.HashPassword("realpw", settings.DefaultBcryptCost)
	s.users.AddUser(&settings.User{Name: "alice", Hash: hash, Addrs: []*regexp.Regexp{regexpAllowAll()}})
	logs := captureLogs(s)
	assertFailureTimingEquivalent(t, s, "alice", "definitely-wrong")
	assertNoPasswordInLogs(t, logs, "definitely-wrong")
	assertFailureLogCategories(t, logs)
}

func TestAuthUnknownUserMatchesPlaintextWrongPassword(t *testing.T) {
	// A legacy plaintext account's wrong-password path must not be faster
	// than the unknown-user path, or timing would expose both account
	// existence and the plaintext storage form.
	s, err := NewServer(&Config{KeySeed: "equiv-plain"})
	if err != nil {
		t.Fatal(err)
	}
	s.users.AddUser(&settings.User{Name: "pat", Pass: "real-pw", Addrs: []*regexp.Regexp{regexpAllowAll()}})
	logs := captureLogs(s)
	assertFailureTimingEquivalent(t, s, "pat", "definitely-wrong")
	assertNoPasswordInLogs(t, logs, "definitely-wrong")
	// and neither the real stored secret nor the presented one leaks
	assertNoPasswordInLogs(t, logs, "real-pw")
	assertFailureLogCategories(t, logs)
}

func assertFailureLogCategories(t *testing.T, logs *bytes.Buffer) {
	t.Helper()
	out := logs.String()
	if !strings.Contains(out, "reason=bad-credentials") || !strings.Contains(out, "reason=unknown-user") {
		t.Fatalf("missing reason categories in: %q", out)
	}
}

func assertNoPasswordInLogs(t *testing.T, logs *bytes.Buffer, secret string) {
	t.Helper()
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("secret %q appeared in logs: %q", secret, logs.String())
	}
}

func TestAuthNoAuthModeUnchanged(t *testing.T) {
	s, err := NewServer(&Config{KeySeed: "noauth"})
	if err != nil {
		t.Fatal(err)
	}
	perms, err := s.authUser(testConnMeta{user: "anyone"}, []byte("whatever"))
	if err != nil {
		t.Fatalf("no-auth mode broke: %v", err)
	}
	if perms != nil {
		t.Fatal("no-auth should return nil permissions")
	}
}

func TestAuthConcurrencyGateBounded(t *testing.T) {
	gate, err := newAuthGate()
	if err != nil {
		t.Fatal(err)
	}
	if cap(gate.slots) < 1 {
		t.Fatal("gate has no capacity")
	}
	// fill every slot, then ensure one more attempt blocks until a release
	for i := 0; i < cap(gate.slots); i++ {
		gate.slots <- struct{}{}
	}
	acquired := make(chan struct{})
	go func() {
		gate.slots <- struct{}{}
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("gate allowed more than its capacity")
	case <-time.After(50 * time.Millisecond):
	}
	<-gate.slots
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("slot was not reusable after release")
	}
}

func TestAuthHashReloadTakesEffect(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	oldHash, _ := settings.HashPassword("old-pw", settings.BcryptMinCost)
	if err := os.WriteFile(cfg, []byte(`{"alice:`+oldHash+`": [""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(&Config{KeySeed: "reload", AuthFile: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("old-pw")); err != nil {
		t.Fatalf("old password should work: %v", err)
	}
	newHash, _ := settings.HashPassword("new-pw", settings.BcryptMinCost)
	if err := os.WriteFile(cfg, []byte(`{"alice:`+newHash+`": [""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("new-pw")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("new-pw")); err != nil {
		t.Fatalf("new hash did not take effect after reload: %v", err)
	}
	if _, err := s.authUser(testConnMeta{user: "alice"}, []byte("old-pw")); err == nil {
		t.Fatal("old password still accepted after migration reload")
	}
}

func TestAuthUnknownHashFailsStartup(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "users.json")
	if err := os.WriteFile(cfg, []byte(`{"alice:$6$bad$hash": [""]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewServer(&Config{KeySeed: "x", AuthFile: cfg})
	if err == nil || !strings.Contains(err.Error(), "alice") {
		t.Fatalf("startup must refuse unknown hash and name the user: %v", err)
	}
}
