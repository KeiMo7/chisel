package chserver

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpillora/chisel/server/authlimit"
	"github.com/jpillora/chisel/share/cio"
)

func newLockoutServer(t *testing.T, cfg AuthLimitConfig) *Server {
	t.Helper()
	s, err := NewServer(&Config{KeySeed: "lockout-test", AuthLimit: cfg})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.AddUser("alice", "correct horse", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("bob", "battery staple", ""); err != nil {
		t.Fatal(err)
	}
	return s
}

func fastLockoutCfg() AuthLimitConfig {
	return AuthLimitConfig{
		SourceFailures:  3,
		AccountFailures: 3,
		Window:          time.Minute,
		Cooldown:        200 * time.Millisecond,
		MaxSources:      1000,
		MaxAccounts:     1000,
	}
}

func meta(user string, ip string) testConnMeta {
	return testConnMeta{
		user:       user,
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 51515},
	}
}

func TestLockoutThresholdThenRecovery(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())

	// three failures from one source/account cross both thresholds
	for i := 0; i < 3; i++ {
		if _, err := s.authUser(meta("alice", "192.0.2.10"), []byte("wrong")); err == nil {
			t.Fatalf("attempt %d: wrong password accepted", i)
		}
	}

	// correct password is rejected while the cooldown runs, and the
	// error states how much longer the source must wait
	_, err := s.authUser(meta("alice", "192.0.2.10"), []byte("correct horse"))
	if err == nil {
		t.Fatal("correct password accepted during cooldown")
	}
	if !strings.Contains(err.Error(), "retry in") {
		t.Fatalf("error does not state remaining time: %q", err.Error())
	}

	// after the cooldown the correct password works again
	time.Sleep(250 * time.Millisecond)
	perms, err := s.authUser(meta("alice", "192.0.2.10"), []byte("correct horse"))
	if err != nil {
		t.Fatalf("login did not recover after cooldown: %v", err)
	}
	if perms == nil || perms.Extensions["user"] != "alice" {
		t.Fatalf("unexpected perms after recovery: %+v", perms)
	}
}

func TestLockoutCorrectPasswordRejectedWithRemainder(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())
	for i := 0; i < 3; i++ {
		if _, err := s.authUser(meta("alice", "192.0.2.11"), []byte("nope")); err == nil {
			t.Fatal("bad password accepted")
		}
	}
	_, err := s.authUser(meta("alice", "192.0.2.11"), []byte("correct horse"))
	if err == nil || !strings.Contains(err.Error(), "retry in") {
		t.Fatalf("expected cooldown error with remainder, got: %v", err)
	}
}

func TestLockoutAccountsAndSourcesIndependent(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())

	// lock alice's account and the source 192.0.2.20
	for i := 0; i < 3; i++ {
		if _, err := s.authUser(meta("alice", "192.0.2.20"), []byte("bad")); err == nil {
			t.Fatal("bad password accepted")
		}
	}

	// bob from a different source: completely unaffected
	if _, err := s.authUser(meta("bob", "198.51.100.20"), []byte("battery staple")); err != nil {
		t.Fatalf("unrelated account was affected: %v", err)
	}

	// bob from the banned source is blocked at the source layer, but the
	// response text must not reveal whether "bob" exists
	_, err := s.authUser(meta("bob", "192.0.2.20"), []byte("battery staple"))
	if err == nil {
		t.Fatal("banned source was allowed through")
	}
	if strings.Contains(err.Error(), "bob") || strings.Contains(err.Error(), "alice") {
		t.Fatalf("source lockout response leaks an account name: %q", err.Error())
	}

	// alice from a clean source is blocked at the account layer; the
	// message is account-scoped and identical for existing accounts only
	_, err = s.authUser(meta("alice", "198.51.100.21"), []byte("correct horse"))
	if err == nil || !strings.Contains(err.Error(), "retry in") {
		t.Fatalf("account lockout missing remainder: %v", err)
	}
}

func TestLockoutNoUserEnumerationFromBannedSource(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())
	for i := 0; i < 3; i++ {
		if _, err := s.authUser(meta("ghost", "192.0.2.30"), []byte("x")); err == nil {
			t.Fatal("bad password accepted")
		}
	}
	// every username presented from the banned source gets the same
	// source-scoped rejection, existing or not
	errExisting := mustErr(t, s, meta("alice", "192.0.2.30"), []byte("correct horse"))
	errMissing := mustErr(t, s, meta("nobody-home", "192.0.2.30"), []byte("whatever"))
	if errExisting.Error() != errMissing.Error() {
		t.Fatalf("banned-source responses differ by account existence:\n existing=%q\n missing=%q",
			errExisting.Error(), errMissing.Error())
	}
}

func TestLockoutLogsNeverContainPassword(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())
	var logs bytes.Buffer
	s.Logger = cio.NewLoggerFlag("server", 0)
	s.Logger.Info = true
	s.Logger.SetOutput(&logs)

	secret := "correct horse"
	for i := 0; i < 4; i++ {
		_, _ = s.authUser(meta("alice", "192.0.2.40"), []byte(secret))
	}
	out := logs.String()
	for _, leak := range []string{secret, "horse", "len=", "length"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log output leaks password material %q:\n%s", leak, out)
		}
	}
}

func TestLockoutConcurrentFailuresDoNotLoseCounts(t *testing.T) {
	cfg := fastLockoutCfg()
	cfg.SourceFailures = 200
	cfg.AccountFailures = 200
	s := newLockoutServer(t, cfg)

	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.authUser(meta("alice", "192.0.2.50"), []byte("wrong")); err == nil {
				t.Error("wrong password accepted")
			}
		}()
	}
	wg.Wait()

	snap := s.AuthLimitSnapshot()
	var src, acct authlimit.EntrySnapshot
	for _, e := range snap.Sources {
		if e.Key == "192.0.2.50" {
			src = e
		}
	}
	for _, e := range snap.Accounts {
		if e.Key == "alice" {
			acct = e
		}
	}
	if src.FailuresInWindow != n || acct.FailuresInWindow != n {
		t.Fatalf("lost concurrent failures: source=%d account=%d want %d",
			src.FailuresInWindow, acct.FailuresInWindow, n)
	}
	if !src.Locked || !acct.Locked {
		t.Fatalf("threshold not reached under concurrency: src=%+v acct=%+v", src, acct)
	}

	// the lock must now reject even a correct password
	if _, err := s.authUser(meta("alice", "192.0.2.50"), []byte("correct horse")); err == nil {
		t.Fatal("correct password accepted after concurrent lockout")
	}
}

func TestNoAuthModeUnchanged(t *testing.T) {
	// no users: limiter must stay inert and every attempt must pass
	s, err := NewServer(&Config{KeySeed: "no-auth-lockout", AuthLimit: fastLockoutCfg()})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := s.authUser(meta("anyone", "192.0.2.60"), []byte("anything")); err != nil {
			t.Fatalf("allow-all blocked on attempt %d: %v", i, err)
		}
	}
	if m := s.AuthLimitSnapshot().Metrics; m.FailedAttempts != 0 || m.LockedRejections != 0 {
		t.Fatalf("no-auth mode touched the limiter: %+v", m)
	}
}

func TestManualUnlock(t *testing.T) {
	s := newLockoutServer(t, fastLockoutCfg())
	for i := 0; i < 3; i++ {
		_, _ = s.authUser(meta("alice", "192.0.2.70"), []byte("bad"))
	}
	if _, err := s.authUser(meta("alice", "192.0.2.70"), []byte("correct horse")); err == nil {
		t.Fatal("expected lockout before manual unlock")
	}
	if !s.UnlockAccount("alice") || !s.UnlockSource("192.0.2.70") {
		t.Fatal("manual unlock reported a missing key")
	}
	if _, err := s.authUser(meta("alice", "192.0.2.70"), []byte("correct horse")); err != nil {
		t.Fatalf("manual unlock did not restore access: %v", err)
	}
}

func TestIllegalLockoutConfigRejectsStartup(t *testing.T) {
	bad := AuthLimitConfig{
		SourceFailures: 0, AccountFailures: -1,
		Window: time.Second, Cooldown: time.Second,
		MaxSources: 1, MaxAccounts: 1,
	}
	if _, err := NewServer(&Config{KeySeed: "bad-cfg", Auth: "u:p", AuthLimit: bad}); err == nil {
		t.Fatal("server started with an illegal lockout config")
	}
}

func mustErr(t *testing.T, s *Server, m testConnMeta, pass []byte) error {
	t.Helper()
	_, err := s.authUser(m, pass)
	if err == nil {
		t.Fatal("expected rejection")
	}
	return err
}
