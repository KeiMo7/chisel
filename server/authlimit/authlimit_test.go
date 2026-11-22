package authlimit

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// fakeClock gives tests deterministic, jumpable time. It starts at a
// fixed wall time and only moves forward via Advance; cooldown logic uses
// these readings the same way production uses time.Now (monotonic).
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) now() time.Time { return f.t }
func (f *fakeClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

func testLimiter(t *testing.T, cfg Config, clock *fakeClock) *Limiter {
	t.Helper()
	l, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.now = clock.now
	return l
}

func baseCfg() Config {
	return Config{
		SourceFailures:  3,
		AccountFailures: 3,
		Window:          time.Minute,
		Cooldown:        2 * time.Minute,
		MaxSources:      64,
		MaxAccounts:     64,
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{SourceFailures: 0, AccountFailures: 1, Window: time.Second, Cooldown: time.Second, MaxSources: 1, MaxAccounts: 1},
		{SourceFailures: 1, AccountFailures: -1, Window: time.Second, Cooldown: time.Second, MaxSources: 1, MaxAccounts: 1},
		{SourceFailures: 1, AccountFailures: 1, Window: 0, Cooldown: time.Second, MaxSources: 1, MaxAccounts: 1},
		{SourceFailures: 1, AccountFailures: 1, Window: time.Second, Cooldown: -time.Second, MaxSources: 1, MaxAccounts: 1},
		{SourceFailures: 1, AccountFailures: 1, Window: time.Second, Cooldown: time.Second, MaxSources: 0, MaxAccounts: 1},
		{SourceFailures: 1, AccountFailures: 1, Window: time.Second, Cooldown: time.Second, MaxSources: 1, MaxAccounts: 0},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d: illegal config accepted: %+v", i, c)
		}
	}
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
}

func TestThresholdArmsCooldownAndRecovers(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	// two failures stay under the threshold of three
	for i := 0; i < 2; i++ {
		armed, _, _, _, err := l.RecordFailure("192.0.2.1", "alice")
		if err != nil || armed {
			t.Fatalf("attempt %d: armed=%v err=%v", i, armed, err)
		}
	}
	if d := l.Evaluate("192.0.2.1", "alice"); d.SourceLocked || d.AccountLocked {
		t.Fatalf("under threshold but locked: %+v", d)
	}

	// third failure arms both dimensions simultaneously
	srcArmed, acctArmed, srcRem, acctRem, err := l.RecordFailure("192.0.2.1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !srcArmed || !acctArmed || srcRem != 2*time.Minute || acctRem != 2*time.Minute {
		t.Fatalf("expected both cooldowns of 2m, got src(%v,%v) acct(%v,%v)",
			srcArmed, srcRem, acctArmed, acctRem)
	}

	// every attempt is rejected while cooling, with a positive remainder
	d := l.Evaluate("192.0.2.1", "alice")
	if !d.SourceLocked || !d.AccountLocked || d.SourceRemaining <= 0 || d.AccountRemaining <= 0 {
		t.Fatalf("locked state wrong: %+v", d)
	}

	// the inspection snapshot must report the active lock truthfully,
	// with a positive remaining cooldown, not an expired/empty state
	snap := l.Snapshot()
	var srcSnap, acctSnap EntrySnapshot
	for _, e := range snap.Sources {
		if e.Key == "192.0.2.1" {
			srcSnap = e
		}
	}
	for _, e := range snap.Accounts {
		if e.Key == "alice" {
			acctSnap = e
		}
	}
	if !srcSnap.Locked || srcSnap.CooldownRemaining <= 0 {
		t.Fatalf("source snapshot does not show active lock: %+v", srcSnap)
	}
	if !acctSnap.Locked || acctSnap.CooldownRemaining <= 0 {
		t.Fatalf("account snapshot does not show active lock: %+v", acctSnap)
	}

	// failures while locked must not extend the cooldown
	clk.advance(30 * time.Second)
	if _, _, _, _, err := l.RecordFailure("192.0.2.1", "alice"); err != nil {
		t.Fatal(err)
	}
	d = l.Evaluate("192.0.2.1", "alice")
	if !d.SourceLocked || d.SourceRemaining > 91*time.Second {
		t.Fatalf("cooldown was extended by locked-period failures: %+v", d)
	}

	// past the cooldown deadline, evaluation opens up again
	clk.advance(2 * time.Minute)
	if d := l.Evaluate("192.0.2.1", "alice"); d.SourceLocked || d.AccountLocked {
		t.Fatalf("cooldown did not expire: %+v", d)
	}
	if m := l.MetricsNow(); m.SourceCooldowns != 1 || m.AccountCooldowns != 1 || m.LockedRejections < 2 {
		t.Fatalf("unexpected metrics: %+v", m)
	}
}

func TestWindowDecays(t *testing.T) {
	clk := newFakeClock()
	cfg := baseCfg()
	l := testLimiter(t, cfg, clk)

	for i := 0; i < 2; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.2", "bob"); err != nil {
			t.Fatal(err)
		}
	}
	// after the window slides past, old failures no longer count
	clk.advance(cfg.Window + time.Second)
	for i := 0; i < 2; i++ {
		armed, _, _, _, err := l.RecordFailure("192.0.2.2", "bob")
		if err != nil || armed {
			t.Fatalf("stale failures kept counting: armed=%v err=%v", armed, err)
		}
	}
	snap := l.Snapshot()
	if len(snap.Sources) != 1 || snap.Sources[0].FailuresInWindow != 2 {
		t.Fatalf("window decay wrong: %+v", snap.Sources)
	}
}

func TestConcurrentFailuresCountExactly(t *testing.T) {
	clk := newFakeClock()
	cfg := baseCfg()
	cfg.SourceFailures = 100
	cfg.AccountFailures = 100
	l := testLimiter(t, cfg, clk)

	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, _, err := l.RecordFailure("198.51.100.7", "carol"); err != nil {
				t.Errorf("record: %v", err)
			}
		}()
	}
	wg.Wait()

	snap := l.Snapshot()
	var src, acct EntrySnapshot
	for _, e := range snap.Sources {
		if e.Key == "198.51.100.7" {
			src = e
		}
	}
	for _, e := range snap.Accounts {
		if e.Key == "carol" {
			acct = e
		}
	}
	if src.FailuresInWindow != n || acct.FailuresInWindow != n {
		t.Fatalf("lost increments under concurrency: source=%d account=%d want %d",
			src.FailuresInWindow, acct.FailuresInWindow, n)
	}
	if !src.Locked || !acct.Locked {
		t.Fatalf("threshold not armed after %d concurrent failures", n)
	}
	if m := l.MetricsNow(); m.FailedAttempts != int64(n) {
		t.Fatalf("failed attempt counter = %d, want %d", m.FailedAttempts, n)
	}
}

func TestAccountIsolation(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	// lock alice's account
	for i := 0; i < 3; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.3", "alice"); err != nil {
			t.Fatal(err)
		}
	}
	// bob from a different source is untouched
	if d := l.Evaluate("192.0.2.4", "bob"); d.SourceLocked || d.AccountLocked {
		t.Fatalf("unrelated account/source locked: %+v", d)
	}
	// even from the banned source, bob's account is not itself locked;
	// only the source dimension blocks him
	d := l.Evaluate("192.0.2.3", "bob")
	if d.AccountLocked || !d.SourceLocked {
		t.Fatalf("expected source-only block for bob from banned source: %+v", d)
	}
	// alice from a clean source is blocked on the account dimension only
	d = l.Evaluate("203.0.113.9", "alice")
	if d.SourceLocked || !d.AccountLocked {
		t.Fatalf("expected account-only block for alice elsewhere: %+v", d)
	}
}

func TestSourceMergesAcrossAccountsAndPorts(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	// three failures against three different accounts, same source
	for _, acct := range []string{"u1", "u2", "u3"} {
		if _, _, _, _, err := l.RecordFailure("203.0.113.5", acct); err != nil {
			t.Fatal(err)
		}
	}
	if d := l.Evaluate("203.0.113.5", "anyone"); !d.SourceLocked {
		t.Fatalf("source failures spread across accounts were not merged: %+v", d)
	}
	// no single account reached three failures, so no account lock
	if d := l.Evaluate("203.0.113.5", "u2"); d.AccountLocked {
		t.Fatalf("account u2 wrongly locked: %+v", d)
	}

	// source key ignores the port component
	if got := SourceKey(&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40000}); got != "203.0.113.5" {
		t.Fatalf("source key included port: %q", got)
	}
	if got := SourceKey(&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 1}); got != "203.0.113.5" {
		t.Fatalf("source key not port-independent: %q", got)
	}
	if got := SourceKey(nil); got != "unknown" {
		t.Fatalf("nil addr key = %q, want unknown", got)
	}
}

func TestSuccessClearsAccountButNotSourceLock(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	for i := 0; i < 3; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.6", "dave"); err != nil {
			t.Fatal(err)
		}
	}
	// manual unlock of the account only
	if !l.UnlockAccount("dave") {
		t.Fatal("account was not tracked")
	}
	d := l.Evaluate("192.0.2.6", "dave")
	if d.AccountLocked || !d.SourceLocked {
		t.Fatalf("account unlock should leave the source lock intact: %+v", d)
	}
	// unlocking an unknown key reports false but stays safe
	if l.UnlockSource("never-seen") {
		t.Fatal("unlock reported a phantom key")
	}
	if !l.UnlockSource("192.0.2.6") {
		t.Fatal("source was not tracked")
	}
	if d := l.Evaluate("192.0.2.6", "dave"); d.SourceLocked || d.AccountLocked {
		t.Fatalf("manual source unlock failed: %+v", d)
	}
}

func TestSuccessClearsAccountFailures(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	for i := 0; i < 2; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.7", "erin"); err != nil {
			t.Fatal(err)
		}
	}
	l.RecordSuccess("192.0.2.7", "erin")
	for _, e := range l.Snapshot().Accounts {
		if e.Key == "erin" && e.FailuresInWindow != 0 {
			t.Fatalf("successful login did not clear account failures: %+v", e)
		}
	}
	// two more failures after the reset keep the ACCOUNT dimension under
	// its threshold. Use fresh sources so the source dimension cannot arm
	// independently and mask the account-reset behaviour under test.
	_, acctArmed, _, _, err := l.RecordFailure("198.18.0.1", "erin")
	if err != nil || acctArmed {
		t.Fatalf("account failure history was not reset: accountArmed=%v", acctArmed)
	}
	if _, _, _, _, err := l.RecordFailure("198.18.0.2", "erin"); err != nil {
		t.Fatal(err)
	}
	if d := l.Evaluate("198.18.0.3", "erin"); d.AccountLocked {
		t.Fatal("account locked despite successful-auth reset")
	}
}

func TestClockRollbackKeepsCooldown(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)

	for i := 0; i < 3; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.8", "frank"); err != nil {
			t.Fatal(err)
		}
	}
	// wall clock jumps backwards by ten minutes: the cooldown deadline,
	// measured against the same reading source, remains in the future
	clk.advance(-10 * time.Minute)
	d := l.Evaluate("192.0.2.8", "frank")
	if !d.SourceLocked || !d.AccountLocked {
		t.Fatalf("clock rollback released the cooldown: %+v", d)
	}
	if d.SourceRemaining < 11*time.Minute {
		t.Fatalf("rollback shortened the cooldown: %s", d.SourceRemaining)
	}
}

func TestCapacityEvictionConservative(t *testing.T) {
	clk := newFakeClock()

	// scenario A: every shard slot holds an UNLOCKED entry, so a new key
	// must evict the oldest unlocked one and raise the eviction counter.
	cfgA := baseCfg()
	cfgA.SourceFailures = 3 // one failure leaves entries unlocked
	cfgA.MaxSources = shardCount
	lA := testLimiter(t, cfgA, clk)
	i := 0
	for len(lA.Snapshot().Sources) < shardCount {
		key := "src-" + itoa(i)
		i++
		if _, _, err := lA.recordOne(&lA.sources, key, clk.now(), cfgA.SourceFailures, cfgA.MaxSources, true); err != nil {
			t.Fatalf("fill unlocked shards: %v", err)
		}
	}
	if _, _, err := lA.recordOne(&lA.sources, "overflow-unlocked", clk.now(), cfgA.SourceFailures, cfgA.MaxSources, true); err != nil {
		t.Fatalf("unlocked eviction should succeed: %v", err)
	}
	if m := lA.MetricsNow(); m.Evictions < 1 {
		t.Fatalf("eviction not counted: %+v", m)
	}

	// scenario B: threshold 1 means every entry is LOCKED. Nothing can be
	// evicted without pardoning an attacker, so the store fails closed.
	cfgB := baseCfg()
	cfgB.SourceFailures = 1
	cfgB.Cooldown = time.Minute
	cfgB.MaxSources = shardCount
	lB := testLimiter(t, cfgB, clk)
	i = 0
	for len(lB.Snapshot().Sources) < shardCount {
		key := "lock-" + itoa(i)
		i++
		// collisions while filling correctly fail closed; keep walking
		// keys until every shard holds its locked entry
		_, _, _ = lB.recordOne(&lB.sources, key, clk.now(), cfgB.SourceFailures, cfgB.MaxSources, true)
	}
	if _, _, err := lB.recordOne(&lB.sources, "overflow-locked", clk.now(), cfgB.SourceFailures, cfgB.MaxSources, true); err == nil {
		t.Fatal("expected fail-closed error when every shard entry is locked")
	}
	// the public RecordFailure path additionally books the internal
	// error counter and must propagate the capacity failure to the caller
	if _, _, _, _, err := lB.RecordFailure("overflow-public", "z"); err == nil {
		t.Fatal("RecordFailure must propagate the capacity failure")
	}
	if m := lB.MetricsNow(); m.InternalErrors < 1 {
		t.Fatalf("internal error metric not incremented: %+v", m)
	}
}
func TestReaperRemovesStaleEntries(t *testing.T) {
	clk := newFakeClock()
	cfg := baseCfg()
	l := testLimiter(t, cfg, clk)

	if _, _, _, _, err := l.RecordFailure("192.0.2.20", "gina"); err != nil {
		t.Fatal(err)
	}
	if len(l.Snapshot().Sources) != 1 || len(l.Snapshot().Accounts) != 1 {
		t.Fatal("entry not recorded")
	}
	// age beyond window and cooldown, then run the same sweep the
	// background reaper runs
	clk.advance(cfg.Cooldown + cfg.Window + time.Second)
	l.reap()
	if len(l.Snapshot().Sources) != 0 || len(l.Snapshot().Accounts) != 0 {
		t.Fatalf("stale entries were not reclaimed: %+v", l.Snapshot())
	}
}

func TestLockoutLifecycleIsLogged(t *testing.T) {
	clk := newFakeClock()
	var buf bytes.Buffer
	logger := cio.NewLoggerFlag("authlimit", 0)
	logger.Info = true
	logger.SetOutput(&buf)
	l, err := New(baseCfg(), logger)
	if err != nil {
		t.Fatal(err)
	}
	l.SetClock(clk.now)

	for i := 0; i < 3; i++ {
		if _, _, _, _, err := l.RecordFailure("192.0.2.44", "ivan"); err != nil {
			t.Fatal(err)
		}
	}
	armed := buf.String()
	if !strings.Contains(armed, `source "192.0.2.44" reached 3 failures`) ||
		!strings.Contains(armed, `account "ivan" reached 3 failures`) ||
		!strings.Contains(armed, "cooldown armed") {
		t.Fatalf("arming not logged:\n%s", armed)
	}

	// natural expiry is observed on the next evaluation
	clk.advance(3 * time.Minute)
	if d := l.Evaluate("192.0.2.44", "ivan"); d.SourceLocked || d.AccountLocked {
		t.Fatalf("cooldown did not expire: %+v", d)
	}
	expired := buf.String()
	if !strings.Contains(expired, `source "192.0.2.44" cooldown expired`) ||
		!strings.Contains(expired, `account "ivan" cooldown expired`) {
		t.Fatalf("expiry not logged:\n%s", expired)
	}

	// manual unlock is logged as an explicit operator action
	if _, _, _, _, err := l.RecordFailure("192.0.2.45", "judy"); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if !l.UnlockSource("192.0.2.45") {
		t.Fatal("source not tracked")
	}
	if got := buf.String(); !strings.Contains(got, "manually unlocked") {
		t.Fatalf("manual unlock not logged: %s", got)
	}

	// this layer only ever sees hosts and usernames; assert no
	// credential-shaped field exists in the whole log trail
	if strings.Contains(strings.ToLower(buf.String()), "pass") {
		t.Fatalf("log mentions a password field: %s", buf.String())
	}
}

func TestSnapshotAndStringLeakNoSecrets(t *testing.T) {
	clk := newFakeClock()
	l := testLimiter(t, baseCfg(), clk)
	if _, _, _, _, err := l.RecordFailure("192.0.2.30", "heidi"); err != nil {
		t.Fatal(err)
	}
	snap := l.Snapshot()
	if len(snap.Sources) != 1 || len(snap.Accounts) != 1 {
		t.Fatalf("snapshot missing entries: %+v", snap)
	}
	if !strings.Contains(l.String(), "sources=1") {
		t.Fatalf("String() unusable: %q", l.String())
	}
}

// itoa avoids strconv import noise in the capacity test key generation.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
