package quota

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

func testSet(t *testing.T, limits Limits) *Set {
	t.Helper()
	s, err := NewSetForTest(limits, "", cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func testLimits(maxConns, maxQueue int) Limits {
	return Limits{
		MaxConns:     maxConns,
		MaxQueue:     maxQueue,
		Rate:         Rate(DefaultRate),
		QueueTimeout: Duration(2 * time.Second),
	}
}

// TestConcurrentAcquireNeverExceedsLimit races many acquirers against one
// channel and checks the in-flight count never passes the limit.
func TestConcurrentAcquireNeverExceedsLimit(t *testing.T) {
	const limit = 4
	s := testSet(t, testLimits(limit, 64))
	var peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := s.Acquire(context.Background(), "ch")
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			n := int32(s.Stats()[0].InFlight)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			lease.Release()
		}()
	}
	wg.Wait()
	if peak.Load() > limit {
		t.Fatalf("in-flight peaked at %d, limit %d", peak.Load(), limit)
	}
	//every admitted lease must return its slot
	l := s.registry.Get("ch", s.Defaults())
	l.Wait()
	if got := l.stats().InFlight; got != 0 {
		t.Fatalf("in-flight leaked after release: %d", got)
	}
	if got := l.stats().Queued; got != 0 {
		t.Fatalf("queue leaked after release: %d", got)
	}
}

// TestQueueIsBounded checks that requests beyond the queue bound are rejected
// immediately instead of accumulating.
func TestQueueIsBounded(t *testing.T) {
	s := testSet(t, testLimits(1, 2))
	first, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatal(err)
	}
	blocked := make(chan *Lease, 2)
	for i := 0; i < 2; i++ {
		go func() {
			lease, err := s.Acquire(context.Background(), "ch")
			if err != nil {
				blocked <- nil
				return
			}
			blocked <- lease
		}()
	}
	//wait for both to be queued
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.Stats()[0].Queued == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if lease, err := s.Acquire(context.Background(), "ch"); !errors.Is(err, ErrQueueFull) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("expected ErrQueueFull, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("queue-full rejection blocked for %s", elapsed)
	}
	first.Release()
	<-blocked
	<-blocked
}

// TestQueueTimeoutReleasesEntry checks timed-out waiters free their queue
// entry and that the slot is still handed on cleanly.
func TestQueueTimeoutReleasesEntry(t *testing.T) {
	limits := testLimits(1, 1)
	limits.QueueTimeout = Duration(30 * time.Millisecond)
	s := testSet(t, limits)
	lease, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Acquire(context.Background(), "ch")
	if !errors.Is(err, ErrQueueTimeout) {
		t.Fatalf("expected queue timeout, got %v", err)
	}
	lease.Release()
	l := s.registry.Get("ch", s.Defaults())
	if got := l.stats().Queued; got != 0 {
		t.Fatalf("timed-out waiter left %d queued", got)
	}
	next, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatalf("slot not returned after timeout: %v", err)
	}
	next.Release()
}

// TestRuntimeLimitChange checks lower limits only affect new admissions and
// that in-flight connections finish naturally.
func TestRuntimeLimitChange(t *testing.T) {
	s := testSet(t, testLimits(4, 4))
	var leases []*Lease
	for i := 0; i < 3; i++ {
		lease, err := s.Acquire(context.Background(), "ch")
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	//lower the limit; the three in-flight connections are untouched and
	//only new admissions use the new value
	if err := s.SetLimits(testLimits(2, 4)); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats()[0].InFlight; got != 3 {
		t.Fatalf("in-flight changed by lower limit: %d", got)
	}
	//once a connection finishes, in-flight is 2, which equals the new
	//limit, so the next request must queue rather than start
	leases[0].Release()
	admitted := make(chan *Lease, 1)
	go func() {
		lease, err := s.Acquire(context.Background(), "ch")
		if err != nil {
			admitted <- nil
			return
		}
		admitted <- lease
	}()
	select {
	case <-admitted:
		t.Fatal("new request bypassed the lowered limit")
	case <-time.After(100 * time.Millisecond):
	}
	if got := s.Stats()[0].Queued; got != 1 {
		t.Fatalf("expected 1 queued, got %d", got)
	}
	for _, lease := range leases[1:] {
		lease.Release()
	}
	select {
	case lease := <-admitted:
		if lease == nil {
			t.Fatal("queued request failed after slots freed")
		}
		lease.Release()
	case <-time.After(time.Second):
		t.Fatal("queued request was not admitted after slots freed")
	}
}

// TestAbnormalReleaseReturnsQuota exercises release on panic-like paths:
// every lease is released even when forwarding fails, and the quota is fully
// returned.
func TestAbnormalReleaseReturnsQuota(t *testing.T) {
	s := testSet(t, testLimits(2, 8))
	//simulate forwarding failures: the lease is wrapped and released in a
	//defer exactly like the proxy does on connection reset / dial failure
	fail := func() {
		lease, err := s.Acquire(context.Background(), "ch")
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		rwc := lease.Wrap(&failingRWC{})
		defer rwc.Close()
		//rest of forwarding would run here
	}
	for i := 0; i < 20; i++ {
		fail()
	}
	l := s.registry.Get("ch", s.Defaults())
	l.Wait()
	st := l.stats()
	if st.InFlight != 0 || st.Queued != 0 {
		t.Fatalf("quota leaked: in-flight=%d queued=%d", st.InFlight, st.Queued)
	}
	if st.Admitted != 20 {
		t.Fatalf("admitted=%d, want 20", st.Admitted)
	}
	//and the full capacity is available again
	var leases []*Lease
	for i := 0; i < 2; i++ {
		lease, err := s.Acquire(context.Background(), "ch")
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	for _, lease := range leases {
		lease.Release()
	}
}

type failingRWC struct{}

func (f *failingRWC) Read([]byte) (int, error)  { return 0, io.ErrUnexpectedEOF }
func (f *failingRWC) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (f *failingRWC) Close() error              { return nil }

// TestChannelsAreIsolated checks that a saturated channel does not block
// another channel's admissions.
func TestChannelsAreIsolated(t *testing.T) {
	s := testSet(t, testLimits(1, 1))
	busy, err := s.Acquire(context.Background(), "busy")
	if err != nil {
		t.Fatal(err)
	}
	//fill busy's queue
	queued := make(chan struct{})
	go func() {
		lease, err := s.Acquire(context.Background(), "busy")
		if err == nil {
			lease.Release()
		}
		close(queued)
	}()
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	other, err := s.Acquire(context.Background(), "other")
	if err != nil {
		t.Fatalf("isolated channel rejected: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("isolated channel was delayed by %s", elapsed)
	}
	other.Release()
	busy.Release()
	<-queued
}

// TestStableChannelAcrossReconnect checks that the same key reuses counters
// instead of resetting quota.
func TestStableChannelAcrossReconnect(t *testing.T) {
	s := testSet(t, testLimits(2, 2))
	lease, err := s.Acquire(context.Background(), "stable")
	if err != nil {
		t.Fatal(err)
	}
	before := s.Stats()[0]
	if before.Admitted != 1 {
		t.Fatalf("admitted=%d", before.Admitted)
	}
	//a reconnect resolves the same channel from the registry
	l1 := s.registry.Get("stable", s.Defaults())
	l2 := s.registry.Get("stable", s.Defaults())
	if l1 != l2 {
		t.Fatal("reconnect created a fresh limiter")
	}
	if got := l1.stats().InFlight; got != 1 {
		t.Fatalf("quota reset on reconnect: in-flight=%d", got)
	}
	lease.Release()
}

// TestDisabledSetIsInert checks that a disabled Set never gates forwarding.
func TestDisabledSetIsInert(t *testing.T) {
	s, err := NewSet(Config{}, cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	if s != nil {
		t.Fatal("disabled config produced a Set")
	}
	lease, err := s.Acquire(context.Background(), "ch")
	if err != nil || lease != nil {
		t.Fatalf("disabled set gated forwarding: %v %v", lease, err)
	}
}

// TestStatsAccountBytes checks the counters exposed to operators.
func TestStatsAccountBytes(t *testing.T) {
	s := testSet(t, testLimits(2, 2))
	lease, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatal(err)
	}
	w := lease.Wrap(&echoRWC{Reader: bytesReader("hello")})
	buf := make([]byte, 5)
	//reads pass through uncounted; writes are counted once per direction
	if _, err := io.ReadFull(w, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	st := s.Stats()[0]
	if st.Bytes != 5 {
		t.Fatalf("bytes=%d, want 5 (one count per direction)", st.Bytes)
	}
	if st.Channel != "ch" || st.MaxConns != 2 || st.MaxQueue != 2 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	lease.Release()
}

type bytesReader string

func (b bytesReader) Read(p []byte) (int, error) {
	if len(b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b)
	return n, nil
}

type echoRWC struct {
	Reader io.Reader
	bytes.Buffer
}

func (e *echoRWC) Read(p []byte) (int, error) { return e.Reader.Read(p) }
func (e *echoRWC) Close() error               { return nil }

// TestRateLimitThrottles verifies the aggregate byte rate is enforced and the
// wait aborts when the lease closes.
func TestRateLimitThrottles(t *testing.T) {
	limits := testLimits(1, 1)
	limits.Rate = Rate(1000) //1KB/s
	s := testSet(t, limits)
	lease, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	w := lease.Wrap(&echoRWC{Reader: bytesReader("")})
	start := time.Now()
	//2KB at 1KB/s takes about a second; the bucket starts full, so one
	//burst chunk is free and the rest is throttled
	if _, err := w.Write(make([]byte, 2000)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed < 750*time.Millisecond {
		t.Fatalf("rate limit not applied: %s for 2000 bytes at 1000 B/s", elapsed)
	}
	//closing the lease aborts a throttled write promptly
	go func() {
		time.Sleep(20 * time.Millisecond)
		lease.Release()
	}()
	start = time.Now()
	w.Write(make([]byte, 8000))
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("throttled write did not abort on release: %s", elapsed)
	}
}

// TestDegradedOnAccountingPanic checks an accounting failure degrades to
// unlimited instead of wedging the channel.
func TestDegradedOnAccountingPanic(t *testing.T) {
	s := testSet(t, testLimits(1, 1))
	l := s.registry.Get("ch", s.Defaults())
	lease, err := l.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	l.degrade("boom", "test")
	if !l.degraded.Load() {
		t.Fatal("limiter did not degrade")
	}
	//after degradation, admission is immediate and unlimited
	var leases []*Lease
	for i := 0; i < 10; i++ {
		lease, err := l.Acquire(context.Background())
		if err != nil {
			t.Fatalf("degraded limiter rejected: %v", err)
		}
		leases = append(leases, lease)
	}
	if got := l.stats().InFlight; got != 0 {
		t.Fatalf("degraded limiter still tracks in-flight: %d", got)
	}
	for _, lease := range leases {
		lease.Release()
	}
}

// TestCloseWakesQueued checks shutdown releases waiters with ErrClosed.
func TestCloseWakesQueued(t *testing.T) {
	s := testSet(t, testLimits(1, 1))
	lease, err := s.Acquire(context.Background(), "ch")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.Acquire(context.Background(), "ch")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	s.Close()
	lease.Release()
	select {
	case err := <-done:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("expected ErrClosed, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake queued request")
	}
}

// TestValidateNamesOffendingOption checks startup validation messages.
func TestValidateNamesOffendingOption(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		expect string
	}{
		{"zero conns", Config{Enabled: true, MaxConns: 0, MaxQueue: 1, BytesPerSec: 1, QueueTimeout: time.Second}, "--quota-max-conns"},
		{"negative conns", Config{Enabled: true, MaxConns: -1, MaxQueue: 1, BytesPerSec: 1, QueueTimeout: time.Second}, "--quota-max-conns"},
		{"too many conns", Config{Enabled: true, MaxConns: MaxConns + 1, MaxQueue: 1, BytesPerSec: 1, QueueTimeout: time.Second}, "--quota-max-conns"},
		{"zero queue", Config{Enabled: true, MaxConns: 1, MaxQueue: 0, BytesPerSec: 1, QueueTimeout: time.Second}, "--quota-max-queue"},
		{"zero rate", Config{Enabled: true, MaxConns: 1, MaxQueue: 1, BytesPerSec: 0, QueueTimeout: time.Second}, "--quota-rate"},
		{"huge rate", Config{Enabled: true, MaxConns: 1, MaxQueue: 1, BytesPerSec: Rate(MaxRate + 1), QueueTimeout: time.Second}, "--quota-rate"},
		{"zero timeout", Config{Enabled: true, MaxConns: 1, MaxQueue: 1, BytesPerSec: 1}, "--quota-queue-timeout"},
		{"negative idle", Config{Enabled: true, MaxConns: 1, MaxQueue: 1, BytesPerSec: 1, QueueTimeout: time.Second, IdleTimeout: -time.Second}, "--quota-idle-timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.expect) {
				t.Fatalf("expected error naming %s, got %v", tc.expect, err)
			}
		})
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("disabled config rejected: %v", err)
	}
}

// TestQuotaFileOverrides checks per-channel file limits overlay the defaults
// and reload to live channels.
func TestQuotaFileOverrides(t *testing.T) {
	path := t.TempDir() + "/quota.json"
	write := func(body string) {
		if err := writeFile(path, body); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"channels":{"slow":{"max-conns":1,"max-queue":2}}}`)
	base := testLimits(8, 32)
	s, err := NewSetForTest(base, path, cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	slow := s.Limits("slow")
	if slow.MaxConns != 1 || slow.MaxQueue != 2 {
		t.Fatalf("override not applied: %+v", slow)
	}
	if slow.Rate != base.Rate || slow.QueueTimeout != base.QueueTimeout {
		t.Fatalf("overlay clobbered defaults: %+v", slow)
	}
	if got := s.Limits("other"); got != base {
		t.Fatalf("unmentioned channel changed: %+v", got)
	}
	//create a live limiter, then reload with a new value
	lease, err := s.Acquire(context.Background(), "slow")
	if err != nil {
		t.Fatal(err)
	}
	write(`{"channels":{"slow":{"max-conns":2,"max-queue":3}}}`)
	if err := s.provider.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := s.Limits("slow").MaxConns; got != 2 {
		t.Fatalf("reload did not update limits: %d", got)
	}
	lease.Release()
	//an invalid update is rejected and leaves the previous limits
	write(`{"channels":{"slow":{"max-conns":0}}}`)
	if err := s.provider.Reload(); err == nil {
		t.Fatal("invalid quota file accepted")
	}
	if got := s.Limits("slow").MaxConns; got != 2 {
		t.Fatalf("invalid reload changed limits: %d", got)
	}
}

func TestQuotaFileInvalidAtStartup(t *testing.T) {
	path := t.TempDir() + "/quota.json"
	if err := writeFile(path, `{"channels":{"ch":{"max-queue":-1}}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSetForTest(testLimits(2, 2), path, cio.NewLogger("test")); err == nil {
		t.Fatal("invalid quota file accepted at startup")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
