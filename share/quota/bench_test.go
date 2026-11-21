package quota

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// BenchmarkQuotaDisabled measures the forwarding seam when quotas are off,
// i.e. the unchanged nil-Set path.
func BenchmarkQuotaDisabled(b *testing.B) {
	var set *Set
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease, err := set.Acquire(context.Background(), "ch")
		if err != nil || lease != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkQuotaEnabled measures admission plus accounting on the enabled
// path, at the defaults (1 GiB/s, so throttling is not the bottleneck).
func BenchmarkQuotaEnabled(b *testing.B) {
	set, err := NewSetForTest(testLimits(64, 64), "", cio.NewLogger("bench"))
	if err != nil {
		b.Fatal(err)
	}
	defer set.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lease, err := set.Acquire(context.Background(), "ch")
		if err != nil {
			b.Fatal(err)
		}
		lease.Release()
	}
}

// BenchmarkQuotaWrapIO measures the per-read/write accounting overhead with
// the rate cap set to the allowed maximum, so the numbers show the wrapper
// itself rather than the default 1 GiB/s ceiling.
func BenchmarkQuotaWrapIO(b *testing.B) {
	limits := testLimits(1, 1)
	limits.Rate = Rate(MaxRate)
	set, err := NewSetForTest(limits, "", cio.NewLogger("bench"))
	if err != nil {
		b.Fatal(err)
	}
	defer set.Close()
	lease, err := set.Acquire(context.Background(), "ch")
	if err != nil {
		b.Fatal(err)
	}
	defer lease.Release()
	w := lease.Wrap(&sinkRWC{})
	buf := make([]byte, 32*1024)
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// TestNoExtraGoroutinesWhenDisabled checks that the disabled path is inert:
// a nil Set is a no-op and never starts background workers.
func TestNoExtraGoroutinesWhenDisabled(t *testing.T) {
	var set *Set
	if lease, err := set.Acquire(context.Background(), "x"); lease != nil || err != nil {
		t.Fatalf("nil set gated forwarding: %v %v", lease, err)
	}
	cfg := Config{}
	if cfg.Active() {
		t.Fatal("zero config reported active")
	}
	s, err := NewSet(cfg, cio.NewLogger("test"))
	if err != nil || s != nil {
		t.Fatalf("disabled config created state: %v %v", s, err)
	}
}

type sinkRWC struct{}

func (sinkRWC) Read([]byte) (int, error)    { return 0, io.EOF }
func (sinkRWC) Write(p []byte) (int, error) { return len(p), nil }
func (sinkRWC) Close() error                { return nil }

// TestIdleTimeoutIsPerChannel checks a stalled connection is closed after the
// idle timeout via the two-way accounting, and that a busy one survives.
func TestIdleTimeoutIsPerChannel(t *testing.T) {
	limits := testLimits(4, 4)
	limits.IdleTimeout = Duration(60 * time.Millisecond)
	set, err := NewSetForTest(limits, "", cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	stalled, err := set.Acquire(context.Background(), "stalled")
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Release()
	conn := &closableRWC{}
	stalled.Wrap(conn)
	busy, err := set.Acquire(context.Background(), "busy")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Release()
	busyConn := &closableRWC{}
	bw := busy.Wrap(busyConn)
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		bw.Write([]byte("keepalive"))
		time.Sleep(15 * time.Millisecond)
	}
	if !conn.closed.Load() {
		t.Fatal("stalled connection was not closed by the idle timeout")
	}
	if busyConn.closed.Load() {
		t.Fatal("busy connection was closed by the idle timeout")
	}
}

type closableRWC struct {
	closed atomic.Bool
}

func (c *closableRWC) Read([]byte) (int, error) { return 0, io.EOF }
func (c *closableRWC) Write(p []byte) (int, error) {
	return len(p), nil
}
func (c *closableRWC) Close() error { c.closed.Store(true); return nil }

// TestStatsSampleFormat pins the operator-visible usage sample format.
func TestStatsSampleFormat(t *testing.T) {
	set, err := NewSetForTest(testLimits(2, 3), "", cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	lease, err := set.Acquire(context.Background(), "3000=>svc:80")
	if err != nil {
		t.Fatal(err)
	}
	w := lease.Wrap(&sinkRWC{})
	w.Write(make([]byte, 1024))
	got := set.Stats()[0].String()
	want := fmt.Sprintf("in-flight=1/2 queued=0/3 bytes=1024 admitted=1 rejected=0 timed-out=0")
	if got != want {
		t.Fatalf("stats sample:\n got %q\nwant %q", got, want)
	}
	lease.Release()
}
