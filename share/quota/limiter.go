package quota

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

var (
	// ErrDisabled is returned when a nil Limiter is used.
	ErrDisabled = errors.New("quota disabled")
	// ErrQueueFull means the channel's wait queue is full.
	ErrQueueFull = errors.New("channel quota queue full")
	// ErrQueueTimeout means the request waited too long for a slot.
	ErrQueueTimeout = errors.New("channel quota queue timeout")
	// ErrClosed means the limiter was shut down while the request waited.
	ErrClosed = errors.New("channel quota closed")
	// ErrLeaseClosed is returned internally when a closed connection
	// aborts a throttling wait.
	ErrLeaseClosed = errors.New("quota lease closed")
)

const maxThrottleStep = 50 * time.Millisecond

// Limiter owns the quota state of one channel (one remote). All state is
// guarded by mu; Acquire/Release/setLimits are safe for concurrent use.
type Limiter struct {
	name string
	log  *cio.Logger

	mu       sync.Mutex
	limits   Limits
	inflight int
	queue    []*waiter
	closed   bool
	// bucket is guarded by its own mutex so throttling never blocks
	// admission accounting.
	bucket   *bucket
	degraded atomic.Bool

	admitted uint64
	rejected uint64
	timedOut uint64
	bytes    atomic.Int64
	wg       sync.WaitGroup
}

type waiter struct {
	ready   chan struct{}
	granted bool
}

// newLimiter creates a limiter with the given resolved limits.
func newLimiter(name string, limits Limits, log *cio.Logger) *Limiter {
	l := &Limiter{
		name:   name,
		log:    log,
		limits: limits,
		bucket: newBucket(int64(limits.Rate)),
	}
	return l
}

// Acquire admits one connection. On success the caller owns a slot until
// Lease.Release is called, including on every error path. It blocks in the
// channel's bounded queue when the concurrency limit is reached.
//
// On success a waitGroup keeps the goroutine counted until Release, so
// callers can Wait for all admitted work to finish.
func (l *Limiter) Acquire(ctx context.Context) (lease *Lease, err error) {
	if l == nil {
		return nil, ErrDisabled
	}
	defer func() {
		// A bug in quota accounting must never wedge forwarding: degrade to
		// unlimited operation and say so loudly instead of blocking.
		if r := recover(); r != nil {
			l.degrade(r, "acquire")
			lease, err = l.newLease(0, false), nil
		}
	}()
	if l.degraded.Load() {
		return l.newLease(0, false), nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	limits := l.limits
	if l.inflight < limits.MaxConns {
		l.inflight++
		l.admitted++
		l.mu.Unlock()
		return l.newLease(time.Duration(limits.IdleTimeout), true), nil
	}
	if len(l.queue) >= limits.MaxQueue {
		l.rejected++
		l.mu.Unlock()
		return nil, fmt.Errorf("%w (max %d in flight, %d queued)", ErrQueueFull, limits.MaxConns, len(l.queue))
	}
	w := &waiter{ready: make(chan struct{})}
	l.queue = append(l.queue, w)
	l.mu.Unlock()

	timer := time.NewTimer(time.Duration(limits.QueueTimeout))
	defer timer.Stop()
	select {
	case <-w.ready:
		l.mu.Lock()
		if l.closed {
			l.releaseLocked()
			l.mu.Unlock()
			return nil, ErrClosed
		}
		l.admitted++
		limits = l.limits //use the current limits for the new lease
		l.mu.Unlock()
		if l.degraded.Load() {
			return l.newLease(0, false), nil
		}
		return l.newLease(time.Duration(limits.IdleTimeout), true), nil
	case <-timer.C:
		return l.abandon(w, ErrQueueTimeout)
	case <-ctx.Done():
		return l.abandon(w, ctx.Err())
	}
}

// abandon releases a queue entry. If a slot was granted concurrently, the
// slot is handed to the next waiter instead of being leaked.
func (l *Limiter) abandon(w *waiter, cause error) (*Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if errors.Is(cause, ErrQueueTimeout) {
		l.timedOut++
	}
	if w.granted {
		//a slot arrived as the request gave up: pass it on, never leak it
		l.releaseLocked()
	} else {
		for i, queued := range l.queue {
			if queued == w {
				l.queue = append(l.queue[:i], l.queue[i+1:]...)
				break
			}
		}
	}
	return nil, cause
}

// releaseLocked returns a slot. If requests are waiting, the slot transfers
// to the oldest waiter, keeping inflight constant. Caller holds l.mu.
func (l *Limiter) releaseLocked() {
	if len(l.queue) > 0 {
		w := l.queue[0]
		l.queue = l.queue[1:]
		w.granted = true
		close(w.ready)
		return
	}
	if l.inflight > 0 {
		l.inflight--
	}
}

// degrade switches the limiter to unlimited operation. It is called when an
// internal accounting error (panic) occurs.
func (l *Limiter) degrade(reason any, op string) {
	if !l.degraded.CompareAndSwap(false, true) {
		return
	}
	l.log.Infof("WARNING: quota accounting for channel %q failed during %s (%v); "+
		"forwarding continues without limits for this channel", l.name, op, reason)
	l.mu.Lock()
	//stop tracking occupancy: leases already in flight release against the
	//guard in releaseLocked, so the counter cannot go negative
	l.inflight = 0
	for len(l.queue) > 0 {
		w := l.queue[0]
		l.queue = l.queue[1:]
		w.granted = true
		close(w.ready)
	}
	l.mu.Unlock()
}

// setLimits applies new limits at runtime. In-flight connections are never
// interrupted: they finish naturally, and only new admissions use the new
// values. The rate bucket takes effect for subsequent reads and writes.
func (l *Limiter) setLimits(limits Limits) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.limits = limits
	l.mu.Unlock()
	l.bucket.setRate(int64(limits.Rate))
}

// Close stops the limiter, waking queued requests with ErrClosed. In-flight
// leases still release normally.
func (l *Limiter) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	for len(l.queue) > 0 {
		w := l.queue[0]
		l.queue = l.queue[1:]
		w.granted = true
		close(w.ready)
	}
	l.mu.Unlock()
}

// stats snapshots one channel.
func (l *Limiter) stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	return Stats{
		Channel:  l.name,
		InFlight: l.inflight,
		Queued:   len(l.queue),
		MaxConns: l.limits.MaxConns,
		MaxQueue: l.limits.MaxQueue,
		Rate:     l.limits.Rate,
		Bytes:    l.bytes.Load(),
		Admitted: l.admitted,
		Rejected: l.rejected,
		TimedOut: l.timedOut,
		Degraded: l.degraded.Load(),
	}
}

func (l *Limiter) newLease(idle time.Duration, holds bool) *Lease {
	lease := &Lease{
		l:     l,
		holds: holds,
		idle:  idle,
		done:  make(chan struct{}),
	}
	lease.lastActivity.Store(time.Now().UnixNano())
	if holds && l != nil {
		l.wg.Add(1)
	}
	if idle > 0 {
		go lease.watchIdle()
	}
	return lease
}

// Wait blocks until every admitted lease has been released.
func (l *Limiter) Wait() {
	if l != nil {
		l.wg.Wait()
	}
}

// Lease is one admitted connection. Release must be called exactly once when
// forwarding ends; it is idempotent and safe on every error path.
type Lease struct {
	l     *Limiter
	holds bool
	idle  time.Duration

	done         chan struct{}
	released     sync.Once
	lastActivity atomic.Int64

	connMu sync.Mutex
	conn   io.Closer
}

// Release returns the connection's slot to the channel. It is idempotent so
// callers may defer it unconditionally on every error path.
func (q *Lease) Release() {
	if q == nil {
		return
	}
	q.released.Do(func() {
		close(q.done)
		if !q.holds || q.l == nil {
			return
		}
		// Always return the slot: an accounting panic must not leak quota
		// or wedge Wait.
		func() {
			defer q.l.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					//unlock before degrading, which takes the same mutex
					go q.l.degrade(r, "release")
				}
			}()
			q.l.mu.Lock()
			defer q.l.mu.Unlock()
			q.l.releaseLocked()
		}()
	})
}

func (q *Lease) account(n int) {
	if q == nil || n <= 0 {
		return
	}
	q.lastActivity.Store(time.Now().UnixNano())
	if q.l == nil {
		return
	}
	q.l.bytes.Add(int64(n))
	if q.l.degraded.Load() {
		return
	}
	rate := q.l.bucket
	if err := rate.wait(n, q.done); err != nil {
		return
	}
}

func (q *Lease) watchIdle() {
	interval := q.idle / 4
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-q.done:
			return
		case <-ticker.C:
		}
		last := time.Unix(0, q.lastActivity.Load())
		if time.Since(last) < q.idle {
			continue
		}
		q.connMu.Lock()
		conn := q.conn
		q.connMu.Unlock()
		if conn == nil {
			continue
		}
		q.l.log.Infof("Channel %q connection idle for %s, closing (per-channel timeout)",
			q.l.name, q.idle)
		conn.Close()
		return
	}
}

// Wrap returns a read-write closer which accounts bytes, applies the
// channel's aggregate rate limit and enforces the optional idle timeout.
// The wrapper preserves CloseWrite so cio.Pipe keeps propagating half-closes.
func (q *Lease) Wrap(rwc io.ReadWriteCloser) io.ReadWriteCloser {
	w := &throttled{rwc: rwc, lease: q}
	q.connMu.Lock()
	q.conn = w
	q.connMu.Unlock()
	return w
}

type throttled struct {
	rwc   io.ReadWriteCloser
	lease *Lease
}

// Read passes data through. Bytes are counted on the matching Write: every
// tunneled byte is written once per direction, so counting reads too would
// double the totals and halve the effective rate.
func (t *throttled) Read(p []byte) (int, error) {
	return t.rwc.Read(p)
}

func (t *throttled) Write(p []byte) (int, error) {
	n, err := t.rwc.Write(p)
	if n > 0 {
		t.lease.account(n)
	}
	return n, err
}

func (t *throttled) Close() error { return t.rwc.Close() }

// CloseWrite forwards the half-close when the underlying stream supports it.
func (t *throttled) CloseWrite() error {
	if cw, ok := t.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.rwc.Close()
}

// bucket is a token bucket shared by both directions of one channel, so the
// limit is aggregate rather than per direction.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	burst  float64
	last   time.Time
}

func newBucket(rate int64) *bucket {
	b := &bucket{rate: float64(rate)}
	b.burst = b.rate
	b.tokens = b.burst
	b.last = time.Now()
	return b
}

func (b *bucket) setRate(rate int64) {
	b.mu.Lock()
	b.rate = float64(rate)
	b.burst = b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = time.Now()
	b.mu.Unlock()
}

// wait blocks until n bytes of allowance are available, or returns
// ErrLeaseClosed. Long waits are split so shutdown never stalls.
func (b *bucket) wait(n int, done <-chan struct{}) error {
	remaining := float64(n)
	for remaining > 0 {
		b.mu.Lock()
		if b.rate <= 0 {
			b.mu.Unlock()
			return nil
		}
		now := time.Now()
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
		if b.tokens >= remaining {
			b.tokens -= remaining
			b.mu.Unlock()
			return nil
		}
		remaining -= b.tokens
		b.tokens = 0
		delay := time.Duration(remaining / b.rate * float64(time.Second))
		b.mu.Unlock()
		if delay > maxThrottleStep {
			delay = maxThrottleStep
		}
		if delay < time.Millisecond {
			delay = time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-done:
			timer.Stop()
			return ErrLeaseClosed
		case <-timer.C:
		}
	}
	return nil
}
