// Package authlimit implements in-memory authentication failure tracking
// with sliding-window counting and fixed cooldown ("lockout") periods.
//
// Two independent dimensions are tracked:
//
//   - source: the peer's network address (host part only), so a single
//     attacker cannot spread attempts across ephemeral source ports
//   - account: the presented username, so attacks on one account do not
//     lock the others
//
// The store is sharded: hot keys only contend with their own shard, there
// is no global lock on the authentication path, and every state mutation
// happens while holding one shard lock, so concurrent failures from the
// same source cannot lose increments.
//
// All state is in-memory only. A restart starts with an empty store, which
// fails open (nothing is locked), and cooldowns use monotonic time, so a
// wall-clock jump backwards can never shorten or cancel a cooldown.
package authlimit

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// shardCount is fixed and a power of two so shard selection is a mask.
const shardCount = 64

// Config tunes the failure limiter. The zero value is not valid; use
// DefaultConfig and Validate.
type Config struct {
	// SourceFailures is the number of failed attempts from one source
	// within Window that arms a source cooldown.
	SourceFailures int
	// AccountFailures is the number of failed attempts against one
	// account within Window that arms an account cooldown.
	AccountFailures int
	// Window is the sliding window in which failures are counted.
	Window time.Duration
	// Cooldown is the lockout duration armed once a threshold is hit.
	Cooldown time.Duration
	// MaxSources bounds the number of source entries kept.
	MaxSources int
	// MaxAccounts bounds the number of account entries kept.
	MaxAccounts int
}

// DefaultConfig returns safe, conservative defaults: ten failures from a
// source or against an account within five minutes arms a ten-minute
// cooldown, and each dimension keeps at most ten thousand entries.
func DefaultConfig() Config {
	return Config{
		SourceFailures:  10,
		AccountFailures: 10,
		Window:          5 * time.Minute,
		Cooldown:        10 * time.Minute,
		MaxSources:      10000,
		MaxAccounts:     10000,
	}
}

// Validate rejects illegal configuration so callers can refuse to start.
func (c Config) Validate() error {
	if c.SourceFailures < 1 {
		return fmt.Errorf("auth-limit: source failure threshold must be >= 1, got %d", c.SourceFailures)
	}
	if c.AccountFailures < 1 {
		return fmt.Errorf("auth-limit: account failure threshold must be >= 1, got %d", c.AccountFailures)
	}
	if c.Window <= 0 {
		return fmt.Errorf("auth-limit: window must be > 0, got %s", c.Window)
	}
	if c.Cooldown <= 0 {
		return fmt.Errorf("auth-limit: cooldown must be > 0, got %s", c.Cooldown)
	}
	if c.MaxSources < 1 {
		return fmt.Errorf("auth-limit: max sources must be >= 1, got %d", c.MaxSources)
	}
	if c.MaxAccounts < 1 {
		return fmt.Errorf("auth-limit: max accounts must be >= 1, got %d", c.MaxAccounts)
	}
	return nil
}

// entry tracks one source or account. Failures are monotonic timestamps
// inside the current window; the slice is capped at the arming threshold
// because additional history can never change a decision once the
// cooldown is armed and earlier entries only age out.
type entry struct {
	failures []time.Time
	// until is the monotonic deadline of the armed cooldown; the zero
	// value means no cooldown is active.
	until time.Time
	// lastSeen orders eviction when the shard is full.
	lastSeen time.Time
}

// cooling reports whether the entry is currently locked, returning the
// remaining cooldown. Uses monotonic time, so wall-clock rollback cannot
// release a lock early.
func (e *entry) cooling(now time.Time) (time.Duration, bool) {
	if e.until.IsZero() {
		return 0, false
	}
	if !now.Before(e.until) {
		return 0, false
	}
	return e.until.Sub(now), true
}

// prune drops failure timestamps outside the sliding window and clears an
// expired cooldown. Must be called with the shard lock held.
func (e *entry) prune(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	keep := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	e.failures = keep
	if !e.until.IsZero() && !now.Before(e.until) {
		e.until = time.Time{}
	}
}

type shard struct {
	mu      sync.Mutex
	entries map[string]*entry
}

// Metrics are counters observable while the process runs. They are
// monotonic and safe to read concurrently.
type Metrics struct {
	FailedAttempts   atomic.Int64
	SourceCooldowns  atomic.Int64
	AccountCooldowns atomic.Int64
	LockedRejections atomic.Int64
	SuccessfulAuths  atomic.Int64
	Evictions        atomic.Int64
	InternalErrors   atomic.Int64
}

// Decision is the result of evaluating one authentication attempt,
// recorded before the caller compares credentials.
type Decision struct {
	// SourceLocked / AccountLocked mean a cooldown is active and the
	// attempt must be rejected regardless of the password.
	SourceLocked  bool
	AccountLocked bool
	// SourceRemaining / AccountRemaining carry the cooldown remainder
	// when the corresponding lock is active.
	SourceRemaining  time.Duration
	AccountRemaining time.Duration
}

// EntrySnapshot is the externally visible state of one tracked key.
type EntrySnapshot struct {
	Key               string    `json:"key"`
	FailuresInWindow  int       `json:"failures_in_window"`
	Locked            bool      `json:"locked"`
	CooldownRemaining float64   `json:"cooldown_remaining_seconds"`
	LastSeen          time.Time `json:"last_seen"`
}

// Snapshot is a point-in-time copy of the whole store for inspection.
type Snapshot struct {
	Sources  []EntrySnapshot `json:"sources"`
	Accounts []EntrySnapshot `json:"accounts"`
	Metrics  MetricsSnapshot `json:"metrics"`
}

// MetricsSnapshot is a plain-value copy of Metrics.
type MetricsSnapshot struct {
	FailedAttempts   int64 `json:"failed_attempts"`
	SourceCooldowns  int64 `json:"source_cooldowns_armed"`
	AccountCooldowns int64 `json:"account_cooldowns_armed"`
	LockedRejections int64 `json:"locked_rejections"`
	SuccessfulAuths  int64 `json:"successful_auths"`
	Evictions        int64 `json:"evictions"`
	InternalErrors   int64 `json:"internal_errors"`
}

// Limiter is the concurrency-safe failure store.
type Limiter struct {
	cfg      Config
	logger   *cio.Logger
	sources  [shardCount]shard
	accounts [shardCount]shard
	metrics  Metrics
	// now yields the current time. Production uses time.Now, whose
	// monotonic readings make cooldowns immune to wall-clock rollback;
	// tests override it to simulate jumps without real sleeps.
	now func() time.Time
}

// New validates the configuration and builds an empty limiter. Start the
// background reaper with StartReaper when bounded memory growth matters.
func New(cfg Config, logger *cio.Logger) (*Limiter, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	l := &Limiter{cfg: cfg, logger: logger, now: time.Now}
	for i := range l.sources {
		l.sources[i].entries = make(map[string]*entry)
		l.accounts[i].entries = make(map[string]*entry)
	}
	return l, nil
}

// SetClock overrides the time source. It exists for deterministic tests;
// production callers leave the default time.Now clock untouched.
func (l *Limiter) SetClock(now func() time.Time) {
	if now != nil {
		l.now = now
	}
}

// StartReaper periodically removes expired entries so the maps cannot
// grow without bound even when no traffic touches the stale keys. It stops
// when ctx is cancelled.
func (l *Limiter) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.reap()
			}
		}
	}()
}

func (l *Limiter) shardFor(key string, entries *[shardCount]shard) *shard {
	// FNV-1a inline: no allocation, good distribution for short keys.
	var h uint32 = 2166136261
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &entries[h&(shardCount-1)]
}

// SourceKey extracts the host of a peer address so every connection from
// one IP shares a single counter regardless of source port. Addresses
// without a host collapse onto a conservative shared key rather than
// bypassing tracking.
func SourceKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		// some Addr implementations omit the port; use the raw string
		host = addr.String()
	}
	if host == "" {
		return "unknown"
	}
	return host
}

// Evaluate checks whether either dimension is currently in cooldown. It
// performs no mutation and never blocks on another shard.
func (l *Limiter) Evaluate(source, account string) Decision {
	now := l.now()
	d := Decision{}
	if rem, locked := l.locked(&l.sources, source, "source", now); locked {
		d.SourceLocked, d.SourceRemaining = true, rem
	}
	if rem, locked := l.locked(&l.accounts, account, "account", now); locked {
		d.AccountLocked, d.AccountRemaining = true, rem
	}
	if d.SourceLocked || d.AccountLocked {
		l.metrics.LockedRejections.Add(1)
	}
	return d
}

func (l *Limiter) locked(entries *[shardCount]shard, key, dim string, now time.Time) (time.Duration, bool) {
	s := l.shardFor(key, entries)
	s.mu.Lock()
	e, ok := s.entries[key]
	if !ok {
		s.mu.Unlock()
		return 0, false
	}
	wasCooling := !e.until.IsZero()
	e.prune(now, l.cfg.Window)
	if wasCooling && e.until.IsZero() {
		// natural expiry observed on the authentication path
		l.logf("auth-limit: %s %q cooldown expired, access restored", dim, key)
	}
	rem, locked := e.cooling(now)
	s.mu.Unlock()
	return rem, locked
}

// RecordFailure registers one failed attempt on both dimensions and arms
// a cooldown when a threshold is reached within the window. All updates
// for a given key happen under that key's shard lock, so concurrent
// failures from the same source cannot lose counts.
//
// The armed return values indicate whether this specific failure crossed
// the threshold. The returned error is non-nil only on internal state
// failure (e.g. capacity exhausted with every entry locked), in which
// case callers must reject the attempt as an internal failure.
func (l *Limiter) RecordFailure(source, account string) (sourceArmed, accountArmed bool, sourceRemain, accountRemain time.Duration, err error) {
	l.metrics.FailedAttempts.Add(1)
	now := l.now()
	sourceArmed, sourceRemain, err = l.recordOne(&l.sources, source, now, l.cfg.SourceFailures, l.cfg.MaxSources, true)
	if err != nil {
		l.metrics.InternalErrors.Add(1)
		return false, false, 0, 0, err
	}
	accountArmed, accountRemain, err = l.recordOne(&l.accounts, account, now, l.cfg.AccountFailures, l.cfg.MaxAccounts, false)
	if err != nil {
		l.metrics.InternalErrors.Add(1)
		return false, false, 0, 0, err
	}
	return
}

// recordOne returns armed=true only when this call crosses the threshold.
// A non-nil error means the key could not be tracked and the caller must
// fail closed.
func (l *Limiter) recordOne(entries *[shardCount]shard, key string, now time.Time, threshold, maxPerDim int, isSource bool) (armed bool, remain time.Duration, err error) {
	defer func() {
		if r := recover(); r != nil {
			armed, remain = false, 0
			err = fmt.Errorf("auth-limit: internal state failure: %v", r)
		}
	}()
	s := l.shardFor(key, entries)
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[key]
	if !ok {
		// Conservative capacity handling: if the shard is already at
		// its share of the cap, make room before tracking a new key.
		if len(s.entries) >= capForShard(maxPerDim) {
			if !l.evictLocked(s, now, isSource) {
				// Everything tracked is locked: dropping tracking of a
				// locked key would pardon an attacker, so refuse rather
				// than silently fail open.
				dim := "account"
				if isSource {
					dim = "source"
				}
				return false, 0, fmt.Errorf("auth-limit: %s tracking capacity exhausted with all entries locked", dim)
			}
		}
		e = &entry{}
		s.entries[key] = e
	}
	e.prune(now, l.cfg.Window)
	e.lastSeen = now
	if len(e.failures) < threshold {
		e.failures = append(e.failures, now)
	}
	if !e.until.IsZero() {
		// already cooling: further attempts do not extend the cooldown
		return false, e.until.Sub(now), nil
	}
	if len(e.failures) >= threshold {
		e.until = now.Add(l.cfg.Cooldown)
		dim := "account"
		if isSource {
			dim = "source"
			l.metrics.SourceCooldowns.Add(1)
		} else {
			l.metrics.AccountCooldowns.Add(1)
		}
		l.logf("auth-limit: %s %q reached %d failures within %s, cooldown armed for %s",
			dim, key, threshold, l.cfg.Window, l.cfg.Cooldown)
		return true, l.cfg.Cooldown, nil
	}
	return false, 0, nil
}

// capForShard divides the per-dimension cap across the fixed shards,
// guaranteeing the total map size stays bounded by the configured cap
// (plus at most shardCount-1 entries).
func capForShard(dimCap int) int {
	per := dimCap / shardCount
	if per < 1 {
		per = 1
	}
	return per
}

// logf is nil-safe: unit tests construct limiters without a logger.
func (l *Limiter) logf(format string, args ...any) {
	if l.logger != nil {
		l.logger.Infof(format, args...)
	}
}

// evictLocked makes room in a full shard. It first reaps expired entries,
// then removes the unlocked entry with the oldest activity. Locked
// entries are never evicted, since losing their cooldown would pardon an
// active attacker. Returns false when nothing could be dropped.
func (l *Limiter) evictLocked(s *shard, now time.Time, isSource bool) bool {
	dim := "account"
	if isSource {
		dim = "source"
	}
	// pass 1: anything already expired
	for k, e := range s.entries {
		e.prune(now, l.cfg.Window)
		if e.until.IsZero() && len(e.failures) == 0 {
			delete(s.entries, k)
			l.metrics.Evictions.Add(1)
			l.logf("auth-limit: reaped expired %s entry %q during capacity eviction", dim, k)
			return true
		}
	}
	// pass 2: oldest unlocked entry
	var oldestKey string
	var oldestTime time.Time
	for k, e := range s.entries {
		if !e.until.IsZero() {
			continue
		}
		if oldestKey == "" || e.lastSeen.Before(oldestTime) {
			oldestKey, oldestTime = k, e.lastSeen
		}
	}
	if oldestKey == "" {
		return false
	}
	delete(s.entries, oldestKey)
	l.metrics.Evictions.Add(1)
	l.logf("auth-limit: capacity reached, abandoned tracking of %s %q "+
		"(oldest unlocked entry); its failure history was discarded", dim, oldestKey)
	return true
}

// RecordSuccess clears the account's failure history (a successful login
// proves the account is not under a continuing guess attack) and lets the
// source's window decay naturally on its own. An active source cooldown
// is not cleared: a correct password from a banned source must still be
// rejected while the cooldown runs.
func (l *Limiter) RecordSuccess(source, account string) {
	l.metrics.SuccessfulAuths.Add(1)
	now := l.now()
	l.clearAccount(account, now)
	l.touchSource(source, now)
}

func (l *Limiter) clearAccount(account string, now time.Time) {
	s := l.shardFor(account, &l.accounts)
	s.mu.Lock()
	if e, ok := s.entries[account]; ok {
		e.prune(now, l.cfg.Window)
		e.failures = nil
	}
	s.mu.Unlock()
}

func (l *Limiter) touchSource(source string, now time.Time) {
	s := l.shardFor(source, &l.sources)
	s.mu.Lock()
	if e, ok := s.entries[source]; ok {
		e.prune(now, l.cfg.Window)
		e.lastSeen = now
	}
	s.mu.Unlock()
}

// UnlockSource manually clears a source cooldown and its failure history.
// It reports whether the key was tracked.
func (l *Limiter) UnlockSource(source string) bool {
	return l.manualUnlock(&l.sources, source, "source")
}

// UnlockAccount manually clears an account cooldown and its failure
// history. It reports whether the key was tracked.
func (l *Limiter) UnlockAccount(account string) bool {
	return l.manualUnlock(&l.accounts, account, "account")
}

func (l *Limiter) manualUnlock(entries *[shardCount]shard, key, dim string) bool {
	s := l.shardFor(key, entries)
	s.mu.Lock()
	_, ok := s.entries[key]
	delete(s.entries, key)
	s.mu.Unlock()
	if ok {
		l.logf("auth-limit: %s %q manually unlocked, cooldown and failures cleared", dim, key)
	}
	return ok
}

// reap removes fully-expired entries across every shard.
func (l *Limiter) reap() {
	now := l.now()
	reapShard := func(entries *[shardCount]shard) {
		for i := range entries {
			s := &entries[i]
			s.mu.Lock()
			for k, e := range s.entries {
				e.prune(now, l.cfg.Window)
				if e.until.IsZero() && len(e.failures) == 0 {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
	reapShard(&l.sources)
	reapShard(&l.accounts)
}

// Snapshot copies the current state for inspection endpoints and tests.
func (l *Limiter) Snapshot() Snapshot {
	now := l.now()
	snap := Snapshot{
		Sources:  l.snapshotDimension(&l.sources, now),
		Accounts: l.snapshotDimension(&l.accounts, now),
		Metrics: MetricsSnapshot{
			FailedAttempts:   l.metrics.FailedAttempts.Load(),
			SourceCooldowns:  l.metrics.SourceCooldowns.Load(),
			AccountCooldowns: l.metrics.AccountCooldowns.Load(),
			LockedRejections: l.metrics.LockedRejections.Load(),
			SuccessfulAuths:  l.metrics.SuccessfulAuths.Load(),
			Evictions:        l.metrics.Evictions.Load(),
			InternalErrors:   l.metrics.InternalErrors.Load(),
		},
	}
	return snap
}

func (l *Limiter) snapshotDimension(entries *[shardCount]shard, now time.Time) []EntrySnapshot {
	out := []EntrySnapshot{}
	for i := range entries {
		s := &entries[i]
		s.mu.Lock()
		for k, e := range s.entries {
			e.prune(now, l.cfg.Window)
			rem, locked := e.cooling(now)
			out = append(out, EntrySnapshot{
				Key:               k,
				FailuresInWindow:  len(e.failures),
				Locked:            locked,
				CooldownRemaining: rem.Seconds(),
				LastSeen:          e.lastSeen,
			})
		}
		s.mu.Unlock()
	}
	return out
}

// MetricsNow returns a plain-value copy of the live counters.
func (l *Limiter) MetricsNow() MetricsSnapshot {
	return l.Snapshot().Metrics
}

// String renders the active lock state for operator logs. It never
// includes credentials: keys are source hosts or usernames only.
func (l *Limiter) String() string {
	snap := l.Snapshot()
	var b strings.Builder
	fmt.Fprintf(&b, "sources=%d accounts=%d locked_rejections=%d failed=%d",
		len(snap.Sources), len(snap.Accounts), snap.Metrics.LockedRejections, snap.Metrics.FailedAttempts)
	return b.String()
}
