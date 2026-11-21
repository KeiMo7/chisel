package quota

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// Registry owns one Limiter per channel key. Keys are stable remote encodings
// (settings.Remote.Encode), so reconnects reuse the same counters and limits
// instead of resetting them. All methods are safe for concurrent use.
type Registry struct {
	log *cio.Logger

	mu       sync.Mutex
	limiters map[string]*Limiter
	closed   bool
}

// NewRegistry creates an empty registry.
func NewRegistry(log *cio.Logger) *Registry {
	if log == nil {
		log = cio.NewLogger("quota")
	}
	return &Registry{
		log:      log.Fork("quota"),
		limiters: map[string]*Limiter{},
	}
}

// Get returns the limiter for the given stable channel key, creating it with
// the supplied limits on first use. Later calls return the existing limiter,
// so quota is never reset by a reconnect.
func (r *Registry) Get(key string, limits Limits) *Limiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.limiters[key]; ok {
		return l
	}
	if r.closed {
		return nil
	}
	l := newLimiter(key, limits, r.log)
	r.limiters[key] = l
	return l
}

// Stats snapshots every live channel, sorted by key.
func (r *Registry) Stats() []Stats {
	r.mu.Lock()
	live := make([]*Limiter, 0, len(r.limiters))
	for _, l := range r.limiters {
		live = append(live, l)
	}
	r.mu.Unlock()
	stats := make([]Stats, 0, len(live))
	for _, l := range live {
		stats = append(stats, l.stats())
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Channel < stats[j].Channel })
	return stats
}

// Close stops every limiter and rejects future Get calls.
func (r *Registry) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	live := make([]*Limiter, 0, len(r.limiters))
	for _, l := range r.limiters {
		live = append(live, l)
	}
	r.mu.Unlock()
	for _, l := range live {
		l.Close()
	}
}

// Stats is a point-in-time usage sample for one channel.
type Stats struct {
	Channel  string `json:"channel"`
	InFlight int    `json:"in-flight"`
	Queued   int    `json:"queued"`
	MaxConns int    `json:"max-conns"`
	MaxQueue int    `json:"max-queue"`
	Rate     Rate   `json:"rate"`
	Bytes    int64  `json:"bytes"`
	Admitted uint64 `json:"admitted"`
	Rejected uint64 `json:"rejected"`
	TimedOut uint64 `json:"timed-out"`
	Degraded bool   `json:"degraded"`
}

// String renders one usage sample for the periodic stats log.
func (s Stats) String() string {
	return fmt.Sprintf("in-flight=%d/%d queued=%d/%d bytes=%d admitted=%d rejected=%d timed-out=%d",
		s.InFlight, s.MaxConns, s.Queued, s.MaxQueue, s.Bytes, s.Admitted, s.Rejected, s.TimedOut)
}

// LogStats writes one line per live channel.
func (r *Registry) LogStats() {
	for _, s := range r.Stats() {
		r.log.Infof("channel %q: %s", s.Channel, s)
	}
}

// LogStatsLoop logs until ctx is cancelled. interval <= 0 is a no-op.
func (r *Registry) LogStatsLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.LogStats()
		}
	}
}
