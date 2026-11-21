package quota

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// Set is the process-wide quota state: one registry of per-channel limiters
// plus the optional hot-reloadable file. A single Set is shared by every
// tunnel of one chisel process (and, on the server, by every session), which
// keeps a channel's quota stable across reconnects.
type Set struct {
	log        *cio.Logger
	registry   *Registry
	provider   *Provider
	statsEvery time.Duration

	mu       sync.RWMutex
	defaults Limits
	live     map[string]bool
}

// NewSet validates cfg and builds the quota state. It fails with the
// offending option when the configuration is invalid, so callers can refuse
// to start.
func NewSet(cfg Config, log *cio.Logger) (*Set, error) {
	if !cfg.Active() {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return newSet(cfg.Defaults(), cfg.File, cfg.StatsInterval, log)
}

// NewSetForTest builds a Set from resolved limits, used by unit tests.
func NewSetForTest(defaults Limits, file string, log *cio.Logger) (*Set, error) {
	if err := defaults.Validate(); err != nil {
		return nil, err
	}
	return newSet(defaults, file, 0, log)
}

func newSet(defaults Limits, file string, statsEvery time.Duration, log *cio.Logger) (*Set, error) {
	if log == nil {
		log = cio.NewLogger("quota")
	}
	s := &Set{
		log:        log.Fork("quota"),
		registry:   NewRegistry(log),
		defaults:   defaults,
		statsEvery: statsEvery,
		live:       map[string]bool{},
	}
	provider, err := NewProvider(file, log, s.reapplyAll)
	if err != nil {
		s.registry.Close()
		return nil, err
	}
	s.provider = provider
	return s, nil
}

// Defaults returns the global limits used for channels without an override.
func (s *Set) Defaults() Limits {
	if s == nil {
		return Limits{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaults
}

// Acquire is the admission gate for one channel. A nil Set or a disabled
// configuration returns (nil, nil), meaning "unlimited": callers then take
// the original forwarding path without any wrapper.
func (s *Set) Acquire(ctx context.Context, channel string) (*Lease, error) {
	if s == nil || !s.enabled() {
		return nil, nil
	}
	limits := s.resolve(channel)
	s.mu.Lock()
	s.live[channel] = true
	s.mu.Unlock()
	l := s.registry.Get(channel, limits)
	if l == nil {
		return nil, ErrClosed
	}
	lease, err := l.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("channel %q: %w", channel, err)
	}
	return lease, nil
}

func (s *Set) enabled() bool {
	return s != nil && s.registry != nil
}

// resolve combines the global defaults with the channel's file override.
func (s *Set) resolve(channel string) Limits {
	s.mu.RLock()
	limits := s.defaults
	s.mu.RUnlock()
	if s.provider != nil {
		if override, ok := s.provider.Override(channel); ok {
			limits = override.Overlay(limits)
		}
	}
	return limits
}

// Limits returns the effective limits for a channel.
func (s *Set) Limits(channel string) Limits {
	if !s.enabled() {
		return Limits{}
	}
	return s.resolve(channel)
}

// SetLimits updates the global defaults and every live channel. In-flight
// connections finish under the old values; new admissions use the new ones.
func (s *Set) SetLimits(limits Limits) error {
	if !s.enabled() {
		return nil
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.defaults = limits
	s.mu.Unlock()
	s.reapplyAll()
	return nil
}

// SetChannelLimits overrides one live channel at runtime, bypassing the file.
func (s *Set) SetChannelLimits(channel string, limits Limits) error {
	if !s.enabled() {
		return nil
	}
	if err := limits.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	s.live[channel] = true
	s.mu.Unlock()
	l := s.registry.Get(channel, limits)
	if l == nil {
		return ErrClosed
	}
	l.setLimits(limits)
	return nil
}

// reapplyAll pushes freshly resolved limits to every live channel. It is
// called after a global change or a quota file reload.
func (s *Set) reapplyAll() {
	if !s.enabled() {
		return
	}
	s.mu.RLock()
	channels := make([]string, 0, len(s.live))
	for channel := range s.live {
		channels = append(channels, channel)
	}
	s.mu.RUnlock()
	for _, channel := range channels {
		limits := s.resolve(channel)
		if l := s.registry.Get(channel, limits); l != nil {
			l.setLimits(limits)
		}
	}
}

// Stats snapshots every live channel.
func (s *Set) Stats() []Stats {
	if !s.enabled() {
		return nil
	}
	return s.registry.Stats()
}

// StatsJSON renders the current usage sample as indented JSON, for tooling
// and documentation. Channel keys contain "=>", so HTML escaping is disabled
// to keep them readable.
func (s *Set) StatsJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	stats := []Stats{}
	if s.enabled() {
		stats = s.Stats()
	}
	if err := enc.Encode(stats); err != nil {
		return nil, err
	}
	//trim the trailing newline Encode appends
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// LogStats writes one usage line per live channel.
func (s *Set) LogStats() {
	if !s.enabled() {
		return
	}
	s.registry.LogStats()
}

// LogStatsLoop logs usage until ctx is cancelled.
func (s *Set) LogStatsLoop(ctx context.Context) {
	if !s.enabled() {
		return
	}
	s.registry.LogStatsLoop(ctx, s.statsEvery)
}

// Close stops the file watcher and every limiter.
func (s *Set) Close() {
	if !s.enabled() {
		return
	}
	if s.provider != nil {
		s.provider.Close()
	}
	s.registry.Close()
}
