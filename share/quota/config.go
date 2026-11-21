// Package quota implements opt-in, per-remote-channel admission control and
// byte-rate limiting for chisel's inbound proxies.
//
// Each proxy (one remote) owns its own Limiter, so a saturated channel can
// only block its own new requests. Limiter state is kept in a Registry keyed
// by the remote's stable encoding, so it survives SSH reconnects within the
// process. The zero Config is disabled; when disabled no wrapper, mutex or
// goroutine is added to the forwarding path.
package quota

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jpillora/sizestr"
)

// Upper bounds. MaxConns is bounded because every admitted connection
// consumes one SSH channel (and its flow-control window), so a large value
// would defeat the purpose of isolating the shared SSH connection.
const (
	MaxConns = 256
	MaxQueue = 4096
	MaxRate  = int64(1) << 40 // 1 TiB/s
)

// Defaults used by the command line front ends when quotas are enabled.
const (
	DefaultMaxConns     = 8
	DefaultMaxQueue     = 32
	DefaultRate         = int64(1) << 30 // 1 GiB/s: a rate bucket is always present
	DefaultQueueTimeout = 30 * time.Second
)

// Rate is a bytes-per-second limit. When used as a command line flag it
// parses size strings such as "10MB" (decimal) or "1MiB" (binary).
type Rate int64

// Set implements opts.Setter (and flag.Value).
func (r *Rate) Set(s string) error {
	n, err := sizestr.Parse(s)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid byte rate %q (use e.g. 10MB, 1MiB or 1048576)", s)
	}
	*r = Rate(n)
	return nil
}

func (r Rate) String() string {
	if r == 0 {
		return "0"
	}
	//render exact binary multiples as e.g. "1GiB" rather than "1.07GB"
	if int64(r) >= 1<<10 && int64(r)%(1<<10) == 0 {
		units := []string{"KiB", "MiB", "GiB", "TiB"}
		v := float64(r)
		for _, unit := range units {
			v /= 1024
			if v < 1024 || unit == "TiB" {
				return strconv.FormatFloat(v, 'f', -1, 64) + unit
			}
		}
	}
	return sizestr.ToString(int64(r))
}

// UnmarshalJSON accepts either a size string ("10MB") or a number of bytes.
func (r *Rate) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		return r.Set(s)
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil || n < 0 {
		return fmt.Errorf("invalid rate %s (use a size string or bytes)", b)
	}
	*r = Rate(n)
	return nil
}

// Duration is a JSON duration that accepts a Go duration string ("30s") or a
// number of seconds.
type Duration time.Duration

func (d Duration) String() string { return time.Duration(d).String() }

func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var secs float64
	if err := json.Unmarshal(b, &secs); err != nil {
		return fmt.Errorf("invalid duration %s (use a string such as \"30s\" or seconds)", b)
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// Limits are the fully resolved limits for one channel.
type Limits struct {
	MaxConns     int      `json:"max-conns"`
	MaxQueue     int      `json:"max-queue"`
	Rate         Rate     `json:"rate"`
	QueueTimeout Duration `json:"queue-timeout"`
	// IdleTimeout zero disables the idle watchdog.
	IdleTimeout Duration `json:"idle-timeout"`
}

// Unset reports whether every field is zero, so callers can apply defaults.
func (l Limits) Unset() bool {
	return l.MaxConns == 0 && l.MaxQueue == 0 && l.Rate == 0 &&
		l.QueueTimeout == 0 && l.IdleTimeout == 0
}

// Overlay fills zero fields of l from other.
func (l Limits) Overlay(other Limits) Limits {
	if l.MaxConns == 0 {
		l.MaxConns = other.MaxConns
	}
	if l.MaxQueue == 0 {
		l.MaxQueue = other.MaxQueue
	}
	if l.Rate == 0 {
		l.Rate = other.Rate
	}
	if l.QueueTimeout == 0 {
		l.QueueTimeout = other.QueueTimeout
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = other.IdleTimeout
	}
	return l
}

// Validate checks resolved limits and names every offending field.
func (l Limits) Validate() error {
	if l.MaxConns < 1 || l.MaxConns > MaxConns {
		return fmt.Errorf("max-conns must be between 1 and %d (got %d)", MaxConns, l.MaxConns)
	}
	if l.MaxQueue < 1 || l.MaxQueue > MaxQueue {
		return fmt.Errorf("max-queue must be between 1 and %d (got %d)", MaxQueue, l.MaxQueue)
	}
	if l.Rate < 1 || int64(l.Rate) > MaxRate {
		return fmt.Errorf("rate must be between 1B and %s per second (got %s)",
			sizestr.ToString(MaxRate), l.Rate)
	}
	if l.QueueTimeout <= 0 {
		return fmt.Errorf("queue-timeout must be greater than zero (got %s)", l.QueueTimeout)
	}
	if l.IdleTimeout < 0 {
		return fmt.Errorf("idle-timeout must be zero or positive (got %s)", l.IdleTimeout)
	}
	return nil
}

// Config controls the per-channel quota. It is embedded in the server and
// client configurations, so its fields are also command line flags.
type Config struct {
	Enabled       bool          `opts:"name=quota,short=-" help:"Enable per-remote-channel admission quotas. Each remote gets an independent concurrency limit, a bounded wait queue, a byte-rate limit and usage counters. Disabled by default, which keeps the previous unlimited forwarding behaviour and log format."`
	File          string        `opts:"name=quota-file,short=-" help:"An optional JSON file with per-channel quota overrides, for example {\"channels\":{\"3000=>example.com:3000\":{\"max-conns\":2}}}. The file is watched and reloaded at runtime; an invalid update is logged and ignored. Setting this flag enables quotas even without --quota."`
	MaxConns      int           `opts:"name=quota-max-conns,short=-" help:"Maximum number of in-flight connections per remote channel when quotas are enabled. Each in-flight connection consumes one SSH channel. Allowed range is 1 to 256."`
	MaxQueue      int           `opts:"name=quota-max-queue,short=-" help:"Maximum number of connections waiting for a per-channel slot when quotas are enabled. When the queue is full, new connections are rejected immediately instead of accumulating. Allowed range is 1 to 4096."`
	BytesPerSec   Rate          `opts:"name=quota-rate,short=-" help:"Aggregate byte-rate limit per remote channel, in both directions, when quotas are enabled. Accepts size suffixes such as 10MB or 1MiB. Allowed range is 1B to 1TiB per second. The 1GiB default effectively disables throttling."`
	QueueTimeout  time.Duration `opts:"name=quota-queue-timeout,short=-" help:"Maximum time a connection may wait in a per-channel queue when quotas are enabled. Expired requests are closed and release their queue entry."`
	IdleTimeout   time.Duration `opts:"name=quota-idle-timeout,short=-" help:"Optional per-connection idle timeout for quota-managed channels. A connection that transfers no tunneled bytes in either direction for this long is closed and its quota slot returned, without affecting other channels. Must be 0 (disabled, the default) or positive, e.g. 2m."`
	StatsInterval time.Duration `opts:"name=quota-stats,short=-" help:"Log per-channel quota usage (in-flight, queue length, cumulative bytes) at this interval when quotas are enabled. Zero (the default) disables periodic logging; the counters are also available through the Go API."`
}

// DefaultConfig returns the defaults used by the command line front ends when
// quotas are enabled. Enabled and File are left zero; callers turn quotas on.
func DefaultConfig() Config {
	return Config{
		MaxConns:     DefaultMaxConns,
		MaxQueue:     DefaultMaxQueue,
		BytesPerSec:  Rate(DefaultRate),
		QueueTimeout: DefaultQueueTimeout,
	}
}

// Active reports whether quotas are enabled, either explicitly or through a
// quota file.
func (c Config) Active() bool {
	return c.Enabled || c.File != ""
}

// Defaults converts the configured global values into Limits.
func (c Config) Defaults() Limits {
	return Limits{
		MaxConns:     c.MaxConns,
		MaxQueue:     c.MaxQueue,
		Rate:         c.BytesPerSec,
		QueueTimeout: Duration(c.QueueTimeout),
		IdleTimeout:  Duration(c.IdleTimeout),
	}
}

// Validate checks the configuration and names the offending option in every
// error. Disabled configurations are always valid.
func (c Config) Validate() error {
	if !c.Active() {
		return nil
	}
	//validate each flag directly so the error names the exact option
	if c.MaxConns < 1 || c.MaxConns > MaxConns {
		return fmt.Errorf("--quota-max-conns must be between 1 and %d (got %d)", MaxConns, c.MaxConns)
	}
	if c.MaxQueue < 1 || c.MaxQueue > MaxQueue {
		return fmt.Errorf("--quota-max-queue must be between 1 and %d (got %d)", MaxQueue, c.MaxQueue)
	}
	if c.BytesPerSec < 1 || int64(c.BytesPerSec) > MaxRate {
		return fmt.Errorf("--quota-rate must be between 1B and %s per second (got %s)",
			sizestr.ToString(MaxRate), c.BytesPerSec)
	}
	if c.QueueTimeout <= 0 {
		return fmt.Errorf("--quota-queue-timeout must be greater than zero (got %s)", c.QueueTimeout)
	}
	if c.IdleTimeout < 0 {
		return fmt.Errorf("--quota-idle-timeout must be zero or positive (got %s)", c.IdleTimeout)
	}
	if c.StatsInterval < 0 {
		return fmt.Errorf("--quota-stats must be zero or positive (got %s)", c.StatsInterval)
	}
	return nil
}
