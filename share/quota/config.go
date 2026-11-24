// Package quota contains the opt-in admission, backpressure, fair scheduling
// and bounded drop/metrics primitives used by chisel's multiplexed tunnels.
//
// The zero Config is disabled.  In that state callers should bypass this
// package completely, preserving the historical forwarding path and its
// performance characteristics.
//
// All metric labels are low-cardinality constants.  Client addresses, target
// addresses, channel identifiers and credentials must never be used as label
// values or embedded in category errors.
package quota

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Kind is the bounded admission/channel class used in metrics.
type Kind string

const (
	KindForward  Kind = "forward"
	KindReverse  Kind = "reverse"
	KindProxy    Kind = "proxy"
	KindDatagram Kind = "datagram"
)

// Direction is the bounded metric direction label.
type Direction string

const (
	DirectionIn  Direction = "in"
	DirectionOut Direction = "out"
)

// Category identifies a rejection without carrying peer-controlled detail.
type Category string

const (
	CategoryClient Category = "client_quota"
	CategoryGlobal Category = "global_quota"
	CategoryTarget Category = "target_quota"
	CategoryAccess Category = "access_denied"
	CategoryState  Category = "unavailable"
)

// Error is a safe, diagnosable quota/admission error.  Error strings contain
// only fixed text; never addresses, identities or credentials.
type Error struct {
	Category Category
	reason   string
	message  string
}

func (e *Error) Error() string { return e.message }

// Reason returns the bounded machine reason.
func (e *Error) Reason() string { return e.reason }

// Is allows errors.Is(err, ErrClientQuota) style checks by category.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Category == e.Category
}

var (
	// ErrClientQuota means the responsible client/principal used all of its
	// hard or fair-share channel quota.
	ErrClientQuota = &Error{Category: CategoryClient, reason: "client_limit", message: "client channel quota exceeded"}
	// ErrGlobalQuota means the shared process/session capacity is full or its
	// protected newcomer reserve is unavailable to this client.
	ErrGlobalQuota = &Error{Category: CategoryGlobal, reason: "global_limit", message: "global channel capacity reached"}
	// ErrTargetQuota means one forwarding target used its target quota.
	ErrTargetQuota = &Error{Category: CategoryTarget, reason: "target_limit", message: "target channel quota exceeded"}
	// ErrAccessDenied preserves the distinguishable ACL category.
	ErrAccessDenied = &Error{Category: CategoryAccess, reason: "acl", message: "access denied"}
	// ErrUnavailable means the tunnel/transport is not currently usable.
	ErrUnavailable = &Error{Category: CategoryState, reason: "no_ssh_connection", message: "tunnel connection unavailable"}
)

func rejectionError(cat Category, reason string) *Error {
	base := ErrGlobalQuota
	switch cat {
	case CategoryClient:
		base = ErrClientQuota
	case CategoryTarget:
		base = ErrTargetQuota
	case CategoryAccess:
		base = ErrAccessDenied
	case CategoryState:
		base = ErrUnavailable
	}
	return &Error{Category: cat, reason: reason, message: base.message}
}

// CategoryOf returns the error category, or "" for unrelated errors.
func CategoryOf(err error) Category {
	var qe *Error
	if errors.As(err, &qe) {
		return qe.Category
	}
	return ""
}

// ByteSize is an int64 number of bytes parsed from plain integers or common
// size suffixes.
type ByteSize int64

func (b ByteSize) String() string { return strconv.FormatInt(int64(b), 10) }

// Set implements flag.Value/opts.Setter.
func (b *ByteSize) Set(v string) error {
	v = strings.TrimSpace(v)
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return fmt.Errorf("size must not be negative")
		}
		*b = ByteSize(n)
		return nil
	}
	mult := int64(1)
	upper := strings.ToUpper(v)
	for _, u := range []struct {
		suffix string
		m      int64
	}{
		{"KIB", 1024}, {"MIB", 1024 * 1024}, {"GIB", 1024 * 1024 * 1024},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1024}, {"M", 1024 * 1024}, {"G", 1024 * 1024 * 1024},
	} {
		if strings.HasSuffix(upper, u.suffix) {
			v = v[:len(v)-len(u.suffix)]
			mult = u.m
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid byte size %q", v)
	}
	*b = ByteSize(n * mult)
	return nil
}

// Config configures the optional mux protection layer.  Zero values mean
// "unlimited/disabled" for the corresponding limit unless Defaults is used.
type Config struct {
	// Enabled turns on admission and managed streams even if all limits are
	// zero.  Setting any positive limit also enables the layer.
	Enabled bool `opts:"name=mux-protect,short=-" help:"Enable multiplexed admission, bounded backlog, fair scheduling and quota metrics. Off by default, preserving unlimited legacy behaviour."`
	// MaxChannels is the process-wide cap for a server Manager.  On a client
	// it is the cap for the single shared tunnel.  Zero is unlimited.
	MaxChannels int `opts:"name=mux-max-channels,short=-" help:"Maximum concurrent multiplexed channels in this quota domain. Zero means unlimited (the default)."`
	// MaxClientChannels caps one principal/client.  Zero is unlimited.
	MaxClientChannels int `opts:"name=mux-max-client-channels,short=-" help:"Maximum concurrent channels owned by one authenticated client/session. Zero means unlimited."`
	// ClientReserve keeps this many global slots for clients below their fair
	// minimum.  It is clamped to MaxClientChannels and MaxChannels.
	ClientReserve int `opts:"name=mux-client-reserve,short=-" help:"Guaranteed channel slots reserved for new or below-share clients when fair admission is enabled."`
	// MaxTargetChannels caps channels with the same internal target scope.
	MaxTargetChannels int `opts:"name=mux-max-target-channels,short=-" help:"Maximum concurrent channels to one forwarding target. Zero means unlimited."`
	// TargetReserve keeps principal capacity available to other targets.
	TargetReserve int `opts:"name=mux-target-reserve,short=-" help:"Minimum channels protected for other forwarding targets of the same client."`
	// MaxPendingBytes bounds one managed channel's queued plus in-flight data.
	MaxPendingBytes ByteSize `opts:"name=mux-max-backlog-bytes,short=-" help:"Maximum queued plus in-flight bytes per channel; writers block at this bound instead of growing without limit."`
	// FairChunkBytes is the maximum chunk given to one fair-scheduler turn.
	FairChunkBytes int `opts:"name=mux-fair-chunk-bytes,short=-" help:"Maximum bytes sent by one fair scheduler turn (default 16384 when protection is enabled)."`
	// DatagramQueue is the bounded packet queue used on congestion-prone
	// datagram paths.  Overflow drops and counts a datagram.
	DatagramQueue int `opts:"name=mux-datagram-queue,short=-" help:"Maximum queued datagrams per relay queue before new datagrams are dropped and counted."`
	// SlowConsumerTimeout closes a channel whose bounded write remains blocked
	// for this long. Zero selects the default; a negative value disables it.
	SlowConsumerTimeout time.Duration `opts:"name=mux-slow-consumer-timeout,short=-" help:"Close a channel whose writes stay blocked for this duration; only that channel is closed and counted."`
	// Metrics enables the low-cardinality /metrics and /debug/quotas endpoints.
	Metrics bool `opts:"name=mux-metrics,short=-" help:"Expose chisel quota, backlog, drop and saturation metrics at /metrics and JSON at /debug/quotas."`
}

// Active reports whether any optional protection should be installed.
func (c Config) Active() bool {
	return c.Enabled || c.MaxChannels > 0 || c.MaxClientChannels > 0 ||
		c.ClientReserve > 0 || c.MaxTargetChannels > 0 || c.TargetReserve > 0 ||
		c.MaxPendingBytes > 0 || c.FairChunkBytes > 0 || c.DatagramQueue > 0 ||
		c.SlowConsumerTimeout != 0
}

// WithDefaults fills operational defaults for an explicitly active config.
// It deliberately does not invent channel concurrency caps.
func (c Config) WithDefaults() Config {
	if !c.Active() {
		// Metrics-only mode still exposes the registry without installing
		// schedulers, quotas or other data-path behavior.
		c.Enabled = false
		return c
	}
	c.Enabled = true
	if c.MaxChannels < 0 {
		c.MaxChannels = 0
	}
	if c.MaxClientChannels < 0 {
		c.MaxClientChannels = 0
	}
	if c.MaxTargetChannels < 0 {
		c.MaxTargetChannels = 0
	}
	if c.MaxPendingBytes <= 0 {
		c.MaxPendingBytes = 1 << 20 // 1 MiB per channel
	}
	if c.FairChunkBytes <= 0 {
		c.FairChunkBytes = 16 << 10 // 16 KiB
	}
	if c.DatagramQueue <= 0 {
		c.DatagramQueue = 256
	}
	if c.SlowConsumerTimeout == 0 {
		c.SlowConsumerTimeout = 15 * time.Second
	}
	if c.ClientReserve < 0 {
		c.ClientReserve = 0
	}
	if c.TargetReserve < 0 {
		c.TargetReserve = 0
	}
	return c
}

// ApplyEnv overlays CHISEL_MUX_* settings.  Environment is used by tests and
// operators who prefer the repository's existing EnvInt/EnvDuration style.
func (c Config) ApplyEnv() Config {
	get := func(names ...string) (string, bool) {
		for _, n := range names {
			if v := os.Getenv("CHISEL_" + n); v != "" {
				return v, true
			}
		}
		return "", false
	}
	if v, ok := get("MUX_PROTECT", "MUX_ENABLED", "QUOTA_ENABLED"); ok {
		c.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
	envInt := func(target *int, names ...string) {
		if v, ok := get(names...); ok {
			if n, err := strconv.Atoi(v); err == nil {
				*target = n
			}
		}
	}
	envInt(&c.MaxChannels, "MUX_MAX_CHANNELS", "QUOTA_MAX_CHANNELS", "MAX_CHANNELS")
	envInt(&c.MaxClientChannels, "MUX_CLIENT_MAX_CHANNELS", "MUX_MAX_CLIENT_CHANNELS", "QUOTA_CLIENT_MAX")
	envInt(&c.ClientReserve, "MUX_CLIENT_RESERVE", "QUOTA_CLIENT_RESERVE")
	envInt(&c.MaxTargetChannels, "MUX_TARGET_MAX_CHANNELS", "QUOTA_TARGET_MAX")
	envInt(&c.TargetReserve, "MUX_TARGET_RESERVE", "QUOTA_TARGET_RESERVE")
	envInt(&c.FairChunkBytes, "MUX_FAIR_CHUNK_BYTES")
	envInt(&c.DatagramQueue, "MUX_DATAGRAM_QUEUE", "DATAGRAM_QUEUE")
	if v, ok := get("MUX_MAX_BACKLOG_BYTES", "MUX_BACKLOG", "QUOTA_MAX_PENDING_BYTES"); ok {
		var b ByteSize
		if err := b.Set(v); err == nil {
			c.MaxPendingBytes = b
		}
	}
	if v, ok := get("MUX_SLOW_CONSUMER_TIMEOUT", "SLOW_CONSUMER_TIMEOUT"); ok {
		if d, err := time.ParseDuration(v); err == nil {
			c.SlowConsumerTimeout = d
		}
	}
	if v, ok := get("MUX_METRICS"); ok {
		c.Metrics = v == "1" || strings.EqualFold(v, "true")
	}
	return c
}

// ApplyEnvDefaults fills unset fields from the environment while preserving
// explicit API/flag values.
func (c Config) ApplyEnvDefaults() Config {
	e := ConfigFromEnv()
	if !c.Enabled && e.Enabled {
		c.Enabled = true
	}
	if c.MaxChannels == 0 {
		c.MaxChannels = e.MaxChannels
	}
	if c.MaxClientChannels == 0 {
		c.MaxClientChannels = e.MaxClientChannels
	}
	if c.ClientReserve == 0 {
		c.ClientReserve = e.ClientReserve
	}
	if c.MaxTargetChannels == 0 {
		c.MaxTargetChannels = e.MaxTargetChannels
	}
	if c.TargetReserve == 0 {
		c.TargetReserve = e.TargetReserve
	}
	if c.MaxPendingBytes == 0 {
		c.MaxPendingBytes = e.MaxPendingBytes
	}
	if c.FairChunkBytes == 0 {
		c.FairChunkBytes = e.FairChunkBytes
	}
	if c.DatagramQueue == 0 {
		c.DatagramQueue = e.DatagramQueue
	}
	if c.SlowConsumerTimeout == 0 {
		c.SlowConsumerTimeout = e.SlowConsumerTimeout
	}
	if !c.Metrics && e.Metrics {
		c.Metrics = true
	}
	return c
}

// ConfigFromEnv returns Config overlaid from the environment.
func ConfigFromEnv() Config { return (Config{}).ApplyEnv() }
