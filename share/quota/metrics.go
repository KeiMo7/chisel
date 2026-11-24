package quota

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics is a lock-light, low-cardinality metrics registry.  Every label
// combination is constructed from the bounded constants in this package.
type Metrics struct {
	admitted sync.Map // labels -> *atomic.Int64
	rejected sync.Map
	active   sync.Map
	dropped  sync.Map

	backlogBytes      atomic.Int64
	backlogHighWater  atomic.Int64
	backpressureTotal atomic.Int64
	saturatedWriters  atomic.Int64
	slowConsumers     atomic.Int64
	leasesReleased    atomic.Int64
}

// Snapshot is a point-in-time copy safe to serialize or assert against.
type Snapshot struct {
	Admitted          map[string]int64 `json:"admitted,omitempty"`
	Rejected          map[string]int64 `json:"rejected,omitempty"`
	Active            map[string]int64 `json:"active,omitempty"`
	Dropped           map[string]int64 `json:"dropped,omitempty"`
	BacklogBytes      int64            `json:"backlog_bytes"`
	BacklogHighWater  int64            `json:"backlog_high_water_bytes"`
	BackpressureTotal int64            `json:"backpressure_total"`
	SaturatedWriters  int64            `json:"saturated_writers"`
	SlowConsumers     int64            `json:"slow_consumers_total"`
	LeasesReleased    int64            `json:"leases_released_total"`
}

func key(parts ...string) string { return strings.Join(parts, "|") }

func incMap(m *sync.Map, k string, delta int64) int64 {
	v, _ := m.LoadOrStore(k, &atomic.Int64{})
	return v.(*atomic.Int64).Add(delta)
}

func getMap(m *sync.Map) map[string]int64 {
	out := map[string]int64{}
	m.Range(func(k, v any) bool {
		if n := v.(*atomic.Int64).Load(); n != 0 {
			out[k.(string)] = n
		}
		return true
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// Admitted records one successful admission.
func (m *Metrics) Admitted(kind Kind, dir Direction) {
	if m != nil {
		incMap(&m.admitted, key(string(kind), string(dir)), 1)
		incMap(&m.active, key(string(kind), string(dir)), 1)
	}
}

// Released records one terminal lease release and decrements active channels.
func (m *Metrics) Released(kind Kind, dir Direction) {
	if m == nil {
		return
	}
	m.leasesReleased.Add(1)
	k := key(string(kind), string(dir))
	if v, ok := m.active.Load(k); ok {
		n := v.(*atomic.Int64).Add(-1)
		if n < 0 {
			// Accounting must never go negative.  Repair and make the anomaly
			// observable through the release counter rather than panicking.
			v.(*atomic.Int64).Store(0)
		}
	}
}

// Rejected records one rejected admission.
func (m *Metrics) Rejected(kind Kind, category Category, reason string) {
	if m != nil {
		incMap(&m.rejected, key(string(kind), string(category), reason), 1)
	}
}

// DropDatagram records a bounded datagram drop.
func (m *Metrics) DropDatagram(kind Kind, reason string) {
	if m != nil {
		incMap(&m.dropped, key(string(kind), reason), 1)
	}
}

// AddBacklog adjusts current per-channel managed backlog.  Positive additions
// update the process-wide high-water mark.
func (m *Metrics) AddBacklog(delta int64) int64 {
	if m == nil {
		return 0
	}
	n := m.backlogBytes.Add(delta)
	if delta > 0 {
		for {
			h := m.backlogHighWater.Load()
			if n <= h || m.backlogHighWater.CompareAndSwap(h, n) {
				break
			}
		}
	}
	return n
}

// Backlog returns current managed backlog bytes.
func (m *Metrics) Backlog() int64 {
	if m == nil {
		return 0
	}
	return m.backlogBytes.Load()
}

// BacklogHighWater returns the largest aggregate backlog observed.
func (m *Metrics) BacklogHighWater() int64 {
	if m == nil {
		return 0
	}
	return m.backlogHighWater.Load()
}

// BackpressureWait records one writer entering a full queue and returns a
// stop function that records saturation duration/gauge exit.
func (m *Metrics) BackpressureWait() func() {
	if m == nil {
		return func() {}
	}
	m.backpressureTotal.Add(1)
	n := m.saturatedWriters.Add(1)
	_ = n
	return func() { m.saturatedWriters.Add(-1) }
}

// SlowConsumerClosed records one slow channel closed by the watchdog.
func (m *Metrics) SlowConsumerClosed() {
	if m != nil {
		m.slowConsumers.Add(1)
	}
}

// Snapshot copies all counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Admitted:          getMap(&m.admitted),
		Rejected:          getMap(&m.rejected),
		Active:            getMap(&m.active),
		Dropped:           getMap(&m.dropped),
		BacklogBytes:      m.backlogBytes.Load(),
		BacklogHighWater:  m.backlogHighWater.Load(),
		BackpressureTotal: m.backpressureTotal.Load(),
		SaturatedWriters:  m.saturatedWriters.Load(),
		SlowConsumers:     m.slowConsumers.Load(),
		LeasesReleased:    m.leasesReleased.Load(),
	}
}

// Prometheus renders metrics in Prometheus text exposition format without
// adding a third-party dependency.
func (m *Metrics) Prometheus() string {
	s := m.Snapshot()
	var b strings.Builder
	writeVec := func(metric, help, typ string, vals map[string]int64, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", metric, help, metric, typ)
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.Split(k, "|")
			fmt.Fprintf(&b, "%s{", metric)
			for i, l := range labels {
				if i > 0 {
					b.WriteByte(',')
				}
				v := ""
				if i < len(parts) {
					v = parts[i]
				}
				fmt.Fprintf(&b, "%s=%q", l, v)
			}
			fmt.Fprintf(&b, "} %d\n", vals[k])
		}
	}
	writeVec("chisel_mux_admitted_total", "Admitted multiplexed channels.", "counter", s.Admitted, "kind", "direction")
	writeVec("chisel_mux_active", "Currently active multiplexed channels.", "gauge", s.Active, "kind", "direction")
	writeVec("chisel_mux_rejected_total", "Rejected channel admissions.", "counter", s.Rejected, "kind", "category", "reason")
	writeVec("chisel_mux_datagram_dropped_total", "Dropped datagrams.", "counter", s.Dropped, "kind", "reason")
	fmt.Fprintf(&b, "# HELP chisel_mux_backlog_bytes Current managed channel backlog.\n# TYPE chisel_mux_backlog_bytes gauge\nchisel_mux_backlog_bytes %d\n", s.BacklogBytes)
	fmt.Fprintf(&b, "# HELP chisel_mux_backlog_high_water_bytes Aggregate backlog high-water mark.\n# TYPE chisel_mux_backlog_high_water_bytes gauge\nchisel_mux_backlog_high_water_bytes %d\n", s.BacklogHighWater)
	fmt.Fprintf(&b, "# HELP chisel_mux_backpressure_total Number of writes blocked by a full channel buffer.\n# TYPE chisel_mux_backpressure_total counter\nchisel_mux_backpressure_total %d\n", s.BackpressureTotal)
	fmt.Fprintf(&b, "# HELP chisel_mux_saturated_writers Current writers waiting for buffer space.\n# TYPE chisel_mux_saturated_writers gauge\nchisel_mux_saturated_writers %d\n", s.SaturatedWriters)
	fmt.Fprintf(&b, "# HELP chisel_mux_slow_consumers_closed_total Channels closed for persistent non-reading.\n# TYPE chisel_mux_slow_consumers_closed_total counter\nchisel_mux_slow_consumers_closed_total %d\n", s.SlowConsumers)
	fmt.Fprintf(&b, "# HELP chisel_mux_leases_released_total Terminal admission releases.\n# TYPE chisel_mux_leases_released_total counter\nchisel_mux_leases_released_total %d\n", s.LeasesReleased)
	return b.String()
}
