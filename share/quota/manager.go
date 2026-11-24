package quota

import (
	"context"
	"sync"
)

// Manager is the process-wide authority for global and per-client channel
// admission.  A server owns one Manager; a client owns one single-principal
// Manager for its shared SSH transport.
type Manager struct {
	Config  Config
	Metrics *Metrics

	mu      sync.Mutex
	total   int
	clients map[string]*clientState
}

type clientState struct {
	active  int
	targets map[string]int
}

// Authority binds admission to one client/principal.
type Authority struct {
	manager *Manager
	client  string
}

// Lease is one successful atomic admission.  It is safe and correct to call
// Release any number of times; only the first call changes accounting.
type Lease struct {
	manager   *Manager
	authority *Authority
	client    string
	target    string
	kind      Kind
	direction Direction
	once      sync.Once
}

// NewManager creates an admission domain.  A zero Config is unlimited.
func NewManager(cfg Config) *Manager {
	cfg = cfg.ApplyEnvDefaults().WithDefaults()
	return &Manager{
		Config:  cfg,
		Metrics: &Metrics{},
		clients: map[string]*clientState{},
	}
}

// Disabled reports whether no protection was configured.
func (m *Manager) Disabled() bool { return m == nil || !m.Config.Active() }

// Client returns an authority for a bounded internal client key.  The key is
// never used as a metric label or returned in an error.
func (m *Manager) Client(key string) *Authority {
	if key == "" {
		key = "session"
	}
	return &Authority{manager: m, client: key}
}

// Local is the single-principal authority used by client processes.
func (m *Manager) Local() *Authority { return m.Client("local") }

// Manager returns the owning manager.
func (a *Authority) Manager() *Manager {
	if a == nil {
		return nil
	}
	return a.manager
}

// Metrics returns the manager's metrics registry.
func (a *Authority) Metrics() *Metrics {
	if a == nil || a.manager == nil {
		return nil
	}
	return a.manager.Metrics
}

func (m *Manager) limits() (global, client, clientReserve, target, targetReserve int) {
	c := m.Config
	global = c.MaxChannels
	client = c.MaxClientChannels
	clientReserve = c.ClientReserve
	target = c.MaxTargetChannels
	targetReserve = c.TargetReserve
	if clientReserve == 0 && (global > 0 || client > 0) {
		clientReserve = 1
	}
	if targetReserve == 0 && target > 0 {
		targetReserve = 1
	}
	if client > 0 && clientReserve > client {
		clientReserve = client
	}
	if global > 0 && clientReserve > global {
		clientReserve = global
	}
	if target > 0 && targetReserve > target {
		targetReserve = target
	}
	if client > 0 && targetReserve > client {
		targetReserve = client
	}
	return
}

// Admit atomically checks every applicable quota.  Rejections are counted and
// return a category *Error; callers can distinguish client, global, target
// and ACL failures with errors.Is/CategoryOf.
func (a *Authority) Admit(ctx context.Context, kind Kind, direction Direction, target string) (*Lease, error) {
	if a == nil || a.manager == nil || !a.manager.Config.Active() {
		return &Lease{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := a.manager
	globalMax, clientMax, clientReserve, targetMax, targetReserve := m.limits()

	m.mu.Lock()
	if globalMax > 0 && m.total >= globalMax {
		m.mu.Unlock()
		m.Metrics.Rejected(kind, CategoryGlobal, "global_limit")
		return nil, rejectionError(CategoryGlobal, "global_limit")
	}
	st := m.clients[a.client]
	if st == nil {
		st = &clientState{targets: map[string]int{}}
		m.clients[a.client] = st
	}
	if clientMax > 0 && st.active >= clientMax {
		m.mu.Unlock()
		m.Metrics.Rejected(kind, CategoryClient, "client_limit")
		return nil, rejectionError(CategoryClient, "client_limit")
	}
	targetActive := 0
	if target != "" {
		targetActive = st.targets[target]
	}
	if targetMax > 0 && targetActive >= targetMax {
		m.mu.Unlock()
		m.Metrics.Rejected(kind, CategoryTarget, "target_limit")
		return nil, rejectionError(CategoryTarget, "target_limit")
	}
	freeGlobal := 0
	if globalMax > 0 {
		freeGlobal = globalMax - m.total
	}
	// Protect the last clientReserve global slots for clients still below
	// their guaranteed minimum.  This prevents a busy client from filling the
	// entire shared domain and leaving a new client with no slot.
	if clientReserve > 0 && st.active >= clientReserve && globalMax > 0 && freeGlobal <= clientReserve {
		m.mu.Unlock()
		m.Metrics.Rejected(kind, CategoryClient, "client_fair_share")
		return nil, rejectionError(CategoryClient, "client_fair_share")
	}
	// Keep targetReserve slots of this client's hard capacity available for
	// other targets which are below their own guaranteed share.
	if targetReserve > 0 && target != "" && targetActive >= targetReserve && clientMax > 0 {
		clientFree := clientMax - st.active
		if clientFree <= targetReserve {
			m.mu.Unlock()
			m.Metrics.Rejected(kind, CategoryTarget, "target_fair_share")
			return nil, rejectionError(CategoryTarget, "target_fair_share")
		}
	}
	// Atomic commit.
	m.total++
	st.active++
	if target != "" {
		st.targets[target]++
	}
	m.mu.Unlock()

	m.Metrics.Admitted(kind, direction)
	return &Lease{
		manager:   m,
		authority: a,
		client:    a.client,
		target:    target,
		kind:      kind,
		direction: direction,
	}, nil
}

// Release releases the admission exactly once.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(l.release)
}

func (l *Lease) release() {
	if l.manager == nil {
		return
	}
	m := l.manager
	m.mu.Lock()
	m.total--
	if m.total < 0 {
		m.total = 0
	}
	if st := m.clients[l.client]; st != nil {
		st.active--
		if st.active < 0 {
			st.active = 0
		}
		if l.target != "" {
			st.targets[l.target]--
			if st.targets[l.target] <= 0 {
				delete(st.targets, l.target)
			}
		}
		if st.active == 0 {
			delete(m.clients, l.client)
		}
	}
	m.mu.Unlock()
	m.Metrics.Released(l.kind, l.direction)
}

// Active returns process-wide active channel count.
func (m *Manager) Active() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.total
}

// Clients returns the number of currently active client states.
func (m *Manager) Clients() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.clients)
}

// ClientActive returns one client's active count.  It is intended for tests
// and local admin APIs; callers must not expose the key as a metric label.
func (m *Manager) ClientActive(key string) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if st := m.clients[key]; st != nil {
		return st.active
	}
	return 0
}

// ManagerSnapshot includes aggregate quota state and metrics.
type ManagerSnapshot struct {
	Snapshot
	TotalActive int `json:"total_active"`
	Clients     int `json:"clients"`
}

// Snapshot returns metrics plus instantaneous manager counts.
func (m *Manager) Snapshot() ManagerSnapshot {
	if m == nil {
		return ManagerSnapshot{}
	}
	m.mu.Lock()
	total, clients := m.total, len(m.clients)
	m.mu.Unlock()
	return ManagerSnapshot{Snapshot: m.Metrics.Snapshot(), TotalActive: total, Clients: clients}
}
