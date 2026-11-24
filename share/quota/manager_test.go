package quota

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func testManager(c Config) *Manager {
	c.Enabled = true
	return NewManager(c)
}

func TestZeroConfigIsDisabledAndDoesNotImposeCaps(t *testing.T) {
	var c Config
	if c.Active() {
		t.Fatal("zero quota config must remain disabled")
	}
	m := NewManager(c)
	if !m.Disabled() {
		t.Fatal("manager from zero config must be disabled")
	}
	l, err := m.Local().Admit(context.Background(), KindForward, DirectionOut, "x")
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	if m.Active() != 0 {
		t.Fatal("noop lease changed accounting")
	}

	metricsOnly := NewManager(Config{Metrics: true})
	if !metricsOnly.Config.Metrics || !metricsOnly.Disabled() {
		t.Fatal("metrics-only mode must preserve /metrics while staying disabled")
	}
}

func TestAdmissionDistinguishesClientGlobalAndTarget(t *testing.T) {
	m := testManager(Config{
		MaxChannels:       3,
		MaxClientChannels: 2,
		ClientReserve:     1,
		MaxTargetChannels: 1,
		TargetReserve:     1,
	})
	ctx := context.Background()
	a := m.Client("busy")

	l1, err := a.Admit(ctx, KindForward, DirectionIn, "target-a")
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()
	// Same target's hard limit is distinguishable before the client cap.
	if _, err := a.Admit(ctx, KindForward, DirectionIn, "target-a"); !errors.Is(err, ErrTargetQuota) {
		t.Fatalf("expected target quota, got %v", err)
	}
	l2, err := a.Admit(ctx, KindForward, DirectionIn, "target-b")
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Release()
	_, err = a.Admit(ctx, KindForward, DirectionIn, "target-c")
	if !errors.Is(err, ErrClientQuota) {
		t.Fatalf("expected client quota, got %v", err)
	}

	// A second principal can use the protected global reserve even while the
	// first client is at its configured maximum.
	b := m.Client("newcomer")
	l3, err := b.Admit(ctx, KindForward, DirectionIn, "target-a")
	if err != nil {
		t.Fatalf("newcomer reserve denied: %v", err)
	}
	defer l3.Release()
	if m.Active() != 3 {
		t.Fatalf("active=%d, want 3", m.Active())
	}
	_, err = m.Client("third").Admit(ctx, KindForward, DirectionIn, "x")
	if !errors.Is(err, ErrGlobalQuota) {
		t.Fatalf("expected global quota, got %v", err)
	}
}

func TestAdmissionReleaseImmediatelyRecoversAndOnceOnly(t *testing.T) {
	m := testManager(Config{MaxClientChannels: 1, ClientReserve: 1, MaxChannels: 4})
	a := m.Client("cycle")
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		l, err := a.Admit(ctx, KindForward, DirectionOut, "t")
		if err != nil {
			t.Fatalf("round %d admit: %v", i, err)
		}
		if _, err := a.Admit(ctx, KindForward, DirectionOut, "t2"); !errors.Is(err, ErrClientQuota) {
			t.Fatalf("round %d expected client quota, got %v", i, err)
		}
		l.Release()
		l.Release() // must be idempotent
		if got := m.Active(); got != 0 {
			t.Fatalf("round %d active=%d after release", i, got)
		}
		if got := m.ClientActive("cycle"); got != 0 {
			t.Fatalf("round %d client active=%d after release", i, got)
		}
	}
	s := m.Snapshot()
	// Twenty successful admissions; the duplicate Release calls add none.
	if s.LeasesReleased != 20 {
		t.Fatalf("released=%d, want 20", s.LeasesReleased)
	}
}

func TestAdmissionTwentyRoundsConcurrentAbnormalLifecycle(t *testing.T) {
	m := testManager(Config{MaxChannels: 64, MaxClientChannels: 32, ClientReserve: 1})
	ctx := context.Background()
	var wg sync.WaitGroup
	for round := 0; round < 20; round++ {
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				l, err := m.Local().Admit(ctx, KindForward, DirectionIn, "target")
				if err != nil {
					t.Errorf("admit: %v", err)
					return
				}
				// Simulate all five terminal paths converging on Release.
				l.Release()
			}()
		}
		wg.Wait()
		if m.Active() != 0 || m.Clients() != 0 {
			t.Fatalf("round %d leaked active=%d clients=%d", round, m.Active(), m.Clients())
		}
	}
}

func TestTargetFairnessLeavesCapacityForOtherTargets(t *testing.T) {
	m := testManager(Config{MaxClientChannels: 2, TargetReserve: 1})
	a := m.Local()
	ctx := context.Background()
	busy, err := a.Admit(ctx, KindForward, DirectionIn, "busy")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Release()
	// With client max two and target reserve one, busy may not consume the
	// final slot; another target must still establish.
	if _, err := a.Admit(ctx, KindForward, DirectionIn, "busy"); !errors.Is(err, ErrTargetQuota) {
		t.Fatalf("expected busy target fair-share rejection, got %v", err)
	}
	other, err := a.Admit(ctx, KindForward, DirectionIn, "other")
	if err != nil {
		t.Fatalf("other target denied: %v", err)
	}
	defer other.Release()
}
