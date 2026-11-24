package e2e_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/quota"
	"golang.org/x/crypto/ssh"
)

func muxWaitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !fn() {
		t.Fatal("condition was not met before timeout")
	}
}

func startMuxEcho(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return l.Addr().String()
}

func startMuxDiscard(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return l.Addr().String()
}

// startMuxSilent accepts connections but never reads or writes. It models a
// stalled consumer whose receive window eventually closes.
func startMuxSilent(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			// Intentionally do not Read: TCP/SSH flow control backs up.
		}
	}()
	return l.Addr().String()
}

func startMuxServer(t *testing.T, cfg *chserver.Config) (*chserver.Server, string) {
	t.Helper()
	if cfg == nil {
		cfg = &chserver.Config{}
	}
	if !cfg.Quota.Enabled {
		cfg.Quota.Enabled = true
	}
	s, err := chserver.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, "127.0.0.1:" + port
}

func openMuxChannel(t *testing.T, sc ssh.Conn, target string) (ssh.Channel, error) {
	t.Helper()
	ch, _, err := sc.OpenChannel("chisel", []byte(target))
	return ch, err
}

func requireSSHReason(t *testing.T, err error, reason ssh.RejectionReason, message string) {
	t.Helper()
	var oe *ssh.OpenChannelError
	if !errors.As(err, &oe) {
		t.Fatalf("expected ssh.OpenChannelError, got %T: %v", err, err)
	}
	if oe.Reason != reason {
		t.Fatalf("reason=%s, want %s (message=%q)", oe.Reason, reason, oe.Message)
	}
	if message != "" && oe.Message != message {
		t.Fatalf("message=%q, want %q", oe.Message, message)
	}
}

func TestMuxAdmissionCategoriesOverSSH(t *testing.T) {
	echo := startMuxEcho(t)
	s, addr := startMuxServer(t, &chserver.Config{
		Quota: quota.Config{
			MaxChannels:       4,
			MaxClientChannels: 2,
			ClientReserve:     1,
		},
	})
	sc, _, _ := dialChiselSSH(t, addr, "", "")
	defer sc.Close()
	sendConfig(t, sc, nil)

	var held []ssh.Channel
	for i := 0; i < 2; i++ {
		ch, err := openMuxChannel(t, sc, echo)
		if err != nil {
			t.Fatalf("admitted channel %d: %v", i, err)
		}
		held = append(held, ch)
	}
	muxWaitFor(t, time.Second, func() bool { return s.Quota().Active() == 2 })

	_, err := openMuxChannel(t, sc, echo)
	requireSSHReason(t, err, ssh.ResourceShortage, "quota: client limit")
	if quota.CategoryOf(categorizeForTest(err)) != quota.CategoryClient {
		t.Fatalf("client error category not distinguishable: %v", err)
	}

	for _, ch := range held {
		ch.Close()
	}
	muxWaitFor(t, 2*time.Second, func() bool { return s.Quota().Active() == 0 })

	ch, err := openMuxChannel(t, sc, echo)
	if err != nil {
		t.Fatalf("capacity did not recover: %v", err)
	}
	ch.Close()
}

func categorizeForTest(err error) error {
	// The production mapper is package-private; SSH message is the stable wire
	// category. Re-wrap through the same sentinel for assertion convenience.
	var oe *ssh.OpenChannelError
	if errors.As(err, &oe) {
		switch oe.Message {
		case "quota: client limit":
			return quota.ErrClientQuota
		case "quota: global capacity":
			return quota.ErrGlobalQuota
		case "access denied":
			return quota.ErrAccessDenied
		}
	}
	return err
}

func TestMuxGlobalReserveForLaterClient(t *testing.T) {
	echo := startMuxEcho(t)
	s, addr := startMuxServer(t, &chserver.Config{
		Quota: quota.Config{MaxChannels: 2, MaxClientChannels: 4, ClientReserve: 1},
	})

	a, _, _ := dialChiselSSH(t, addr, "", "")
	defer a.Close()
	sendConfig(t, a, nil)
	chA, err := openMuxChannel(t, a, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer chA.Close()
	muxWaitFor(t, time.Second, func() bool { return s.Quota().Active() == 1 })

	// The busy client cannot consume the protected final slot.
	if _, err := openMuxChannel(t, a, echo); err == nil {
		t.Fatal("busy client consumed the newcomer reserve")
	} else {
		requireSSHReason(t, err, ssh.ResourceShortage, "quota: client limit")
	}

	b, _, _ := dialChiselSSH(t, addr, "", "")
	defer b.Close()
	sendConfig(t, b, nil)
	chB, err := openMuxChannel(t, b, echo)
	if err != nil {
		t.Fatalf("later client did not receive reserved slot: %v", err)
	}
	defer chB.Close()
	muxWaitFor(t, time.Second, func() bool { return s.Quota().Active() == 2 })

	c, _, _ := dialChiselSSH(t, addr, "", "")
	defer c.Close()
	sendConfig(t, c, nil)
	_, err = openMuxChannel(t, c, echo)
	requireSSHReason(t, err, ssh.ResourceShortage, "quota: global capacity")
}

func TestMuxACLRemainsDistinguishable(t *testing.T) {
	s, err := chserver.NewServer(&chserver.Config{
		KeySeed: "mux-acl",
		Quota:   quota.Config{Enabled: true, MaxChannels: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("u", "p", `^127\.0\.0\.1:1$`); err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sc, _, _ := dialChiselSSH(t, "127.0.0.1:"+port, "u", "p")
	defer sc.Close()
	sendConfig(t, sc, nil)
	_, _, err = sc.OpenChannel("chisel", []byte("127.0.0.1:9"))
	requireSSHReason(t, err, ssh.Prohibited, "access denied")
}

func TestMuxMetricsEndpointHasBoundedNames(t *testing.T) {
	s, addr := startMuxServer(t, &chserver.Config{
		Quota: quota.Config{Enabled: true, Metrics: true, MaxChannels: 1},
	})
	echo := startMuxEcho(t)
	sc, _, _ := dialChiselSSH(t, addr, "", "")
	defer sc.Close()
	sendConfig(t, sc, nil)
	ch, err := openMuxChannel(t, sc, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	muxWaitFor(t, time.Second, func() bool { return s.Quota().Active() == 1 })

	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{
		"chisel_mux_admitted_total",
		"chisel_mux_active",
		"chisel_mux_rejected_total",
		"chisel_mux_backlog_bytes",
		"chisel_mux_datagram_dropped_total",
		"chisel_mux_saturated_writers",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics output missing %s:\n%s", want, text)
		}
	}
	if strings.Contains(text, "127.0.0.1:") || strings.Contains(text, "session-") {
		t.Fatalf("metrics output contains unbounded address/session labels:\n%s", text)
	}
}

func TestMuxTargetFairShareAllowsOtherTargets(t *testing.T) {
	echo := startMuxEcho(t)
	otherEcho := startMuxEcho(t)
	s, addr := startMuxServer(t, &chserver.Config{
		Quota: quota.Config{
			MaxClientChannels: 2,
			MaxTargetChannels: 1,
			TargetReserve:     1,
		},
	})
	sc, _, _ := dialChiselSSH(t, addr, "", "")
	defer sc.Close()
	sendConfig(t, sc, nil)

	busy, err := openMuxChannel(t, sc, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := openMuxChannel(t, sc, echo); err == nil {
		t.Fatal("second channel to saturated target was not rejected")
	} else {
		requireSSHReason(t, err, ssh.ResourceShortage, "quota: target limit")
	}
	other, err := openMuxChannel(t, sc, otherEcho)
	if err != nil {
		t.Fatalf("other target denied despite reserve: %v", err)
	}
	defer other.Close()
	muxWaitFor(t, time.Second, func() bool { return s.Quota().Active() == 2 })
}

func TestMuxTwentyFullAbnormalRoundsDoNotLeak(t *testing.T) {
	echo := startMuxEcho(t)
	const n = 4
	s, addr := startMuxServer(t, &chserver.Config{
		Quota: quota.Config{MaxChannels: 100, MaxClientChannels: n, ClientReserve: 1},
	})
	for round := 0; round < 20; round++ {
		sc, _, _ := dialChiselSSH(t, addr, "", "")
		sendConfig(t, sc, nil)
		chs := make([]ssh.Channel, 0, n)
		for i := 0; i < n; i++ {
			ch, err := openMuxChannel(t, sc, echo)
			if err != nil {
				t.Fatalf("round %d channel %d: %v", round, i, err)
			}
			chs = append(chs, ch)
		}
		_, err := openMuxChannel(t, sc, echo)
		requireSSHReason(t, err, ssh.ResourceShortage, "quota: client limit")
		// Abnormal peer disappearance rather than per-channel graceful EOF.
		_ = sc.Close()
		for _, ch := range chs {
			_ = ch.Close()
		}
		muxWaitFor(t, 3*time.Second, func() bool { return s.Quota().Active() == 0 })
	}
}
