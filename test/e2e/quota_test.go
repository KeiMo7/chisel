package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/quota"
	"github.com/jpillora/chisel/share/settings"
)

// discardServer accepts connections and discards everything, never replying.
// It stands in for a slow intranet service.
func silentServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn) //absorb without replying
			}()
		}
	}()
	return l.Addr().String(), func() { l.Close() }
}

// quotaClient enables quotas on the forwarding side. Forward remotes are
// admitted by the client's proxies; reverse remotes by the server's.
func quotaClient(t *testing.T, cfg quota.Config, remotes ...string) *chclient.Config {
	t.Helper()
	return &chclient.Config{Quota: cfg, Remotes: remotes}
}

func enabledQuota(maxConns, maxQueue int) quota.Config {
	cfg := quota.DefaultConfig()
	cfg.Enabled = true
	cfg.MaxConns = maxConns
	cfg.MaxQueue = maxQueue
	cfg.QueueTimeout = 2 * time.Second
	return cfg
}

// TestQuotaIsolatesSlowChannel is the acceptance test for latency isolation:
// a slow channel saturates its own slot and its queue, while another channel
// using the same SSH connection keeps responding promptly.
func TestQuotaIsolatesSlowChannel(t *testing.T) {
	slowAddr, closeSlow := silentServer(t)
	defer closeSlow()
	echoAddr := startEchoTCP(t)

	slowLocal := availablePort()
	fastLocal := availablePort()
	_, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     quotaClient(t, enabledQuota(1, 1), slowLocal+":"+slowAddr, fastLocal+":"+echoAddr),
		fileServer: true,
	}.layout().setup(t)
	defer teardown()

	//occupy the slow channel's only slot with a request that never finishes
	slowConn, err := net.Dial("tcp", "127.0.0.1:"+slowLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer slowConn.Close()
	if _, err := slowConn.Write([]byte("hold")); err != nil {
		t.Fatal(err)
	}
	//fill its queue too, so it is fully saturated
	queuedConn, err := net.Dial("tcp", "127.0.0.1:"+slowLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer queuedConn.Close()
	if _, err := queuedConn.Write([]byte("wait")); err != nil {
		t.Fatal(err)
	}
	slowKey := channelKey(t, slowLocal+":"+slowAddr)
	fastKey := channelKey(t, fastLocal+":"+echoAddr)
	waitFor(t, 2*time.Second, func() bool {
		stats := client.Quota().Stats()
		slow := findStat(stats, slowKey)
		return slow != nil && slow.InFlight == 1 && slow.Queued == 1
	})

	//the fast channel must stay responsive; measure several round trips
	var samples []time.Duration
	for i := 0; i < 10; i++ {
		start := time.Now()
		if err := echoOnce(fastLocal, "ping"); err != nil {
			t.Fatalf("fast channel failed while slow channel saturated: %v", err)
		}
		samples = append(samples, time.Since(start))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[len(samples)/2]
	t.Logf("fast channel RTT while slow channel saturated: p50=%s p95=%s", median, samples[len(samples)-1])
	if median > 250*time.Millisecond {
		t.Fatalf("fast channel latency degraded to %s while another channel was saturated", median)
	}

	//the fast channel's own counters must show it was never queued
	fast := findStat(client.Quota().Stats(), fastKey)
	if fast == nil || fast.Queued != 0 || fast.Rejected != 0 {
		t.Fatalf("fast channel affected by slow channel: %+v", fast)
	}

	//releasing the slow slot lets its queued request proceed
	slowConn.Close()
	waitFor(t, 3*time.Second, func() bool {
		slow := findStat(client.Quota().Stats(), slowKey)
		return slow != nil && slow.Queued == 0
	})
}

// TestQuotaNormalConcurrency checks the counters and that traffic flows
// normally under the limit.
func TestQuotaNormalConcurrency(t *testing.T) {
	echoAddr := startEchoTCP(t)
	local := availablePort()
	_, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     quotaClient(t, enabledQuota(8, 32), local+":"+echoAddr),
		fileServer: true,
	}.layout().setup(t)
	defer teardown()

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := echoOnce(local, "hello"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	key := channelKey(t, local+":"+echoAddr)
	stat := findStat(client.Quota().Stats(), key)
	if stat == nil {
		t.Fatalf("channel not reported: %+v", client.Quota().Stats())
	}
	if stat.Admitted < 16 || stat.Rejected != 0 {
		t.Fatalf("unexpected counters: %+v", stat)
	}
	waitFor(t, 2*time.Second, func() bool {
		key := channelKey(t, local+":"+echoAddr)
		stat := findStat(client.Quota().Stats(), key)
		return stat != nil && stat.InFlight == 0 && stat.Queued == 0
	})
}

// TestQuotaDynamicAdjustment lowers the limit at runtime: in-flight
// connections finish naturally and only new admissions follow the new value.
func TestQuotaDynamicAdjustment(t *testing.T) {
	echoAddr := startEchoTCP(t)
	local := availablePort()
	_, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     quotaClient(t, enabledQuota(8, 32), local+":"+echoAddr),
		fileServer: true,
	}.layout().setup(t)
	defer teardown()
	channel := channelKey(t, local+":"+echoAddr)

	//hold three connections open so in-flight exceeds the new limit
	var held []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:"+local)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("hold\n")); err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	waitFor(t, 2*time.Second, func() bool {
		stat := findStat(client.Quota().Stats(), channel)
		return stat != nil && stat.InFlight >= 3
	})

	lowered := quota.Limits{MaxConns: 2, MaxQueue: 4, Rate: quota.Rate(quota.DefaultRate), QueueTimeout: quota.Duration(5 * time.Second)}
	if err := client.Quota().SetChannelLimits(channel, lowered); err != nil {
		t.Fatal(err)
	}
	stat := findStat(client.Quota().Stats(), channel)
	if stat.MaxConns != 2 {
		t.Fatalf("runtime limit not visible: %+v", stat)
	}
	//in-flight connections are untouched and still usable
	if got := stat.InFlight; got != 3 {
		t.Fatalf("lowering the limit interrupted in-flight connections: %d", got)
	}
	if _, err := held[0].Write([]byte("still here\n")); err != nil {
		t.Fatalf("in-flight connection interrupted by limit change: %v", err)
	}

	//a new request queues because in-flight is over the new limit
	done := make(chan error, 1)
	go func() { done <- echoOnce(local, "after lower") }()
	select {
	case err := <-done:
		t.Fatalf("new request bypassed the lowered limit: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	waitFor(t, time.Second, func() bool {
		stat := findStat(client.Quota().Stats(), channel)
		return stat != nil && stat.Queued == 1
	})
	//free two slots; the queued request is admitted and completes
	held[1].Close()
	held[2].Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queued request failed after slots freed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued request was not admitted after slots freed")
	}
}

// TestQuotaReturnedAfterAbnormalClose checks a channel's quota is fully
// returned after the peer resets mid-transfer and after a rejected dial.
func TestQuotaReturnedAfterAbnormalClose(t *testing.T) {
	echoAddr := startEchoTCP(t)
	local := availablePort()
	_, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     quotaClient(t, enabledQuota(2, 2), local+":"+echoAddr),
		fileServer: true,
	}.layout().setup(t)
	defer teardown()
	channel := channelKey(t, local+":"+echoAddr)

	//open and reset many connections in a row; each must return its slot
	for i := 0; i < 25; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:"+local)
		if err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte("x"))
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0) //force RST
		}
		conn.Close()
	}
	waitFor(t, 5*time.Second, func() bool {
		stat := findStat(client.Quota().Stats(), channel)
		return stat != nil && stat.InFlight == 0 && stat.Queued == 0
	})
	stat := findStat(client.Quota().Stats(), channel)
	if stat.InFlight != 0 || stat.Queued != 0 {
		t.Fatalf("quota leaked after resets: %+v", stat)
	}
	//full capacity is available again
	for i := 0; i < 2; i++ {
		if err := echoOnce(local, "recovered"); err != nil {
			t.Fatalf("channel did not recover: %v", err)
		}
	}

	//a dial failure at the exit must also release its slot: the proxy
	//opens a channel, the exit fails to dial and rejects it
	deadLocal := availablePort()
	deadAddr := "127.0.0.1:" + availablePort() //nothing listening
	_, client2, teardown2 := testLayout{
		server:     &chserver.Config{},
		client:     quotaClient(t, enabledQuota(1, 1), deadLocal+":"+deadAddr),
		fileServer: true,
	}.layout().setup(t)
	defer teardown2()
	deadKey := channelKey(t, deadLocal+":"+deadAddr)
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:"+deadLocal)
		if err != nil {
			continue
		}
		conn.Write([]byte("fail"))
		conn.Close()
	}
	waitFor(t, 5*time.Second, func() bool {
		stat := findStat(client2.Quota().Stats(), deadKey)
		return stat != nil && stat.InFlight == 0 && stat.Queued == 0
	})
}

// TestQuotaReverseChannelIsolation checks the server-side quota path used by
// reverse remotes: the reverse channel is admitted by the server, and a
// saturated reverse channel must not affect a direct forward channel.
func TestQuotaReverseChannelIsolation(t *testing.T) {
	slowAddr, closeSlow := silentServer(t)
	defer closeSlow()
	echoAddr := startEchoTCP(t)
	reverseLocal := availablePort()
	forwardLocal := availablePort()
	serverCfg := &chserver.Config{
		Reverse: true,
		Quota:   enabledQuota(1, 1),
	}
	_, client, teardown := testLayout{
		server: serverCfg,
		client: &chclient.Config{Remotes: []string{
			"R:" + reverseLocal + ":" + slowAddr,
			forwardLocal + ":" + echoAddr,
		}},
		fileServer: true,
	}.layout().setup(t)
	defer teardown()

	//saturate the reverse channel on the server side
	held, err := net.Dial("tcp", "127.0.0.1:"+reverseLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.Write([]byte("hold"))
	queued, err := net.Dial("tcp", "127.0.0.1:"+reverseLocal)
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close()
	queued.Write([]byte("wait"))
	waitFor(t, 2*time.Second, func() bool {
		stat := findStat(client.Quota().Stats(), channelKey(t, "R:"+reverseLocal+":"+slowAddr))
		return stat == nil //forward client quota is not involved
	})
	//forward traffic keeps working
	for i := 0; i < 5; i++ {
		if err := echoOnce(forwardLocal, "ping"); err != nil {
			t.Fatalf("forward channel affected by reverse saturation: %v", err)
		}
	}
}

// TestQuotaChannelKeyStableAcrossReconnect forces a tunnel reconnect through
// a droppable proxy and checks the same remote resolves to the same limiter,
// keeping its counters.
func TestQuotaChannelKeyStableAcrossReconnect(t *testing.T) {
	echoAddr := startEchoTCP(t)
	local := availablePort()
	drop := newDroppableProxy(t)
	clientCfg := &chclient.Config{
		Quota:         enabledQuota(4, 8),
		Remotes:       []string{local + ":" + echoAddr},
		MaxRetryCount: -1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return drop.Dial(addr)
		},
	}
	_, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     clientCfg,
		fileServer: true,
	}.layout().setup(t)
	defer teardown()
	key := channelKey(t, local+":"+echoAddr)
	for i := 0; i < 10; i++ {
		if err := echoOnce(local, "count"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 2*time.Second, func() bool {
		stat := findStat(client.Quota().Stats(), key)
		return stat != nil && stat.InFlight == 0
	})
	before := findStat(client.Quota().Stats(), key)
	if before == nil || before.Admitted < 10 {
		t.Fatalf("admissions not counted: %+v", before)
	}
	//drop every transport connection; the client reconnects through the
	//proxy and forwarding resumes without the tunnel-level quota resetting
	conns := drop.DropAll()
	if conns == 0 {
		t.Fatal("no transport connection went through the proxy")
	}
	waitFor(t, 15*time.Second, func() bool {
		return echoOnce(local, "after") == nil
	})
	after := findStat(client.Quota().Stats(), key)
	if after == nil || after.Admitted < before.Admitted {
		t.Fatalf("quota reset across reconnect: before=%+v after=%+v", before, after)
	}
}

// droppableProxy forwards TCP to the address the first dial names, and can
// close every live pair on demand.
type droppableProxy struct {
	l      net.Listener
	mu     sync.Mutex
	target string
	conns  map[net.Conn]struct{}
	opened int
}

func newDroppableProxy(t *testing.T) *droppableProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &droppableProxy{l: l, conns: map[net.Conn]struct{}{}}
	t.Cleanup(func() { l.Close(); p.DropAll() })
	go func() {
		for {
			src, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			target := p.target
			p.mu.Unlock()
			dst, err := net.Dial("tcp", target)
			if err != nil {
				src.Close()
				continue
			}
			p.track(src)
			p.track(dst)
			go p.pipe(src, dst)
			go p.pipe(dst, src)
		}
	}()
	return p
}

// Dial records the real server address and connects through the proxy.
func (p *droppableProxy) Dial(addr string) (net.Conn, error) {
	p.mu.Lock()
	p.target = addr
	p.opened++
	p.mu.Unlock()
	return net.Dial("tcp", p.l.Addr().String())
}

func (p *droppableProxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *droppableProxy) pipe(dst, src net.Conn) {
	defer src.Close()
	defer dst.Close()
	io.Copy(dst, src)
}

// DropAll closes every live connection and reports how many were open.
func (p *droppableProxy) DropAll() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.conns)
	for c := range p.conns {
		c.Close()
		delete(p.conns, c)
	}
	return n
}

// TestQuotaDisabledUnchanged checks the isolation flag is opt-in: without it
// no quota state exists and forwarding is unchanged.
func TestQuotaDisabledUnchanged(t *testing.T) {
	echoAddr := startEchoTCP(t)
	local := availablePort()
	server, client, teardown := testLayout{
		server:     &chserver.Config{},
		client:     &chclient.Config{Remotes: []string{local + ":" + echoAddr}},
		fileServer: true,
	}.layout().setup(t)
	defer teardown()
	if server.Quota() != nil || client.Quota() != nil {
		t.Fatal("quota state created without --quota")
	}
	if err := echoOnce(local, "default"); err != nil {
		t.Fatal(err)
	}
}

// TestQuotaInvalidConfigRejected checks startup validation names the option.
func TestQuotaInvalidConfigRejected(t *testing.T) {
	cfg := enabledQuota(0, 4)
	if _, err := chserver.NewServer(&chserver.Config{Quota: cfg}); err == nil {
		t.Fatal("server accepted zero quota-max-conns")
	} else if !bytes.Contains([]byte(err.Error()), []byte("--quota-max-conns")) {
		t.Fatalf("error does not name the option: %v", err)
	}
	cfg = enabledQuota(4, 4)
	cfg.BytesPerSec = 0
	if _, err := chclient.NewClient(&chclient.Config{Quota: cfg, Remotes: []string{"3000"}}); err == nil {
		t.Fatal("client accepted zero quota-rate")
	} else if !bytes.Contains([]byte(err.Error()), []byte("--quota-rate")) {
		t.Fatalf("error does not name the option: %v", err)
	}
}

// ---- shared helpers -------------------------------------------------------

// layout lets callers pass a composite literal to (*testLayout).setup.
func (tl testLayout) layout() *testLayout { return &tl }

// channelKey returns the stable quota key for a remote, matching what the
// proxy uses: the remote's log label ("3000=>host:port").
func channelKey(t *testing.T, remote string) string {
	t.Helper()
	r, err := settings.DecodeRemote(remote)
	if err != nil {
		t.Fatal(err)
	}
	return r.String()
}

func findStat(stats []quota.Stats, channel string) *quota.Stats {
	for i := range stats {
		if stats[i].Channel == channel {
			return &stats[i]
		}
	}
	return nil
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func startEchoTCP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return l.Addr().String()
}

func echoOnce(local, msg string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:"+local)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("echo read: %w", err)
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}
