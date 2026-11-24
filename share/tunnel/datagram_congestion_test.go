package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/quota"
	"golang.org/x/crypto/ssh"
)

type muxMetricsTunnel struct{ metrics *quota.Metrics }

func (m muxMetricsTunnel) getSSH(context.Context) ssh.Conn { return nil }
func (m muxMetricsTunnel) quotaMetrics() *quota.Metrics    { return m.metrics }

func TestDatagramCongestionDropsCountAndSharedLoopContinues(t *testing.T) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	metrics := &quota.Metrics{}
	p := &Proxy{sshTun: muxMetricsTunnel{metrics: metrics}}
	s := &socksProxy{
		proxy:        p,
		udp:          u,
		maxSize:      1500,
		maxConns:     2,
		associations: map[*socksAssociation]bool{},
		peers:        map[netip.AddrPort]*socksAssociation{},
		pending:      map[netip.Addr]*socksAssociation{},
	}
	ip := netip.MustParseAddr("127.0.0.1")
	a := &socksAssociation{ip: ip, packets: make(chan []byte, 1)}
	a.packets <- []byte("occupied")
	if !s.register(a, 0) {
		t.Fatal("register pending association failed")
	}

	readDone := make(chan error, 1)
	go func() { readDone <- s.readUDP() }()

	sender, err := net.DialUDP("udp4", nil, u.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	packet := append([]byte{0, 0, 0}, socksIPPort(net.IPv4(127, 0, 0, 1), 53)...)
	if _, err := sender.Write(packet); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if metrics.Snapshot().Dropped["datagram|association_queue_full"] > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := metrics.Snapshot().Dropped["datagram|association_queue_full"]; got != 1 {
		t.Fatalf("drop count=%d, want 1", got)
	}

	// Drain the standing packet; the same shared receive loop must still be
	// reading and deliver the next datagram instead of blocking on congestion.
	select {
	case old := <-a.packets:
		if string(old) != "occupied" {
			t.Fatalf("unexpected queued packet %q", old)
		}
	case <-time.After(time.Second):
		t.Fatal("standing packet was not readable")
	}
	if _, err := sender.Write(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-a.packets:
		if len(got) == 0 {
			t.Fatal("shared receive loop delivered empty datagram")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shared receive loop did not continue after drop")
	}

	u.Close()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("readUDP did not stop after socket close")
	}
}
