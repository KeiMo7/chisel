package e2e_test

import (
	"io"
	"net"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/quota"
)

func muxEchoOnce(addr string, size int) (time.Duration, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	buf := make([]byte, size)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := c.Write(payload); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(c, buf); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func TestMuxBackpressureSlowConsumerReclaimsAndOtherChannelWorks(t *testing.T) {
	slow := startMuxSilent(t)
	echo := startMuxEcho(t)
	slowLocal := availablePort()
	fastLocal := availablePort()
	tl := testLayout{
		server: &chserver.Config{Quota: quota.Config{
			Enabled:           true,
			MaxChannels:       8,
			MaxClientChannels: 8,
		}},
		client: &chclient.Config{
			Remotes: []string{
				slowLocal + ":" + slow,
				fastLocal + ":" + echo,
			},
			Quota: quota.Config{
				Enabled:             true,
				MaxClientChannels:   8,
				MaxPendingBytes:     32 << 10,
				FairChunkBytes:      4 << 10,
				SlowConsumerTimeout: 400 * time.Millisecond,
			},
		},
	}
	_, client, teardown := tl.setup(t)
	defer teardown()
	// The setup readiness probe to the intentionally silent endpoint can stay
	// in chisel's legal half-open state; that is existing half-close behavior.
	// This test therefore asserts the slow channel's own release count rather
	// than requiring every probe channel to disappear.
	releasedBefore := client.Quota().Snapshot().LeasesReleased

	slowConn, err := net.DialTimeout("tcp", "127.0.0.1:"+slowLocal, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer slowConn.Close()
	writeDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64<<10)
		var total int
		for total < 16<<20 {
			n, err := slowConn.Write(buf)
			total += n
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()

	muxWaitFor(t, 5*time.Second, func() bool {
		return client.Quota().Snapshot().SlowConsumers > 0
	})
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("write to stalled consumer completed without backpressure/close")
		}
		t.Logf("stalled write terminated as intended: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("slow consumer was not disconnected")
	}

	snap := client.Quota().Snapshot()
	if snap.BacklogHighWater <= 0 || snap.BacklogHighWater > 32<<10 {
		t.Fatalf("backlog high-water=%d, want in (0,%d]", snap.BacklogHighWater, 32<<10)
	}
	muxWaitFor(t, 3*time.Second, func() bool {
		snap := client.Quota().Snapshot()
		return snap.BacklogBytes == 0 && snap.LeasesReleased > releasedBefore
	})

	d, err := muxEchoOnce("127.0.0.1:"+fastLocal, 128)
	if err != nil {
		t.Fatalf("other channel failed while slow channel was reclaimed: %v", err)
	}
	t.Logf("other channel RTT after slow close: %s", d)

	// A brand-new connection is admitted immediately after terminal release.
	d, err = muxEchoOnce("127.0.0.1:"+fastLocal, 32)
	if err != nil {
		t.Fatalf("new connection after slow close failed: %v", err)
	}
	t.Logf("new connection RTT: %s", d)
}
