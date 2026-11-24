package e2e_test

import (
	"bytes"
	"net"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/quota"
)

func muxPersistentRTT(t *testing.T, addr string, samples int) (time.Duration, time.Duration) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("rtt-"), 16) // 64 bytes
	buf := make([]byte, len(payload))
	got := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		start := time.Now()
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("rtt write: %v", err)
		}
		if _, err := readFullMux(c, buf); err != nil {
			t.Fatalf("rtt read: %v", err)
		}
		if !bytes.Equal(buf, payload) {
			t.Fatal("rtt echo mismatch")
		}
		got = append(got, time.Since(start))
		time.Sleep(20 * time.Millisecond)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	return got[len(got)/2], got[len(got)-1]
}

func readFullMux(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func muxUploadOnce(t *testing.T, addr string, total int64) float64 {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 64<<10)
	start := time.Now()
	var sent int64
	for sent < total {
		n, err := c.Write(buf)
		sent += int64(n)
		if err != nil {
			t.Fatalf("baseline upload: %v", err)
		}
	}
	mbps := float64(total) / time.Since(start).Seconds() / 1e6
	return mbps
}

func TestMuxFairSchedulingBoundsInteractiveRTTAndThroughput(t *testing.T) {
	echo := startMuxEcho(t)
	discard := startMuxDiscard(t)
	fastLocal := availablePort()
	bigLocal := availablePort()
	tl := testLayout{
		server: &chserver.Config{Quota: quota.Config{Enabled: true, MaxChannels: 32}},
		client: &chclient.Config{
			Remotes: []string{
				fastLocal + ":" + echo,
				bigLocal + ":" + discard,
			},
			Quota: quota.Config{
				Enabled:             true,
				MaxChannels:         32,
				MaxPendingBytes:     256 << 10,
				FairChunkBytes:      16 << 10,
				SlowConsumerTimeout: -1, // fairness test keeps the reader healthy
			},
		},
	}
	_, _, teardown := tl.setup(t)
	defer teardown()
	fastAddr := "127.0.0.1:" + fastLocal
	bigAddr := "127.0.0.1:" + bigLocal

	baseMedian, baseMax := muxPersistentRTT(t, fastAddr, 11)
	baselineMBps := muxUploadOnce(t, bigAddr, 32<<20)
	t.Logf("baseline RTT median=%s max=%s; single-flow throughput=%.1f MB/s", baseMedian, baseMax, baselineMBps)

	big, err := net.DialTimeout("tcp", bigAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer big.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	var bytes int64
	start := time.Now()
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := big.Write(buf)
			atomic.AddInt64(&bytes, int64(n))
			if err != nil {
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond) // let the bulk flow saturate/queue

	satMedian, satMax := muxPersistentRTT(t, fastAddr, 11)
	close(stop)
	_ = big.Close()
	<-done
	elapsed := time.Since(start).Seconds()
	saturatedMBps := float64(atomic.LoadInt64(&bytes)) / elapsed / 1e6
	t.Logf("saturated RTT median=%s max=%s; bulk throughput=%.1f MB/s", satMedian, satMax, saturatedMBps)

	// Quantified upper bound: 50x the empty-path median plus a 250ms scheduling
	// budget, and never above one second median on loopback CI.
	medianBound := time.Duration(50*int64(baseMedian)) + 250*time.Millisecond
	if satMedian > medianBound || satMedian > time.Second {
		t.Fatalf("saturated median RTT %s exceeds bound %s (hard cap 1s)", satMedian, medianBound)
	}
	maxBound := time.Duration(100*int64(baseMax)) + time.Second
	if satMax > maxBound || satMax > 3*time.Second {
		t.Fatalf("saturated max RTT %s exceeds bound %s (hard cap 3s)", satMax, maxBound)
	}
	// "No order-of-magnitude throughput collapse": retain at least one tenth
	// of the otherwise equivalent single-flow throughput.
	if saturatedMBps < baselineMBps/10 {
		t.Fatalf("bulk throughput %.1f MB/s is more than 10x below baseline %.1f MB/s", saturatedMBps, baselineMBps)
	}
}
