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

// BenchmarkQuotaForward compares the same forwarding workload with quotas
// disabled (the unchanged path) and enabled. Each iteration opens one tunneled
// TCP connection, echoes 4 KiB, and closes it; b.RunParallel controls the
// number of concurrent clients.
//
// Equivalent input, so the delta is the admission, accounting and byte
// wrapper cost:
//
//	go test ./test/e2e -run '^$' -bench '^BenchmarkQuotaForward/' -benchmem
func BenchmarkQuotaForward(b *testing.B) {
	for _, mode := range []string{"disabled", "enabled"} {
		b.Run(mode, func(b *testing.B) {
			echo := startBenchEcho(b)
			cfg := quota.DefaultConfig()
			cfg.Enabled = mode == "enabled"
			cfg.MaxConns = 256
			cfg.MaxQueue = 1024
			server, client, local, teardown := benchSetup(b, cfg, echo)
			_ = server
			_ = client
			defer teardown()
			payload := make([]byte, 4096)
			buf := make([]byte, len(payload))
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			localPort := local
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if err := benchEcho(localPort, payload, buf); err != nil {
						b.Error(err)
						return
					}
				}
			})
		})
	}
}

func benchSetup(b *testing.B, cfg quota.Config, echo string) (*chserver.Server, *chclient.Client, string, func()) {
	b.Helper()
	srv, err := chserver.NewServer(&chserver.Config{})
	if err != nil {
		b.Fatal(err)
	}
	srv.SetOutput(io.Discard)
	srv.Info = false
	port := benchFreePort(b)
	if err := srv.Start("127.0.0.1", port); err != nil {
		b.Fatal(err)
	}
	//retry NewClient around races for the chosen ephemeral local port
	var cli *chclient.Client
	var local string
	var remotes []string
	for i := 0; i < 50; i++ {
		local = benchFreePort(b)
		remotes = []string{local + ":" + echo}
		c := &chclient.Config{
			Quota:       cfg,
			Remotes:     remotes,
			Server:      "http://127.0.0.1:" + port,
			Fingerprint: srv.GetFingerprint(),
		}
		cli, err = chclient.NewClient(c)
		if err == nil {
			break
		}
		cli = nil
	}
	if cli == nil {
		b.Fatalf("client setup: %v", err)
	}
	cli.SetOutput(io.Discard)
	cli.Info = false
	if err := cli.Start(b.Context()); err != nil {
		b.Fatal(err)
	}
	if !cli.Ready(b.Context()) {
		b.Fatal("client did not connect")
	}
	waitForBench(b, 3*time.Second, func() bool {
		conn, err := net.Dial("tcp", "127.0.0.1:"+local)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	})
	teardown := func() {
		cli.Close()
		cli.Wait()
		srv.Close()
		srv.Wait()
	}
	return srv, cli, local, teardown
}

func benchEcho(local string, payload, buf []byte) error {
	conn, err := net.Dial("tcp", "127.0.0.1:"+local)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	_, err = io.ReadFull(conn, buf)
	return err
}

func startBenchEcho(b *testing.B) string {
	b.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return l.Addr().String()
}

func benchFreePort(b *testing.B) string {
	b.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// waitFor accepts either *testing.T or *testing.B.
type testHelper interface {
	Helper()
	Fatalf(string, ...any)
}

func waitForBench(h testHelper, timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.Fatalf("condition not met before %s", timeout)
	return false
}
