// Command quotasample runs several concurrent channels through an in-process
// chisel client/server pair and prints a usage-statistics sample for the
// forwarding side's quota state.
//
// It is a documentation and acceptance aid, not part of the chisel binary:
//
//	go run ./example/quota-sample
//
// Forward remotes are admitted by the chisel client's proxies, reverse remotes
// by the server's. The sample uses forward remotes, so the client's quota is
// sampled. The JSON is the same form returned by quota.Set.StatsJSON, which
// embedders can call from their own process.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/quota"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	//an echo endpoint for the fast channels, and a silent one for the slow
	fastAddr, err := listenEcho()
	if err != nil {
		return err
	}
	defer fastAddr.Close()
	slowAddr, err := listenSilent()
	if err != nil {
		return err
	}
	defer slowAddr.Close()

	//two fast channels and one slow channel on a single tunnel
	fast1, fast2, slowLocal := freePort(), freePort(), freePort()
	cfg := quota.DefaultConfig()
	cfg.Enabled = true
	cfg.MaxConns = 3
	cfg.MaxQueue = 4

	client, teardown, err := start(cfg, []string{
		fast1 + ":" + fastAddr.Addr().String(),
		fast2 + ":" + fastAddr.Addr().String(),
		slowLocal + ":" + slowAddr.Addr().String(),
	})
	if err != nil {
		return err
	}
	defer teardown()

	//drive traffic on the fast channels and saturate the slow one
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for _, local := range []string{fast1, fast2} {
		wg.Add(1)
		go func(local string) { defer wg.Done(); burst(ctx, local) }(local)
	}
	var held []net.Conn
	for i := 0; i < cfg.MaxConns+cfg.MaxQueue; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:"+slowLocal)
		if err != nil {
			break
		}
		conn.Write([]byte("slow"))
		held = append(held, conn)
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	out, err := client.Quota().StatsJSON()
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	client.Quota().LogStats()
	for _, conn := range held {
		conn.Close()
	}
	return nil
}

func start(cfg quota.Config, remotes []string) (*chclient.Client, func(), error) {
	srv, err := chserver.NewServer(&chserver.Config{})
	if err != nil {
		return nil, nil, err
	}
	port := freePort()
	if err := srv.Start("127.0.0.1", port); err != nil {
		return nil, nil, err
	}
	cli, err := chclient.NewClient(&chclient.Config{
		Server:  "http://127.0.0.1:" + port,
		Remotes: remotes,
		Quota:   cfg,
	})
	if err != nil {
		srv.Close()
		return nil, nil, err
	}
	if err := cli.Start(context.Background()); err != nil {
		return nil, nil, err
	}
	if !cli.Ready(context.Background()) {
		return nil, nil, fmt.Errorf("client did not connect")
	}
	//let each proxy finish binding its listener
	time.Sleep(200 * time.Millisecond)
	teardown := func() {
		cli.Close()
		cli.Wait()
		srv.Close()
		srv.Wait()
	}
	return cli, teardown, nil
}

// burst opens and closes a series of short requests on one channel.
func burst(ctx context.Context, local string) {
	msg := []byte("ping")
	for ctx.Err() == nil {
		conn, err := net.Dial("tcp", "127.0.0.1:"+local)
		if err != nil {
			return
		}
		conn.Write(msg)
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, len(msg))
		io.ReadFull(conn, buf)
		conn.Close()
	}
}

func listenEcho() (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return l, nil
}

func listenSilent() (net.Listener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(io.Discard, conn) }()
		}
	}()
	return l, nil
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}
