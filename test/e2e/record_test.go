package e2e_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/crecord"
)

// waitForRecord polls the record dir until cond matches or the
// deadline passes. Records are fsynced at write time, so polling the
// files observes them as soon as the recording goroutine runs.
func waitForRecord(t *testing.T, dir string, cond func([]crecord.Record) bool) []crecord.Record {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		recs, err := crecord.ReadDir(dir)
		if err == nil && cond(recs) {
			return recs
		}
		if time.Now().After(deadline) {
			recs, _ := crecord.ReadDir(dir)
			t.Fatalf("timed out waiting for records in %s; got %+v", dir, recs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRecordLifecycle covers a normal channel lifecycle: session and
// channel open/close records on both ends, cumulative byte counters,
// a classified close reason, and reconciliation between summary and
// detail records.
func TestRecordLifecycle(t *testing.T) {
	serverDir := t.TempDir()
	clientDir := t.TempDir()
	tmpPort := availablePort()
	conf := testLayout{
		server: &chserver.Config{
			Record: crecord.FlagConfig{Dir: serverDir, Key: "e2e-key"},
		},
		client: &chclient.Config{
			Remotes: []string{tmpPort + ":$FILEPORT"},
			Record:  crecord.FlagConfig{Dir: clientDir, Key: "e2e-key"},
		},
		fileServer: true,
	}
	_, _, teardown := conf.setup(t)
	defer teardown()
	//run one channel through the tunnel
	result, err := post("http://localhost:"+tmpPort, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if result != "foo!" {
		t.Fatalf("expected exclamation mark added")
	}
	//release the keep-alive connection so the channel closes and its
	//close record (with the cumulative counters) is written
	http.DefaultClient.CloseIdleConnections()
	//server side: one session, and the outbound channel open+close.
	//wait for the close that carried bytes (the POST channel; the
	//setup readiness probe opens and closes an empty channel first)
	recs := waitForRecord(t, serverDir, func(recs []crecord.Record) bool {
		s := crecord.Summarize(recs)
		return s.SessionsOpened >= 1 && s.ChannelsOpened >= 1 &&
			s.BytesSent > 0 && s.BytesReceived > 0
	})
	sum := crecord.Summarize(recs)
	//summary totals reconcile with the detail rows
	opens, closes := 0, 0
	openByID := map[string]*crecord.Record{}
	closeByID := map[string]*crecord.Record{}
	for i := range recs {
		r := &recs[i]
		if r.Kind != crecord.KindChannel {
			continue
		}
		switch r.Type {
		case crecord.TypeOpen:
			opens++
			openByID[r.Channel] = r
		case crecord.TypeClose:
			closes++
			closeByID[r.Channel] = r
		}
	}
	if sum.ChannelsOpened != opens || sum.ChannelsClosed != closes {
		t.Fatalf("summary %v does not match details %d/%d", sum, opens, closes)
	}
	//pair open and close by channel ID; the POST channel is the one
	//that carried bytes (the setup probe channel carries none)
	var chOpen, chClose *crecord.Record
	for id, c := range closeByID {
		o := openByID[id]
		if o == nil {
			t.Fatalf("close without open for %s", id)
		}
		if c.BytesSent > 0 || c.BytesReceived > 0 {
			chOpen, chClose = o, c
		}
	}
	if chOpen == nil || chClose == nil {
		t.Fatalf("no channel pair with byte counters in %+v", recs)
	}
	//the pair forms one chain: same channel ID inside one session
	if chOpen.Channel != chClose.Channel || chOpen.Session != chClose.Session {
		t.Fatalf("open/close not linked: %+v vs %+v", chOpen, chClose)
	}
	if chClose.OpenedAt == nil || chClose.DurationMS < 0 {
		t.Fatalf("close record missing lifecycle fields: %+v", chClose)
	}
	if chClose.BytesSent <= 0 || chClose.BytesReceived <= 0 {
		t.Fatalf("expected byte counters, got %+v", chClose)
	}
	if chClose.CloseReason != crecord.ReasonPeerClosed {
		t.Fatalf("expected peer_closed, got %s (%s)", chClose.CloseReason, chClose.Error)
	}
	//client side recorded the same channel from the inbound end
	crecs := waitForRecord(t, clientDir, func(recs []crecord.Record) bool {
		return crecord.Summarize(recs).ChannelsClosed >= 1
	})
	csum := crecord.Summarize(crecs)
	if csum.ChannelsOpened < 1 || csum.SessionsOpened < 1 {
		t.Fatalf("client records incomplete: %+v", csum)
	}
	//no plaintext internal addresses anywhere in the record files
	for _, dir := range []string{serverDir, clientDir} {
		names, _ := filepath.Glob(filepath.Join(dir, "channels-*.jsonl"))
		if len(names) == 0 {
			t.Fatalf("no record segments in %s", dir)
		}
		for _, name := range names {
			b, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "127.0.0.1") {
				t.Fatalf("%s contains a plaintext address", name)
			}
		}
		//and no parsed field carries the file server's port
		filePort := strings.Split(conf.client.Remotes[0], ":")[1]
		for _, r := range mustReadDir(t, dir) {
			for _, field := range []string{r.Remote, r.Src, r.Dst, r.Peer, r.Error} {
				if strings.Contains(field, filePort) {
					t.Fatalf("record field leaks port %s: %+v", filePort, r)
				}
			}
		}
	}
}

func mustReadDir(t *testing.T, dir string) []crecord.Record {
	t.Helper()
	recs, err := crecord.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// tcpRelay is a cuttable TCP proxy: it forwards connections to a
// fixed target, and drop() severs every live connection to simulate
// a network outage while the relay keeps listening for reconnects.
type tcpRelay struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  map[net.Conn]net.Conn
}

func newTCPRelay(t *testing.T, target string) *tcpRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &tcpRelay{ln: ln, target: target, conns: map[net.Conn]net.Conn{}}
	go r.acceptLoop()
	t.Cleanup(func() { r.ln.Close(); r.drop() })
	return r
}

func (r *tcpRelay) addr() string { return r.ln.Addr().String() }

func (r *tcpRelay) acceptLoop() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", r.target)
		if err != nil {
			c.Close()
			continue
		}
		r.mu.Lock()
		r.conns[c] = up
		r.mu.Unlock()
		go func() {
			io.Copy(up, c)
			up.Close()
		}()
		go func() {
			io.Copy(c, up)
			c.Close()
		}()
	}
}

// drop severs all live relayed connections, simulating an outage.
func (r *tcpRelay) drop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for c, up := range r.conns {
		c.Close()
		up.Close()
	}
	r.conns = map[net.Conn]net.Conn{}
}

// TestRecordReconnect covers a mid-stream reconnect: after the
// connection drops and is re-established, the client's second
// session must be recognizable as the same logical channel's second
// connection — same logical ID, new session ID — not an independent
// channel.
func TestRecordReconnect(t *testing.T) {
	serverDir := t.TempDir()
	clientDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, err := chserver.NewServer(&chserver.Config{
		Record: crecord.FlagConfig{Dir: serverDir, Key: "e2e-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	if err := server.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	//the client reaches the server through a relay we can cut
	relay := newTCPRelay(t, "127.0.0.1:"+port)
	tmpPort := availablePort()
	client, err := chclient.NewClient(&chclient.Config{
		Server:           "http://" + relay.addr(),
		Remotes:          []string{tmpPort + ":127.0.0.1:8080"},
		KeepAlive:        500 * time.Millisecond,
		MaxRetryCount:    -1, //retry forever, like the CLI default
		MinRetryInterval: 50 * time.Millisecond,
		MaxRetryInterval: 200 * time.Millisecond,
		Record:           crecord.FlagConfig{Dir: clientDir, Key: "e2e-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if !client.Ready(ctx) {
		t.Fatal("client did not connect")
	}
	//cut the connection; the client notices and reconnects
	relay.drop()
	//wait for the second session to appear in the client records
	recs := waitForRecord(t, clientDir, func(recs []crecord.Record) bool {
		return crecord.Summarize(recs).SessionsOpened >= 2
	})
	var opens []crecord.Record
	for _, r := range recs {
		if r.Kind == crecord.KindSession && r.Type == crecord.TypeOpen {
			opens = append(opens, r)
		}
	}
	if len(opens) < 2 {
		t.Fatalf("expected 2 session opens, got %d", len(opens))
	}
	first, second := opens[0], opens[1]
	//the reconnect is the SAME logical channel's second connection…
	if first.Logical == "" || first.Logical != second.Logical {
		t.Fatalf("reconnect not linked to the same logical channel: %q vs %q",
			first.Logical, second.Logical)
	}
	//…but a distinct connection, not a duplicate record
	if first.Session == second.Session {
		t.Fatalf("reconnect reused session ID %q", first.Session)
	}
	if first.RunID != second.RunID {
		t.Fatalf("reconnect changed run ID: %q vs %q", first.RunID, second.RunID)
	}
	if !second.TS.After(first.TS) {
		t.Fatal("session records out of order")
	}
	//the first session's close is recorded and classified
	var firstClose *crecord.Record
	for i := range recs {
		if recs[i].Kind == crecord.KindSession && recs[i].Type == crecord.TypeClose &&
			recs[i].Session == first.Session {
			firstClose = &recs[i]
		}
	}
	if firstClose == nil {
		t.Fatal("first session has no close record")
	}
	if firstClose.CloseReason == "" {
		t.Fatalf("first session close has no reason: %+v", firstClose)
	}
	//the server sees the same two connections of one logical channel
	srecs := waitForRecord(t, serverDir, func(recs []crecord.Record) bool {
		return crecord.Summarize(recs).SessionsOpened >= 2
	})
	var sOpens []crecord.Record
	for _, r := range srecs {
		if r.Kind == crecord.KindSession && r.Type == crecord.TypeOpen {
			sOpens = append(sOpens, r)
		}
	}
	if len(sOpens) < 2 || sOpens[0].Logical != sOpens[1].Logical ||
		sOpens[0].Session == sOpens[1].Session {
		t.Fatalf("server records do not show one logical channel, two connections: %+v", sOpens)
	}
}

// TestRecordDisabledWritesNothing verifies the opt-in switch: with
// no --record-dir, running a full tunnel creates no record files.
func TestRecordDisabledWritesNothing(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	tmpPort := availablePort()
	teardown := simpleSetup(t,
		&chserver.Config{},
		&chclient.Config{
			Remotes: []string{tmpPort + ":$FILEPORT"},
		})
	defer teardown()
	if _, err := post("http://localhost:"+tmpPort, "foo"); err != nil {
		t.Fatal(err)
	}
	//no record segments anywhere in the working directory
	names, _ := filepath.Glob(filepath.Join(cwd, "channels-*.jsonl"))
	if len(names) != 0 {
		t.Fatalf("recording disabled but found %v", names)
	}
	entries, err := os.ReadDir(cwd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		got := []string{}
		for _, e := range entries {
			got = append(got, e.Name())
		}
		t.Fatalf("recording disabled but files appeared: %v", got)
	}
}
