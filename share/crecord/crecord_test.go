package crecord

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestRecorder(t *testing.T, dir string) *Recorder {
	t.Helper()
	r, err := New(Config{Dir: dir, Key: "test-key", End: "server"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestLifecycleAndSummary(t *testing.T) {
	dir := t.TempDir()
	r := newTestRecorder(t, dir)
	sid := r.NextSessionID()
	r.Write(Record{Type: TypeOpen, Kind: KindSession, Session: sid, Logical: "L1"})
	r.Write(Record{Type: TypeOpen, Kind: KindChannel, Session: sid, Channel: sid + "-c1"})
	r.Write(Record{Type: TypeClose, Kind: KindChannel, Session: sid, Channel: sid + "-c1",
		BytesSent: 100, BytesReceived: 200, CloseReason: ReasonPeerClosed})
	r.Write(Record{Type: TypeClose, Kind: KindSession, Session: sid, CloseReason: ReasonShutdown})
	r.Close()

	recs, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 {
		t.Fatalf("expected 4 records, got %d", len(recs))
	}
	for _, rec := range recs {
		if rec.V != FormatVersion || rec.ID == "" || rec.RunID == "" || rec.End != "server" {
			t.Fatalf("record not stamped: %+v", rec)
		}
	}
	//summary must reconcile with the detail rows
	sum := Summarize(recs)
	if sum.SessionsOpened != 1 || sum.SessionsClosed != 1 ||
		sum.ChannelsOpened != 1 || sum.ChannelsClosed != 1 {
		t.Fatalf("summary mismatch: %+v", sum)
	}
	if sum.BytesSent != 100 || sum.BytesReceived != 200 {
		t.Fatalf("byte totals mismatch: %+v", sum)
	}
	if sum.CloseReasons[ReasonPeerClosed] != 1 || sum.CloseReasons[ReasonShutdown] != 1 {
		t.Fatalf("reason counts mismatch: %+v", sum.CloseReasons)
	}
	//totals equal detail counts by construction
	opens := 0
	for _, rec := range recs {
		if rec.Type == TypeOpen {
			opens++
		}
	}
	if sum.SessionsOpened+sum.ChannelsOpened != opens {
		t.Fatal("summary open total does not match detail rows")
	}
}

func TestRotationBySize(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{Dir: dir, Key: "k", MaxSize: 256, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; i < 20; i++ {
		r.Write(Record{Type: TypeOpen, Kind: KindChannel, Channel: "c"})
	}
	r.Close()
	names, _ := filepath.Glob(filepath.Join(dir, segmentPrefix+"*.jsonl"))
	if len(names) < 2 {
		t.Fatalf("expected rotation into multiple segments, got %v", names)
	}
	//all records survive across segments
	recs, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 20 {
		t.Fatalf("expected 20 records across segments, got %d", len(recs))
	}
}

func TestSerializationFailureSkippedAndCounted(t *testing.T) {
	dir := t.TempDir()
	r := newTestRecorder(t, dir)
	//a func value cannot be marshalled
	r.Write(Record{Type: TypeOpen, Kind: KindChannel, Extra: map[string]any{"bad": func() {}}})
	r.Write(Record{Type: TypeOpen, Kind: KindChannel, Channel: "ok"})
	if r.Dropped() != 1 {
		t.Fatalf("expected 1 dropped record, got %d", r.Dropped())
	}
	r.Close()
	recs, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Channel != "ok" {
		t.Fatalf("bad record was not skipped: %+v", recs)
	}
}

func TestRedaction(t *testing.T) {
	dir := t.TempDir()
	r := newTestRecorder(t, dir)
	red := r.Redactor()
	tok := red.Token("10.1.2.3:3306")
	if !strings.HasPrefix(tok, "h1:") {
		t.Fatalf("token missing scheme prefix: %q", tok)
	}
	if strings.Contains(tok, "10.1.2.3") || strings.Contains(tok, "3306") {
		t.Fatalf("token leaks plaintext: %q", tok)
	}
	//deterministic per key, different across keys
	if tok != red.Token("10.1.2.3:3306") {
		t.Fatal("token not deterministic")
	}
	other := NewRedactor([]byte("other-key")).Token("10.1.2.3:3306")
	if other == tok {
		t.Fatal("token does not depend on key")
	}
	//operators map a token back by recomputing it for a candidate
	if red.Token("10.1.2.3:3306") != tok || red.Token("10.9.9.9:80") == tok {
		t.Fatal("candidate lookup failed")
	}
	//error sanitization removes embedded IPs and ports
	s := red.Sanitize(`dial tcp 10.1.2.3:3306: connect: connection refused`)
	if strings.Contains(s, "10.1.2.3") || strings.Contains(s, "3306") {
		t.Fatalf("sanitize left plaintext: %q", s)
	}
	//records on disk contain no plaintext addresses
	r.Write(Record{Type: TypeOpen, Kind: KindChannel,
		Remote: red.Token("10.1.2.3:3306"), Src: red.Token("192.168.1.5:51000"),
		Error: red.Sanitize("dial tcp 10.1.2.3:3306: refused")})
	r.Close()
	names, _ := filepath.Glob(filepath.Join(dir, segmentPrefix+"*.jsonl"))
	if len(names) != 1 {
		t.Fatalf("expected one segment, got %v", names)
	}
	b, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, plain := range []string{"10.1.2.3", "3306", "192.168.1.5", "51000"} {
		if strings.Contains(string(b), plain) {
			t.Fatalf("record file contains plaintext %q", plain)
		}
	}
}

func TestUnwritableDirBuffersAndRewrites(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("chmod does not restrict root")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "recs")
	if err := os.Mkdir(dir, 0500); err != nil {
		t.Fatal(err)
	}
	//degraded start: directory not writable, records buffer in memory
	r, err := New(Config{Dir: dir, Key: "k"})
	if err != nil {
		t.Fatal(err)
	}
	r.Write(Record{Type: TypeOpen, Kind: KindSession, Session: "s1"})
	r.Write(Record{Type: TypeClose, Kind: KindSession, Session: "s1"})
	//repair the directory; subsequent writes trigger the rewrite
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	//open attempts are throttled to one per second
	time.Sleep(1100 * time.Millisecond)
	r.Write(Record{Type: TypeOpen, Kind: KindChannel, Channel: "c1"})
	r.Close()
	recs, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 rewritten records, got %d: %+v", len(recs), recs)
	}
	//rewrite produced no duplicates: IDs are unique
	ids := map[string]bool{}
	for _, rec := range recs {
		if ids[rec.ID] {
			t.Fatalf("duplicate record ID %s after rewrite", rec.ID)
		}
		ids[rec.ID] = true
	}
}

func TestKeyFileGeneratedAndReused(t *testing.T) {
	dir := t.TempDir()
	r1, err := New(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	tok := r1.Redactor().Token("10.0.0.1:80")
	r1.Close()
	//a second recorder in the same dir reuses record.key
	r2, err := New(Config{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	if r2.Redactor().Token("10.0.0.1:80") != tok {
		t.Fatal("redaction key not persisted across runs")
	}
	fi, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestNilRecorderIsNoop(t *testing.T) {
	var r *Recorder
	r.Write(Record{Type: TypeOpen, Kind: KindChannel})
	if r.Redactor() != nil || r.RunID() != "" || r.NextSessionID() != "" || r.Dropped() != 0 {
		t.Fatal("nil recorder should be an inert no-op")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		err  error
		want CloseReason
	}{
		{nil, ReasonPeerClosed},
		{io.EOF, ReasonPeerClosed},
		{context.Canceled, ReasonShutdown},
		{context.DeadlineExceeded, ReasonTimeout},
		{errors.New("i/o timeout"), ReasonTimeout},
		{errors.New("access denied"), ReasonAuthFailed},
		{errors.New("protocol version mismatch"), ReasonProtocolError},
		{errors.New("connection reset by peer"), ReasonError},
	}
	for _, c := range cases {
		if got := ClassifyError(c.err); got != c.want {
			t.Errorf("ClassifyError(%v) = %s, want %s", c.err, got, c.want)
		}
	}
}
