package quota

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type gateConn struct {
	mu             sync.Mutex
	buf            []byte
	firstWrite     chan struct{}
	releaseFirst   chan struct{}
	closeWriteCall int
}

func (c *gateConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *gateConn) Close() error               { return nil }
func (c *gateConn) CloseWrite() error          { c.closeWriteCall++; return nil }
func (c *gateConn) Write(p []byte) (int, error) {
	select {
	case c.firstWrite <- struct{}{}:
	default:
	}
	<-c.releaseFirst
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return len(p), nil
}

func TestManagedStreamBacklogIsBoundedAndFlushesHalfClose(t *testing.T) {
	metrics := &Metrics{}
	s := NewScheduler(Config{MaxPendingBytes: 4096, FairChunkBytes: 1024}, metrics)
	base := &gateConn{firstWrite: make(chan struct{}, 1), releaseFirst: make(chan struct{})}
	w := s.Wrap(base)

	writeDone := make(chan error, 1)
	go func() {
		_, err := w.Write(make([]byte, 1<<20))
		writeDone <- err
	}()
	select {
	case <-base.firstWrite:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not start write")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && w.Depth() != 4096 {
		time.Sleep(time.Millisecond)
	}
	if d := w.Depth(); d > 4096 {
		t.Fatalf("depth %d exceeds bound", d)
	}
	if d := w.MaxDepth(); d > 4096 {
		t.Fatalf("high-water %d exceeds bound", d)
	}
	close(base.releaseFirst)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("large write did not resume after drain")
	}
	if err := w.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if base.closeWriteCall != 1 {
		t.Fatalf("CloseWrite calls=%d", base.closeWriteCall)
	}
	if d := w.MaxDepth(); d != 4096 {
		t.Fatalf("high-water=%d, want full bound 4096", d)
	}
}

type blockForeverConn struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newBlockForeverConn() *blockForeverConn {
	return &blockForeverConn{started: make(chan struct{}, 1), closed: make(chan struct{})}
}
func (c *blockForeverConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *blockForeverConn) CloseWrite() error          { return c.Close() }
func (c *blockForeverConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *blockForeverConn) Write(p []byte) (int, error) {
	c.started <- struct{}{}
	<-c.closed
	return 0, errors.New("closed")
}

func TestSlowConsumerIsClosedAndOtherStreamsContinue(t *testing.T) {
	metrics := &Metrics{}
	s := NewScheduler(Config{
		MaxPendingBytes:     2048,
		FairChunkBytes:      1024,
		SlowConsumerTimeout: 40 * time.Millisecond,
	}, metrics)
	badBase := newBlockForeverConn()
	bad := s.Wrap(badBase)
	errCh := make(chan error, 1)
	go func() {
		_, err := bad.Write(make([]byte, 64*1024))
		errCh <- err
	}()
	select {
	case <-badBase.started:
	case <-time.After(time.Second):
		t.Fatal("slow write never started")
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrSlowConsumer) && CategoryOf(err) != CategoryState {
			t.Fatalf("expected slow-consumer category, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("slow consumer was not closed")
	}
	if got := metrics.Snapshot().SlowConsumers; got == 0 {
		t.Fatal("slow consumer not counted")
	}

	goodBase := &gateConn{firstWrite: make(chan struct{}, 1), releaseFirst: closedChan()}
	good := s.Wrap(goodBase)
	done := make(chan error, 1)
	go func() {
		if _, err := good.Write([]byte("ok")); err != nil {
			done <- err
			return
		}
		done <- good.CloseWrite()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("other stream failed after slow consumer: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("other stream starved by slow consumer")
	}
}

func closedChan() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func TestBlockedStreamDoesNotBlockOtherStream(t *testing.T) {
	s := NewScheduler(Config{MaxPendingBytes: 1024, FairChunkBytes: 512, SlowConsumerTimeout: time.Second}, &Metrics{})
	badBase := newBlockForeverConn()
	bad := s.Wrap(badBase)
	go func() { _, _ = bad.Write(make([]byte, 8192)) }()
	select {
	case <-badBase.started:
	case <-time.After(time.Second):
		t.Fatal("blocked write did not start")
	}

	goodBase := &gateConn{firstWrite: make(chan struct{}, 1), releaseFirst: closedChan()}
	good := s.Wrap(goodBase)
	done := make(chan error, 1)
	go func() {
		if _, err := good.Write([]byte("ping")); err != nil {
			done <- err
			return
		}
		done <- good.CloseWrite()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("healthy stream blocked by slow stream: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("healthy stream could not make progress while another write was blocked")
	}
	_ = bad.Close()
}

func TestDropQueueCountsCongestion(t *testing.T) {
	m := &Metrics{}
	q := NewDropQueue[int](2, m, KindDatagram)
	if !q.TrySend(1) || !q.TrySend(2) {
		t.Fatal("expected first two datagrams queued")
	}
	if q.TrySend(3) {
		t.Fatal("third datagram should be dropped")
	}
	s := m.Snapshot()
	if s.Dropped[key(string(KindDatagram), "queue_full")] != 1 {
		t.Fatalf("drops=%v", s.Dropped)
	}
}
