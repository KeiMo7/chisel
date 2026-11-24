package quota

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// HalfCloseConn is the stream surface required to preserve chisel's
// half-close semantics through the fair writer.
type HalfCloseConn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

var errManagedClosed = errors.New("quota: managed stream closed")

// ErrSlowConsumer is returned/counted when the write watchdog closes a channel.
var ErrSlowConsumer = &Error{
	Category: CategoryState,
	reason:   "slow_consumer",
	message:  "slow consumer channel closed",
}

// Scheduler owns bounded managed streams. Each stream has one writer goroutine;
// a blocked write therefore cannot stop another stream's writer. Bounded chunk
// sizes keep the shared transport write critical section small, which provides
// fairness without reordering bytes within a stream.
type Scheduler struct {
	cfg     Config
	metrics *Metrics
	stopped atomic.Bool
}

// ManagedStream places bounded backlog in front of an SSH channel. Reads pass
// through unchanged; ordered writes enter one FIFO queue and are emitted by a
// single per-stream writer.
type ManagedStream struct {
	base    HalfCloseConn
	sched   *Scheduler
	maxByte int64
	chunk   int

	mu         sync.Mutex
	cond       *sync.Cond
	queue      [][]byte
	queued     int64
	inflight   int64
	highDepth  int64
	closed     bool
	err        error
	halfCalled bool
	halfDone   bool
	halfErr    error
	halfWait   chan struct{}
}

// NewScheduler creates a fair scheduler factory.
func NewScheduler(cfg Config, metrics *Metrics) *Scheduler {
	cfg = cfg.WithDefaults()
	return &Scheduler{cfg: cfg, metrics: metrics}
}

// Start exists for lifecycle symmetry; per-stream writers start in Wrap.
func (s *Scheduler) Start() {}

// Close prevents new writes from being accepted. Stream owners still call
// Stream.Close for complete cleanup.
func (s *Scheduler) Close() {
	if s != nil {
		s.stopped.Store(true)
	}
}

// Wrap creates and starts a managed stream.
func (s *Scheduler) Wrap(base HalfCloseConn) *ManagedStream {
	if s == nil {
		return nil
	}
	max := int64(s.cfg.MaxPendingBytes)
	chunk := s.cfg.FairChunkBytes
	if chunk <= 0 {
		chunk = 16 << 10
	}
	if max > 0 && int64(chunk) > max {
		chunk = int(max)
	}
	w := &ManagedStream{
		base:     base,
		sched:    s,
		maxByte:  max,
		chunk:    chunk,
		halfWait: make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.writeLoop()
	return w
}

func (w *ManagedStream) depthLocked() int64 { return w.queued + w.inflight }

// Depth returns queued plus write-in-flight bytes.
func (w *ManagedStream) Depth() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.depthLocked()
}

// MaxDepth returns the high-water mark for this stream.
func (w *ManagedStream) MaxDepth() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.highDepth
}

// Read preserves the underlying read path exactly.
func (w *ManagedStream) Read(p []byte) (int, error) { return w.base.Read(p) }

// Write enforces the per-stream backlog bound. When the bound is reached it
// blocks, which applies backpressure to io.Copy and the upstream data source.
func (w *ManagedStream) Write(p []byte) (int, error) {
	if w.maxByte <= 0 {
		return w.base.Write(p)
	}
	written := 0
	stopWait := func() {}
	waiting := false
	stopWaiting := func() {
		if waiting {
			stopWait()
			waiting = false
		}
	}
	defer stopWaiting()

	for written < len(p) {
		n := min(len(p)-written, w.chunk)
		chunkLen := int64(n)
		w.mu.Lock()
		for {
			if w.err != nil {
				w.mu.Unlock()
				return written, w.err
			}
			if w.closed || w.sched.stopped.Load() {
				w.mu.Unlock()
				return written, errManagedClosed
			}
			if w.depthLocked()+chunkLen <= w.maxByte {
				break
			}
			if !waiting {
				stopWait = w.sched.metrics.BackpressureWait()
				waiting = true
			}
			w.cond.Wait()
		}
		stopWaiting()
		if w.halfCalled {
			w.mu.Unlock()
			return written, errManagedClosed
		}
		buf := append([]byte(nil), p[written:written+n]...)
		w.queue = append(w.queue, buf)
		w.queued += chunkLen
		if d := w.depthLocked(); d > w.highDepth {
			w.highDepth = d
		}
		w.sched.metrics.AddBacklog(chunkLen)
		w.cond.Signal()
		w.mu.Unlock()
		written += n
	}
	return written, nil
}

func (w *ManagedStream) writeLoop() {
	for {
		w.mu.Lock()
		for len(w.queue) == 0 && !w.closed && w.err == nil && !w.sched.stopped.Load() {
			if w.halfCalled {
				w.mu.Unlock()
				return
			}
			w.cond.Wait()
		}
		if w.closed || w.err != nil || w.sched.stopped.Load() {
			w.mu.Unlock()
			return
		}
		if w.halfCalled && len(w.queue) == 0 {
			w.mu.Unlock()
			return
		}
		chunk := w.queue[0]
		w.queue[0] = nil
		w.queue = w.queue[1:]
		w.queued -= int64(len(chunk))
		w.inflight += int64(len(chunk))
		w.mu.Unlock()

		err := w.sched.writeChunk(w, chunk)

		w.mu.Lock()
		w.inflight -= int64(len(chunk))
		w.sched.metrics.AddBacklog(-int64(len(chunk)))
		if err != nil && w.err == nil {
			w.err = err
		}
		if w.err != nil {
			for _, q := range w.queue {
				w.sched.metrics.AddBacklog(-int64(len(q)))
			}
			w.queue = nil
			w.queued = 0
		}
		w.cond.Broadcast()
		exit := w.closed || w.err != nil || w.sched.stopped.Load() ||
			(w.halfCalled && len(w.queue) == 0 && w.inflight == 0)
		w.mu.Unlock()
		if exit {
			return
		}
	}
}

func (s *Scheduler) writeChunk(w *ManagedStream, p []byte) error {
	timeout := s.cfg.SlowConsumerTimeout
	if timeout <= 0 {
		_, err := w.base.Write(p)
		return err
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		timedOut.Store(true)
		s.metrics.SlowConsumerClosed()
		// Closing the SSH channel unblocks x/crypto's window wait. Because
		// each stream has its own writer goroutine, this cannot stall other
		// streams.
		_ = w.base.Close()
	})
	_, err := w.base.Write(p)
	if timer.Stop() {
		return err
	}
	if timedOut.Load() {
		return ErrSlowConsumer
	}
	if err != nil {
		return err
	}
	return ErrSlowConsumer
}

// CloseWrite flushes all bounded bytes, then half-closes the underlying
// connection. This preserves in-stream order and existing half-close EOF
// semantics.
func (w *ManagedStream) CloseWrite() error {
	w.mu.Lock()
	if w.halfCalled {
		for !w.halfDone {
			w.cond.Wait()
		}
		err := w.halfErr
		w.mu.Unlock()
		return err
	}
	w.halfCalled = true
	w.cond.Broadcast()
	for !w.closed && !w.sched.stopped.Load() && w.err == nil && (w.queued > 0 || w.inflight > 0) {
		w.cond.Wait()
	}
	var err error
	switch {
	case w.err != nil:
		err = w.err
	case w.closed || w.sched.stopped.Load():
		err = errManagedClosed
	}
	w.mu.Unlock()
	if err != nil {
		w.completeHalfClose(err)
		return err
	}
	err = w.base.CloseWrite()
	w.completeHalfClose(err)
	return err
}

func (w *ManagedStream) completeHalfClose(err error) {
	w.mu.Lock()
	if !w.halfDone {
		w.halfErr = err
		w.halfDone = true
		close(w.halfWait)
		w.cond.Broadcast()
	}
	w.mu.Unlock()
}

// Close fails bounded writers and closes the underlying stream.
func (w *ManagedStream) Close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		if w.err == nil {
			w.err = errManagedClosed
		}
		for _, q := range w.queue {
			w.sched.metrics.AddBacklog(-int64(len(q)))
		}
		w.queue = nil
		w.queued = 0
		w.cond.Broadcast()
	}
	w.mu.Unlock()
	return w.base.Close()
}
