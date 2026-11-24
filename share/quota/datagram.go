package quota

import "sync"

// DropQueue is a bounded generic queue for message-oriented datagram paths.
// Congestion makes TrySend fail immediately and increments a drop counter;
// shared receive loops never block on a slow relay.
type DropQueue[T any] struct {
	ch      chan T
	done    chan struct{}
	closeMu sync.Mutex
	closed  bool
	metrics *Metrics
	kind    Kind
	reason  string
}

// NewDropQueue creates a queue with capacity packets.
func NewDropQueue[T any](capacity int, metrics *Metrics, kind Kind) *DropQueue[T] {
	if capacity <= 0 {
		capacity = 1
	}
	return &DropQueue[T]{
		ch:      make(chan T, capacity),
		done:    make(chan struct{}),
		metrics: metrics,
		kind:    kind,
		reason:  "queue_full",
	}
}

// TrySend enqueues or drops without blocking.
func (q *DropQueue[T]) TrySend(v T) bool {
	if q == nil {
		return false
	}
	q.closeMu.Lock()
	if q.closed {
		q.closeMu.Unlock()
		q.metrics.DropDatagram(q.kind, "closed")
		return false
	}
	select {
	case q.ch <- v:
		q.closeMu.Unlock()
		return true
	default:
		q.closeMu.Unlock()
		q.metrics.DropDatagram(q.kind, q.reason)
		return false
	}
}

// C exposes the receive channel to a single writer goroutine.
func (q *DropQueue[T]) C() <-chan T {
	if q == nil {
		return nil
	}
	return q.ch
}

// Done is closed by Close.
func (q *DropQueue[T]) Done() <-chan struct{} {
	if q == nil {
		return nil
	}
	return q.done
}

// Close permanently stops the queue.
func (q *DropQueue[T]) Close() {
	if q == nil {
		return
	}
	q.closeMu.Lock()
	defer q.closeMu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.done)
	}
}

// Len returns queued packets.
func (q *DropQueue[T]) Len() int {
	if q == nil {
		return 0
	}
	return len(q.ch)
}
