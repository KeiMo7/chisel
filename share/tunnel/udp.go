package tunnel

import (
	"context"
	"encoding/gob"
	"errors"
	"io"
	"sync"

	"github.com/jpillora/chisel/share/quota"
)

type udpPacket struct {
	Src     string
	Payload []byte
}

func init() {
	gob.Register(&udpPacket{})
}

// errDatagramDropped is a local congestion signal.  It is never returned to a
// peer as an establishment error and does not stop the shared receive loop.
var errDatagramDropped = errors.New("datagram queue full")

// udpChannel encodes/decodes udp payloads over a stream
type udpChannel struct {
	r *gob.Decoder
	w *gob.Encoder
	c io.Closer

	// When queue is non-nil, encodes are non-blocking best-effort sends.
	queue *quota.DropQueue[udpPacket]
	lease *quota.Lease

	closeOnce sync.Once
}

func (o *udpChannel) encode(src string, b []byte) error {
	p := udpPacket{Src: src, Payload: b}
	if o.queue != nil {
		if !o.queue.TrySend(p) {
			return errDatagramDropped
		}
		return nil
	}
	return o.w.Encode(p)
}

func (o *udpChannel) encodePacket(p udpPacket) error {
	return o.w.Encode(p)
}

func (o *udpChannel) decode(p *udpPacket) error {
	return o.r.Decode(p)
}

// close releases admission once and closes the underlying channel.
func (o *udpChannel) close() {
	o.closeOnce.Do(func() {
		if o.queue != nil {
			o.queue.Close()
		}
		if o.lease != nil {
			o.lease.Release()
		}
		if o.c != nil {
			_ = o.c.Close()
		}
	})
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
