package tunnel

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jpillora/chisel/share/crecord"
)

// SessionInfo describes the peer of one SSH session for recording
// purposes. Addresses and remotes are redacted by the recorder
// before they are written; nothing here reaches disk in plaintext.
type SessionInfo struct {
	User    string
	Addr    string   //peer address (client: the server URL)
	Remotes []string //encoded remote specs
}

// sessionState holds the recording state of the active SSH session.
type sessionState struct {
	mu      sync.Mutex
	info    SessionInfo
	id      string
	logical string
	opened  time.Time
}

// SetSession describes the next session's peer. It must be called
// before BindSSH; the client calls it once per reconnect attempt,
// the server once per accepted websocket session.
func (t *Tunnel) SetSession(info SessionInfo) {
	t.sess.mu.Lock()
	t.sess.info = info
	t.sess.mu.Unlock()
}

// recordSessionOpen mints a session ID and writes the session-open
// record. No-op when recording is disabled.
func (t *Tunnel) recordSessionOpen() {
	rec := t.Config.Recorder
	if rec == nil {
		return
	}
	t.sess.mu.Lock()
	t.sess.id = rec.NextSessionID()
	t.sess.opened = time.Now()
	info := t.sess.info
	red := rec.Redactor()
	logical := ""
	if red != nil {
		remotes := append([]string(nil), info.Remotes...)
		sort.Strings(remotes)
		logical = red.Token("session|" + info.User + "|" + strings.Join(remotes, ","))
	}
	t.sess.logical = logical
	t.sess.mu.Unlock()
	rr := crecord.Record{
		Type:    crecord.TypeOpen,
		Kind:    crecord.KindSession,
		Session: t.sessionID(),
		Logical: logical,
		User:    info.User,
	}
	if red != nil {
		rr.Peer = red.Token(info.Addr)
		for _, r := range info.Remotes {
			rr.Remotes = append(rr.Remotes, red.Token(r))
		}
	}
	rec.Write(rr)
}

// recordSessionClose writes the session-close record with the
// classified reason for the end of the SSH connection.
func (t *Tunnel) recordSessionClose(err error) {
	rec := t.Config.Recorder
	if rec == nil {
		return
	}
	t.sess.mu.Lock()
	id, logical, opened := t.sess.id, t.sess.logical, t.sess.opened
	t.sess.mu.Unlock()
	if id == "" {
		return
	}
	openedAt := opened.UTC()
	rec.Write(crecord.Record{
		Type:        crecord.TypeClose,
		Kind:        crecord.KindSession,
		Session:     id,
		Logical:     logical,
		OpenedAt:    &openedAt,
		DurationMS:  time.Since(opened).Milliseconds(),
		CloseReason: crecord.ClassifyError(err),
		Error:       sanitizeErr(rec, err),
	})
}

func (t *Tunnel) sessionID() string {
	t.sess.mu.Lock()
	defer t.sess.mu.Unlock()
	return t.sess.id
}

// peerAddr returns the active SSH peer's address without blocking;
// empty when no connection is bound.
func (t *Tunnel) peerAddr() string {
	t.activeConnMut.RLock()
	c := t.activeConn
	t.activeConnMut.RUnlock()
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	return c.RemoteAddr().String()
}

// nextChannelID mints a channel ID inside the current session.
func (t *Tunnel) nextChannelID() string {
	return fmt.Sprintf("%s-c%d", t.sessionID(), t.chanSeq.Add(1))
}

// recordChannelOpen writes a channel-open record. addr fields are
// redacted before writing.
func (t *Tunnel) recordChannelOpen(id, side, remote, src, dst string, opened time.Time) {
	rec := t.Config.Recorder
	if rec == nil {
		return
	}
	rr := crecord.Record{
		Type:    crecord.TypeOpen,
		Kind:    crecord.KindChannel,
		Side:    side,
		Session: t.sessionID(),
		Channel: id,
	}
	if red := rec.Redactor(); red != nil {
		rr.Remote = red.Token(remote)
		rr.Src = red.Token(src)
		rr.Dst = red.Token(dst)
	}
	rec.Write(rr)
}

// recordChannelClose writes the matching channel-close record with
// the cumulative byte counters and the classified close reason.
func (t *Tunnel) recordChannelClose(id string, opened time.Time, sent, recv int64, err error) {
	rec := t.Config.Recorder
	if rec == nil {
		return
	}
	openedAt := opened.UTC()
	rec.Write(crecord.Record{
		Type:          crecord.TypeClose,
		Kind:          crecord.KindChannel,
		Session:       t.sessionID(),
		Channel:       id,
		OpenedAt:      &openedAt,
		DurationMS:    time.Since(opened).Milliseconds(),
		BytesSent:     sent,
		BytesReceived: recv,
		CloseReason:   crecord.ClassifyError(err),
		Error:         sanitizeErr(rec, err),
	})
}

// recordChannelReject writes a reject record for a channel refused
// before establishment (ACL denial, dial failure, disabled feature).
func (t *Tunnel) recordChannelReject(remote string, reason crecord.CloseReason, err error) {
	rec := t.Config.Recorder
	if rec == nil {
		return
	}
	rr := crecord.Record{
		Type:        crecord.TypeReject,
		Kind:        crecord.KindChannel,
		Session:     t.sessionID(),
		Channel:     t.nextChannelID(),
		CloseReason: reason,
		Error:       sanitizeErr(rec, err),
	}
	if red := rec.Redactor(); red != nil {
		rr.Remote = red.Token(remote)
	}
	rec.Write(rr)
}

// sanitizeErr renders an error for a record with every IP address
// (and port) replaced by its redaction token.
func sanitizeErr(rec *crecord.Recorder, err error) string {
	if err == nil {
		return ""
	}
	if red := rec.Redactor(); red != nil {
		return red.Sanitize(err.Error())
	}
	return ""
}
