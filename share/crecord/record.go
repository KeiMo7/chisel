// Package crecord implements chisel's channel records: an opt-in,
// append-only JSONL audit trail of tunnel sessions and forwarded
// connections. Records are redacted (keyed-hash tokens instead of
// plaintext addresses), versioned, fsynced per record, and rotated
// by size or age. Recording is best-effort: failures never affect
// forwarding, failed records are buffered and rewritten later, and
// every record carries a unique ID so rewrites never duplicate.
package crecord

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// FormatVersion is the record format version written into every
// record's "v" field. Readers must switch on "v": later versions
// may add or reinterpret fields, but a v1 record always keeps the
// semantics documented here.
const FormatVersion = 1

// RecordType is the lifecycle event a record describes.
type RecordType string

const (
	// TypeOpen marks the establishment of a session or channel.
	TypeOpen RecordType = "open"
	// TypeClose marks the teardown of a session or channel and
	// carries the cumulative counters and the close reason.
	TypeClose RecordType = "close"
	// TypeReject marks a channel that was refused before it was
	// established (ACL denial, dial failure, disabled capability).
	TypeReject RecordType = "reject"
)

// Kind distinguishes the two granularities of records.
type Kind string

const (
	// KindSession is one SSH session between a client and the server.
	KindSession Kind = "session"
	// KindChannel is one forwarded connection inside a session.
	KindChannel Kind = "channel"
)

// CloseReason classifies why a session or channel ended.
type CloseReason string

const (
	// ReasonPeerClosed: the remote end closed cleanly (incl. EOF).
	ReasonPeerClosed CloseReason = "peer_closed"
	// ReasonTimeout: a keepalive, dial or idle deadline fired.
	ReasonTimeout CloseReason = "timeout"
	// ReasonAuthFailed: authentication or ACL authorization failed.
	ReasonAuthFailed CloseReason = "auth_failed"
	// ReasonProtocolError: the peer spoke an unexpected protocol.
	ReasonProtocolError CloseReason = "protocol_error"
	// ReasonShutdown: this process is shutting down (context cancelled).
	ReasonShutdown CloseReason = "shutdown"
	// ReasonError: any other error.
	ReasonError CloseReason = "error"
)

// Record is one line in a channels-*.jsonl segment file.
//
// Field write timing:
//   - V, ID, Type, Kind, TS, RunID, End: stamped by Recorder.Write
//     for every record.
//   - Session, Logical, User, Peer, Remotes: set at session open
//     (server: after the client's config is validated; client: after
//     the config request is acknowledged) and copied onto the
//     matching session close.
//   - Channel, Side, Remote, Src, Dst: set at channel open (inbound:
//     when the listener accepts; outbound: after the SSH channel is
//     accepted). Remote/Src/Dst are redaction tokens, never plaintext.
//   - OpenedAt, DurationMS, BytesSent, BytesReceived, CloseReason,
//     Error: set only on close/reject records, when the channel or
//     session ends. Byte counters are cumulative for the lifetime of
//     the channel.
type Record struct {
	V      int        `json:"v"`
	ID     string     `json:"id"`
	Type   RecordType `json:"type"`
	Kind   Kind       `json:"kind"`
	TS     time.Time  `json:"ts"`
	RunID  string     `json:"run_id"`
	End    string     `json:"end"` // "server" or "client"
	Side   string     `json:"side,omitempty"`
	User   string     `json:"user,omitempty"`
	Peer   string     `json:"peer,omitempty"`   // redacted
	Remote string     `json:"remote,omitempty"` // redacted
	Src    string     `json:"src,omitempty"`    // redacted
	Dst    string     `json:"dst,omitempty"`    // redacted
	//Remotes lists the session's remotes as redacted tokens.
	Remotes []string `json:"remotes,omitempty"`
	//Session identifies one SSH session; Logical is stable across
	//reconnects of the same logical client configuration.
	Session string `json:"session_id,omitempty"`
	Logical string `json:"logical_id,omitempty"`
	//Channel identifies one forwarded connection within a session.
	Channel       string      `json:"channel_id,omitempty"`
	OpenedAt      *time.Time  `json:"opened_at,omitempty"`
	DurationMS    int64       `json:"duration_ms,omitempty"`
	BytesSent     int64       `json:"bytes_sent,omitempty"`
	BytesReceived int64       `json:"bytes_received,omitempty"`
	CloseReason   CloseReason `json:"close_reason,omitempty"`
	//Error is a sanitized detail string: IP addresses and ports are
	//replaced with redaction tokens before it is written.
	Error string `json:"error,omitempty"`
	//Extra carries optional structured fields. Values that fail to
	//serialize cause the whole record to be skipped and counted.
	Extra map[string]any `json:"extra,omitempty"`
}

// ClassifyError maps an error onto a CloseReason. nil and clean EOF
// mean the peer closed; a cancelled context means local shutdown.
func ClassifyError(err error) CloseReason {
	if err == nil || errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return ReasonPeerClosed
	}
	if errors.Is(err, context.Canceled) {
		return ReasonShutdown
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ReasonTimeout
	}
	m := strings.ToLower(err.Error())
	switch {
	//an unexpected EOF is an abnormal cut, not a clean peer close
	case errors.Is(err, io.ErrUnexpectedEOF), strings.Contains(m, "unexpected eof"),
		strings.Contains(m, "abnormal closure"):
		return ReasonError
	case strings.HasSuffix(m, "eof"):
		return ReasonPeerClosed
	case strings.Contains(m, "timeout"), strings.Contains(m, "deadline"):
		return ReasonTimeout
	case strings.Contains(m, "auth"), strings.Contains(m, "denied"),
		strings.Contains(m, "permission"), strings.Contains(m, "prohibited"):
		return ReasonAuthFailed
	case strings.Contains(m, "protocol"), strings.Contains(m, "handshake"),
		strings.Contains(m, "malformed"):
		return ReasonProtocolError
	}
	return ReasonError
}
