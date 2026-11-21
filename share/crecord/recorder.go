package crecord

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jpillora/chisel/share/cio"
)

// Defaults for segment rotation and the rewrite buffer.
const (
	DefaultMaxSize    = 64 << 20 //64MiB per segment
	DefaultMaxAge     = 24 * time.Hour
	maxPendingRecords = 4096
	//keyFileName stores the generated redaction key inside Dir.
	keyFileName = "record.key"
	//segmentPrefix names every segment file in Dir.
	segmentPrefix = "channels-"
)

// Config configures a Recorder. Dir is required; all other fields
// have defaults. Recording IO is best-effort: an unwritable Dir
// downgrades the Recorder to buffering mode (records are retried in
// the background) instead of failing, so forwarding is never
// interrupted by recording problems.
type Config struct {
	//Dir receives the channels-*.jsonl segment files.
	Dir string
	//Key is the redaction key material. When empty, the key is read
	//from <Dir>/record.key, or generated and written there (mode
	//0600). When the directory is not writable, an ephemeral key is
	//used and a warning is logged.
	Key string
	//MaxSize rotates the current segment after this many bytes.
	MaxSize int64
	//MaxAge rotates the current segment after this much time.
	MaxAge time.Duration
	//End is stamped onto every record: "server" or "client".
	End string
	//Logger receives recording warnings. Nil discards them.
	Logger *cio.Logger
}

// Recorder writes versioned, redacted JSONL records. All methods are
// safe to call on a nil *Recorder (recording disabled) and from
// concurrent goroutines.
type Recorder struct {
	cfg      Config
	log      *cio.Logger
	redactor *Redactor
	runID    string
	end      string

	recSeq  atomic.Int64
	sessSeq atomic.Int64
	dropped atomic.Int64

	mu         sync.Mutex
	file       *os.File
	segStart   time.Time
	segSize    int64
	segSeq     int
	lastOpen   time.Time
	pending    [][]byte
	warnedOpen bool
	closed     bool
}

// New creates a Recorder. It only fails on a configuration error
// (empty Dir); IO problems put the recorder into degraded
// (buffer-and-retry) mode and are reported through the logger.
func New(cfg Config) (*Recorder, error) {
	if cfg.Dir == "" {
		return nil, errors.New("crecord: Dir is required")
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	l := cfg.Logger
	if l == nil {
		l = cio.NewLogger("record")
	}
	r := &Recorder{
		cfg: cfg,
		log: l.Fork("record"),
		end: cfg.End,
	}
	r.runID = "r" + randomHex(8)
	//redaction key: explicit config, else the key file in Dir, else
	//(degraded) an ephemeral key for this process only
	key := cfg.Key
	if key == "" {
		key = r.loadOrCreateKey()
	}
	if key == "" {
		key = "ephemeral-" + randomHex(16)
		r.log.Infof("WARNING: record directory %s not usable yet (%s); "+
			"buffering records and using an ephemeral redaction key",
			cfg.Dir, r.openErrHint())
	}
	r.redactor = NewRedactor([]byte(key))
	//best-effort: open the first segment now so an immediately
	//writable directory starts recording at once
	r.mu.Lock()
	r.ensureFileLocked()
	r.mu.Unlock()
	return r, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (r *Recorder) openErrHint() string {
	if err := os.MkdirAll(r.cfg.Dir, 0755); err != nil {
		return err.Error()
	}
	probe, err := os.CreateTemp(r.cfg.Dir, ".probe")
	if err != nil {
		return err.Error()
	}
	probe.Close()
	os.Remove(probe.Name())
	return "unknown"
}

// loadOrCreateKey reads <Dir>/record.key, creating it (mode 0600)
// when missing. Returns "" when the directory is not usable.
func (r *Recorder) loadOrCreateKey() string {
	path := filepath.Join(r.cfg.Dir, keyFileName)
	if b, err := os.ReadFile(path); err == nil {
		if k := strings.TrimSpace(string(b)); k != "" {
			return k
		}
	}
	if err := os.MkdirAll(r.cfg.Dir, 0755); err != nil {
		return ""
	}
	key := randomHex(32)
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		return ""
	}
	return key
}

// Redactor returns the recorder's redactor, or nil when disabled.
func (r *Recorder) Redactor() *Redactor {
	if r == nil {
		return nil
	}
	return r.redactor
}

// RunID identifies this process run across all of its records.
func (r *Recorder) RunID() string {
	if r == nil {
		return ""
	}
	return r.runID
}

// NextSessionID mints a session ID unique within this run.
func (r *Recorder) NextSessionID() string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("%s-s%d", r.runID, r.sessSeq.Add(1))
}

// Dropped reports how many records were skipped (serialization
// failures plus rewrite-buffer overflow).
func (r *Recorder) Dropped() int64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

// Write stamps and appends one record. It never blocks the caller on
// recording problems: serialization failures are skipped and counted,
// IO failures are buffered for a later rewrite (records carry unique
// IDs, so a rewrite never produces a duplicate).
func (r *Recorder) Write(rec Record) {
	if r == nil {
		return
	}
	rec.V = FormatVersion
	rec.ID = fmt.Sprintf("%s-%d", r.runID, r.recSeq.Add(1))
	rec.TS = time.Now().UTC()
	rec.RunID = r.runID
	rec.End = r.end
	line, err := json.Marshal(rec)
	if err != nil {
		r.dropped.Add(1)
		r.log.Infof("WARNING: dropped unserializable %s/%s record: %s",
			rec.Kind, rec.Type, err)
		return
	}
	r.append(append(line, '\n'))
}

func (r *Recorder) append(line []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.dropped.Add(1)
		return
	}
	if r.ensureFileLocked() != nil {
		r.enqueueLocked(line)
		return
	}
	r.flushPendingLocked()
	if err := r.writeLineLocked(line); err != nil {
		r.enqueueLocked(line)
	}
}

// ensureFileLocked opens a segment when none is open, at most once
// per second, so a persistently unwritable directory costs one
// failed open attempt per second rather than one per record.
func (r *Recorder) ensureFileLocked() error {
	if r.file != nil {
		return nil
	}
	if time.Since(r.lastOpen) < time.Second {
		return errors.New("open throttled")
	}
	r.lastOpen = time.Now()
	if err := os.MkdirAll(r.cfg.Dir, 0755); err != nil {
		r.warnOpen(err)
		return err
	}
	r.segSeq++
	name := fmt.Sprintf("%s%s-%04d.jsonl",
		segmentPrefix, time.Now().UTC().Format("20060102T150405"), r.segSeq)
	f, err := os.OpenFile(filepath.Join(r.cfg.Dir, name),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		r.warnOpen(err)
		return err
	}
	r.file = f
	r.segStart = time.Now()
	r.segSize = 0
	r.warnedOpen = false
	return nil
}

func (r *Recorder) warnOpen(err error) {
	if !r.warnedOpen {
		r.warnedOpen = true
		r.log.Infof("WARNING: cannot write records in %s (%s); buffering for rewrite", r.cfg.Dir, err)
	}
}

// rotateLocked closes the current segment; the next write opens a
// fresh one. Rotation bypasses the open throttle: the directory was
// writable a moment ago, so the new segment opens immediately.
func (r *Recorder) rotateLocked() {
	if r.file != nil {
		r.file.Sync()
		r.file.Close()
		r.file = nil
	}
	r.lastOpen = time.Time{}
}

// writeLineLocked appends one complete line and fsyncs it, so a
// SIGKILL can never leave a half-written or unflushed record behind.
func (r *Recorder) writeLineLocked(line []byte) error {
	if r.segSize+int64(len(line)) > r.cfg.MaxSize ||
		time.Since(r.segStart) > r.cfg.MaxAge {
		r.rotateLocked()
		if err := r.ensureFileLocked(); err != nil {
			return err
		}
	}
	n, err := r.file.Write(line)
	if err != nil {
		r.file.Close()
		r.file = nil
		r.log.Infof("WARNING: record write failed (%s); buffering for rewrite", err)
		return err
	}
	r.segSize += int64(n)
	r.file.Sync()
	return nil
}

// flushPendingLocked rewrites buffered records ahead of new ones.
// Records keep their original IDs, so a record that actually reached
// disk despite a reported error is still written only once.
func (r *Recorder) flushPendingLocked() {
	for len(r.pending) > 0 {
		if err := r.writeLineLocked(r.pending[0]); err != nil {
			return
		}
		r.pending = r.pending[1:]
	}
}

func (r *Recorder) enqueueLocked(line []byte) {
	if len(r.pending) >= maxPendingRecords {
		r.pending = r.pending[1:]
		r.dropped.Add(1)
	}
	r.pending = append(r.pending, line)
}

// Close flushes buffered records and closes the segment. Records
// written after Close are counted as dropped. Because every record
// is fsynced at write time, Close is only needed to flush the
// rewrite buffer; durability never depends on it.
func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	var err error
	if r.file == nil && len(r.pending) > 0 {
		//final attempt to land buffered records, bypassing the
		//open throttle
		r.lastOpen = time.Time{}
		r.ensureFileLocked()
	}
	if r.file != nil {
		r.flushPendingLocked()
		err = r.file.Sync()
		r.file.Close()
		r.file = nil
	}
	if len(r.pending) > 0 {
		r.dropped.Add(int64(len(r.pending)))
		r.pending = nil
	}
	return err
}
