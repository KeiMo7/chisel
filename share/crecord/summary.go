package crecord

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Summary aggregates a set of detail records. It is the
// reconciliation point between totals and details: every counter is
// computed by counting detail records, so a summary derived from a
// record set always matches that set's row counts.
type Summary struct {
	SessionsOpened int
	SessionsClosed int
	ChannelsOpened int
	ChannelsClosed int
	Rejects        int
	BytesSent      int64
	BytesReceived  int64
	CloseReasons   map[CloseReason]int
}

// Summarize counts records by kind and type.
func Summarize(recs []Record) Summary {
	s := Summary{CloseReasons: map[CloseReason]int{}}
	for _, r := range recs {
		switch {
		case r.Kind == KindSession && r.Type == TypeOpen:
			s.SessionsOpened++
		case r.Kind == KindSession && r.Type == TypeClose:
			s.SessionsClosed++
			if r.CloseReason != "" {
				s.CloseReasons[r.CloseReason]++
			}
		case r.Kind == KindChannel && r.Type == TypeOpen:
			s.ChannelsOpened++
		case r.Kind == KindChannel && r.Type == TypeClose:
			s.ChannelsClosed++
			s.BytesSent += r.BytesSent
			s.BytesReceived += r.BytesReceived
			if r.CloseReason != "" {
				s.CloseReasons[r.CloseReason]++
			}
		case r.Type == TypeReject:
			s.Rejects++
			if r.CloseReason != "" {
				s.CloseReasons[r.CloseReason]++
			}
		}
	}
	return s
}

// ReadDir reads every channels-*.jsonl segment in dir, in order.
func ReadDir(dir string) ([]Record, error) {
	names, err := filepath.Glob(filepath.Join(dir, segmentPrefix+"*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var all []Record
	for _, name := range names {
		recs, err := ReadFile(name)
		if err != nil {
			return all, err
		}
		all = append(all, recs...)
	}
	return all, nil
}

// ReadFile parses one segment. Lines that do not parse (a partial
// line left by an interrupted write) are skipped. Records are
// deduplicated by ID so rewritten records appear exactly once, and
// the result is stably sorted by timestamp.
func ReadFile(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var recs []Record
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue //partial or corrupt line
		}
		if r.V != FormatVersion {
			return nil, fmt.Errorf("%s: unsupported record version %d", path, r.V)
		}
		if seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		recs = append(recs, r)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		a, b := recs[i].TS, recs[j].TS
		if a.Equal(b) {
			return recs[i].ID < recs[j].ID
		}
		return a.Before(b)
	})
	return recs, nil
}

// InWindow filters records to those timestamped within [from, to).
// A zero bound is open-ended, so callers can query "sessions opened
// in this window" or "channels closed in this window" by type.
func InWindow(recs []Record, from, to time.Time) []Record {
	var out []Record
	for _, r := range recs {
		if !from.IsZero() && r.TS.Before(from) {
			continue
		}
		if !to.IsZero() && !r.TS.Before(to) {
			continue
		}
		out = append(out, r)
	}
	return out
}
