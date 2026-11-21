package crecord

import "time"

// FlagConfig carries the recording CLI flags, embedded into both the
// server and client configurations so both ends accept the same
// options. Recording is off unless Dir is set; when it is off, no
// record files are created.
type FlagConfig struct {
	Dir     string        `opts:"name=record-dir,short=-" help:"Enable channel recording: append one JSON record per tunnel session and forwarded connection to rotating channels-*.jsonl segments in this directory. Addresses in records are redacted with a keyed hash (see --record-key). Recording is best-effort and never interrupts forwarding. Off by default."`
	Key     string        `opts:"name=record-key,short=-" help:"Key material used to redact addresses in channel records (defaults to the CHISEL_RECORD_KEY environment variable, otherwise a random key generated into <record-dir>/record.key). Holders of the key map a record token back to a candidate address by recomputing its token."`
	MaxSize int64         `opts:"name=record-max-size,short=-" help:"Rotate the channel record segment after this many bytes. Defaults to 67108864 (64MiB)."`
	MaxAge  time.Duration `opts:"name=record-max-age,short=-" help:"Rotate the channel record segment after this much time. Defaults to 24h."`
}

// Config converts the flags into a recorder Config for the given
// end ("server" or "client"). keyEnv is the CHISEL_RECORD_KEY
// environment variable value, used when --record-key is unset.
func (f FlagConfig) Config(end, keyEnv string) Config {
	key := f.Key
	if key == "" {
		key = keyEnv
	}
	return Config{
		Dir:     f.Dir,
		Key:     key,
		MaxSize: f.MaxSize,
		MaxAge:  f.MaxAge,
		End:     end,
	}
}

// Enabled reports whether recording was requested.
func (f FlagConfig) Enabled() bool {
	return f.Dir != ""
}
