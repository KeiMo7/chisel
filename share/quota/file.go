package quota

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/sizestr"
)

// File is the on-disk quota configuration. Channel keys are stable remote
// encodings (the same string shown by the proxy logger, e.g.
// "3000=>example.com:3000"). Per-channel entries are overlaid on the file
// defaults and then on the global CLI defaults, so a file may tune one
// channel without repeating the rest. An absent field inherits; an explicit
// zero or out-of-range value is a startup error.
type File struct {
	Defaults Limits            `json:"defaults"`
	Channels map[string]Limits `json:"channels"`
}

// limitsJSON mirrors Limits with pointer fields so an absent field can
// inherit while an explicitly written invalid value is rejected.
type limitsJSON struct {
	MaxConns     *int      `json:"max-conns"`
	MaxQueue     *int      `json:"max-queue"`
	Rate         *Rate     `json:"rate"`
	QueueTimeout *Duration `json:"queue-timeout"`
	IdleTimeout  *Duration `json:"idle-timeout"`
}

func (l limitsJSON) resolve() Limits {
	out := Limits{}
	if l.MaxConns != nil {
		out.MaxConns = *l.MaxConns
	}
	if l.MaxQueue != nil {
		out.MaxQueue = *l.MaxQueue
	}
	if l.Rate != nil {
		out.Rate = *l.Rate
	}
	if l.QueueTimeout != nil {
		out.QueueTimeout = *l.QueueTimeout
	}
	if l.IdleTimeout != nil {
		out.IdleTimeout = *l.IdleTimeout
	}
	return out
}

// validatePresent validates only the fields actually present in the file.
func (l limitsJSON) validatePresent() error {
	if l.MaxConns != nil && (*l.MaxConns < 1 || *l.MaxConns > MaxConns) {
		return fmt.Errorf("max-conns must be between 1 and %d (got %d)", MaxConns, *l.MaxConns)
	}
	if l.MaxQueue != nil && (*l.MaxQueue < 1 || *l.MaxQueue > MaxQueue) {
		return fmt.Errorf("max-queue must be between 1 and %d (got %d)", MaxQueue, *l.MaxQueue)
	}
	if l.Rate != nil && (*l.Rate < 1 || int64(*l.Rate) > MaxRate) {
		return fmt.Errorf("rate must be between 1B and %s per second (got %s)",
			sizestr.ToString(MaxRate), *l.Rate)
	}
	if l.QueueTimeout != nil && time.Duration(*l.QueueTimeout) <= 0 {
		return fmt.Errorf("queue-timeout must be greater than zero (got %s)", *l.QueueTimeout)
	}
	if l.IdleTimeout != nil && time.Duration(*l.IdleTimeout) < 0 {
		return fmt.Errorf("idle-timeout must be zero or positive (got %s)", *l.IdleTimeout)
	}
	return nil
}

type fileJSON struct {
	Defaults *limitsJSON           `json:"defaults"`
	Channels map[string]limitsJSON `json:"channels"`
}

// parsedFile is a validated quota file. Zero fields mean "inherit", so the
// effective limits for a channel are channels[ch].Overlay(defaults).
type parsedFile struct {
	defaults Limits
	channels map[string]Limits
}

// ParseFile decodes and validates a quota file. It rejects unknown fields,
// trailing data, empty channel keys, and explicit out-of-range values.
func ParseFile(b []byte) (*parsedFile, error) {
	var raw fileJSON
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid JSON: unexpected trailing data")
	}
	out := &parsedFile{channels: map[string]Limits{}}
	if raw.Defaults != nil {
		if err := raw.Defaults.validatePresent(); err != nil {
			return nil, fmt.Errorf("defaults: %w", err)
		}
		out.defaults = raw.Defaults.resolve()
	}
	for channel, limits := range raw.Channels {
		if channel == "" {
			return nil, fmt.Errorf("empty channel key")
		}
		if err := limits.validatePresent(); err != nil {
			return nil, fmt.Errorf("channel %q: %w", channel, err)
		}
		out.channels[channel] = limits.resolve()
	}
	return out, nil
}

// LoadFile reads and validates path.
func LoadFile(path string) (*parsedFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("quota file: %w", err)
	}
	f, err := ParseFile(b)
	if err != nil {
		return nil, fmt.Errorf("quota file %s: %w", path, err)
	}
	return f, nil
}

// Provider owns the optional hot-reloadable quota file. Set resolves the
// reported overrides against the live global defaults.
type Provider struct {
	path     string
	log      *cio.Logger
	onChange func()

	mu     sync.Mutex
	file   parsedFile
	closed bool
	stop   chan struct{}
	once   sync.Once
}

// NewProvider loads and validates path (when non-empty) and starts watching
// it. An invalid file is a startup error.
func NewProvider(path string, log *cio.Logger, onChange func()) (*Provider, error) {
	if log == nil {
		log = cio.NewLogger("quota")
	}
	p := &Provider{
		path:     path,
		log:      log.Fork("quota"),
		onChange: onChange,
		stop:     make(chan struct{}),
		file:     parsedFile{channels: map[string]Limits{}},
	}
	if path == "" {
		return p, nil
	}
	if err := p.load(); err != nil {
		return nil, err
	}
	if err := p.watch(); err != nil {
		return nil, err
	}
	return p, nil
}

// Override returns the file's overrides for a channel, already overlaid on
// the file defaults. Zero fields still inherit the global defaults.
func (p *Provider) Override(channel string) (Limits, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	override, ok := p.file.channels[channel]
	if !ok {
		if p.file.defaults.Unset() {
			return Limits{}, false
		}
		return p.file.defaults, true
	}
	return override.Overlay(p.file.defaults), true
}

// Reload rereads the file and applies it. An invalid update is logged and
// ignored, leaving the previous limits in force.
func (p *Provider) Reload() error {
	if p.path == "" {
		return nil
	}
	if err := p.load(); err != nil {
		return err
	}
	p.log.Infof("Quota file reloaded from %s", p.path)
	if p.onChange != nil {
		p.onChange()
	}
	return nil
}

// Close stops the file watcher.
func (p *Provider) Close() {
	p.once.Do(func() { close(p.stop) })
}

func (p *Provider) load() error {
	f, err := LoadFile(p.path)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.file = *f
	p.mu.Unlock()
	return nil
}

func (p *Provider) watch() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("quota file watcher: %w", err)
	}
	path, err := filepath.Abs(p.path)
	if err != nil {
		watcher.Close()
		return err
	}
	//watch the directory so tmp+rename saves and configmap swaps are seen
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		watcher.Close()
		return fmt.Errorf("quota file watcher: %w", err)
	}
	go func() {
		defer watcher.Close()
		const debounce = 100 * time.Millisecond
		timer := time.NewTimer(debounce)
		timer.Stop()
		defer timer.Stop()
		for {
			select {
			case <-p.stop:
				return
			case e, ok := <-watcher.Events:
				if !ok {
					return
				}
				if e.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
					continue
				}
				if eventPath, err := filepath.Abs(e.Name); err == nil && eventPath == path {
					timer.Reset(debounce)
				}
			case <-timer.C:
				if err := p.Reload(); err != nil {
					p.log.Infof("Ignoring quota file update: %s", err)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				p.log.Infof("Quota file watcher error: %s", err)
			}
		}
	}()
	return nil
}
