package crecord

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is not a test; it is the subprocess body for
// TestSIGKILLLeavesOnlyCompleteRecords. It writes records, signals
// readiness, and then waits to be SIGKILLed without ever calling
// Close.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	dir := os.Args[len(os.Args)-1]
	r, err := New(Config{Dir: dir, Key: "k"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i := 0; i < 100; i++ {
		r.Write(Record{Type: TypeOpen, Kind: KindChannel, Channel: fmt.Sprintf("c%d", i)})
	}
	fmt.Println("READY")
	select {} //killed by the parent
}

// TestSIGKILLLeavesOnlyCompleteRecords kills a recording process
// with SIGKILL and asserts every produced record is complete on
// disk: no partial lines, nothing left unflushed.
func TestSIGKILLLeavesOnlyCompleteRecords(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", dir)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if s.Text() == "READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("helper exited before READY")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper did not become ready")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	//every produced record must be complete on disk
	recs, err := ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 100 {
		t.Fatalf("expected 100 complete records after SIGKILL, got %d", len(recs))
	}
	//and the raw file must contain no partial (unparseable) line
	names, _ := filepath.Glob(filepath.Join(dir, segmentPrefix+"*.jsonl"))
	if len(names) != 1 {
		t.Fatalf("expected one segment, got %v", names)
	}
	b, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("partial line after SIGKILL: %q", line)
		}
		lines++
	}
	if lines != 100 {
		t.Fatalf("expected 100 raw lines, got %d", lines)
	}
}
