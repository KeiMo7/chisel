package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/cnet"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// dialChiselSSHAttempt is like dialChiselSSH but returns the handshake
// error instead of failing the test, so negative auth cases can assert.
func dialChiselSSHAttempt(t *testing.T, serverAddr, user, pass string) (ssh.Conn, error) {
	t.Helper()
	ws, _, err := (&websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		Subprotocols:     []string{"chisel-v3"},
	}).Dial("ws://"+serverAddr, http.Header{})
	if err != nil {
		return nil, err
	}
	conn := cnet.NewWebSocketConn(ws)
	sc, _, _, err := ssh.NewClientConn(conn, "", &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		ws.Close()
		return nil, err
	}
	return sc, nil
}

// TestE2ELockoutBlocksHandshakeThenRecovers drives the real
// websocket+SSH path: failures cross the threshold, subsequent attempts
// (including the correct password) never complete a handshake, and the
// lock expires on its own.
func TestE2ELockoutBlocksHandshakeThenRecovers(t *testing.T) {
	srv, err := chserver.NewServer(&chserver.Config{
		KeySeed: "e2e-lockout",
		Auth:    "foo:bar",
		AuthLimit: chserver.AuthLimitConfig{
			SourceFailures:  3,
			AccountFailures: 3,
			Window:          time.Minute,
			Cooldown:        400 * time.Millisecond,
			MaxSources:      1000,
			MaxAccounts:     1000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Debug = false
	port := availablePort()
	if err := srv.Start("127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := "127.0.0.1:" + port

	// three wrong passwords: all fail at the SSH handshake, none ever
	// produces an established connection (judgement precedes completion)
	for i := 0; i < 3; i++ {
		sc, err := dialChiselSSHAttempt(t, addr, "foo", "wrong")
		if err == nil {
			sc.Close()
			t.Fatalf("attempt %d: wrong password completed a handshake", i)
		}
	}

	// the correct password is now also rejected at the handshake. The
	// x/crypto client surfaces authentication failures as a generic
	// inability to authenticate; what matters is that no SSH connection is
	// established (the decision happens before handshake completion) and
	// that the response carries no account-specific detail.
	sc, err := dialChiselSSHAttempt(t, addr, "foo", "bar")
	if err == nil {
		sc.Close()
		t.Fatal("correct password completed a handshake during cooldown")
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("expected an SSH authentication failure, got %T: %v", err, err)
	}

	// a successful connection becomes possible once the cooldown elapses
	deadline := time.Now().Add(5 * time.Second)
	var good ssh.Conn
	for time.Now().Before(deadline) {
		good, err = dialChiselSSHAttempt(t, addr, "foo", "bar")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("login did not recover after cooldown: %v", err)
	}
	defer good.Close()
}

// TestE2ELockoutAdminEndpoint exercises the operator entry point:
// counters are visible and a manual unlock restores access immediately.
func TestE2ELockoutAdminEndpoint(t *testing.T) {
	adminPort := availablePort()
	srv, err := chserver.NewServer(&chserver.Config{
		KeySeed: "e2e-admin",
		Auth:    "foo:bar",
		AuthLimit: chserver.AuthLimitConfig{
			SourceFailures:  2,
			AccountFailures: 2,
			Window:          time.Minute,
			Cooldown:        time.Hour, // long: only manual unlock restores
			MaxSources:      1000,
			MaxAccounts:     1000,
			AdminAddr:       "127.0.0.1:" + adminPort,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	if err := srv.Start("127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	addr := "127.0.0.1:" + port
	admin := "http://127.0.0.1:" + adminPort

	for i := 0; i < 2; i++ {
		if _, err := dialChiselSSHAttempt(t, addr, "foo", "wrong"); err == nil {
			t.Fatal("wrong password accepted")
		}
	}
	if _, err := dialChiselSSHAttempt(t, addr, "foo", "bar"); err == nil {
		t.Fatal("correct password accepted during cooldown")
	}

	// inspect current counters
	resp, err := http.Get(admin + "/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "locked_rejections") {
		t.Fatalf("admin snapshot unusable: status=%d body=%s", resp.StatusCode, body)
	}
	var snap map[string]any
	if err := json.Unmarshal(body, &snap); err != nil {
		t.Fatal(err)
	}
	sources, ok := snap["sources"].([]any)
	if !ok || len(sources) == 0 {
		t.Fatalf("snapshot shows no tracked sources: %s", body)
	}
	first := sources[0].(map[string]any)
	if locked, _ := first["locked"].(bool); !locked {
		t.Fatalf("snapshot taken during cooldown reports unlocked: %s", body)
	}
	if remaining, _ := first["cooldown_remaining_seconds"].(float64); remaining <= 0 {
		t.Fatalf("snapshot reports non-positive remaining cooldown: %s", body)
	}

	// manual unlock via the admin API
	unlockResp, err := http.Post(admin+"/unlock-source?source=127.0.0.1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	unlockResp.Body.Close()
	if unlockResp.StatusCode != http.StatusOK {
		t.Fatalf("unlock status = %d", unlockResp.StatusCode)
	}
	unlockAcct, err := http.Post(admin+"/unlock-account?account=foo", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	unlockAcct.Body.Close()

	// access restored without waiting for the hour-long cooldown
	sc, err := dialChiselSSHAttempt(t, addr, "foo", "bar")
	if err != nil {
		t.Fatalf("manual admin unlock did not restore access: %v", err)
	}
	defer sc.Close()
}

// TestE2ENormalReconnectUnaffected proves the common client path keeps
// working: repeated good connections never trip the limiter.
func TestE2ENormalReconnectUnaffected(t *testing.T) {
	srv, err := chserver.NewServer(&chserver.Config{
		KeySeed: "e2e-reconnect",
		Auth:    "foo:bar",
		AuthLimit: chserver.AuthLimitConfig{
			SourceFailures:  2,
			AccountFailures: 2,
			Window:          time.Minute,
			Cooldown:        time.Minute,
			MaxSources:      1000,
			MaxAccounts:     1000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	if err := srv.Start("127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	for i := 0; i < 5; i++ {
		sc, err := dialChiselSSHAttempt(t, "127.0.0.1:"+port, "foo", "bar")
		if err != nil {
			t.Fatalf("reconnect %d failed: %v", i, err)
		}
		sc.Close()
	}
	if m := srv.AuthLimitSnapshot().Metrics; m.FailedAttempts != 0 || m.LockedRejections != 0 {
		t.Fatalf("clean reconnects touched failure state: %+v", m)
	}
}
