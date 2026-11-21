package tunnel

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/quota"
	"github.com/jpillora/chisel/share/settings"
)

// TestBindRemotesUnbindsOnPartialFailure verifies that when one remote
// fails to bind, the previously bound listeners are released instead of
// staying bound for the process lifetime.
func TestBindRemotesUnbindsOnPartialFailure(t *testing.T) {
	//occupy a port so the second remote fails to bind
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	_, occupiedPort, _ := net.SplitHostPort(blocker.Addr().String())
	//pick a free port for the first remote
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, freePort, _ := net.SplitHostPort(probe.Addr().String())
	probe.Close()
	//bind: first remote succeeds, second fails
	tun := New(Config{Logger: cio.NewLogger("test"), Inbound: true})
	remotes := []*settings.Remote{}
	for _, s := range []string{
		"127.0.0.1:" + freePort + ":127.0.0.1:1",
		"127.0.0.1:" + occupiedPort + ":127.0.0.1:1",
	} {
		r, err := settings.DecodeRemote(s)
		if err != nil {
			t.Fatal(err)
		}
		remotes = append(remotes, r)
	}
	if err := tun.BindRemotes(context.Background(), remotes); err == nil {
		t.Fatal("expected bind error for occupied port")
	}
	//the first remote's port must be free again
	l, err := net.Listen("tcp", "127.0.0.1:"+freePort)
	if err != nil {
		t.Fatalf("port %s still bound after failed BindRemotes: %v", freePort, err)
	}
	l.Close()
}

// TestProxyQuotaChannelKey checks the quota key is the remote's stable label
// and that a tenant scope prefixes it without changing the remote itself.
func TestProxyQuotaChannelKey(t *testing.T) {
	remote, err := settings.DecodeRemote("3000:example.com:3000")
	if err != nil {
		t.Fatal(err)
	}
	set, err := quota.NewSetForTest(quota.Limits{
		MaxConns:     4,
		MaxQueue:     4,
		Rate:         quota.Rate(quota.DefaultRate),
		QueueTimeout: quota.Duration(time.Second),
	}, "", cio.NewLogger("test"))
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	for _, test := range []struct {
		scope string
		want  string
	}{
		{"", remote.String()},
		{"alice", "alice/" + remote.String()},
	} {
		tun := New(Config{Logger: cio.NewLogger("test"), Quota: set, QuotaScope: test.scope})
		p := &Proxy{Logger: cio.NewLogger("test"), sshTun: tun, remote: remote}
		lease, err := p.admitQuota(context.Background())
		if err != nil {
			t.Fatalf("scope %q: %v", test.scope, err)
		}
		lease.Release()
		found := false
		for _, stat := range set.Stats() {
			found = found || stat.Channel == test.want
		}
		if !found {
			t.Fatalf("scope %q: no channel %q in %+v", test.scope, test.want, set.Stats())
		}
	}
}

// TestProxyQuotaDisabled checks a proxy without a quota set forwards without
// a lease, and that the unit-test sshTunnel implementation is tolerated.
func TestProxyQuotaDisabled(t *testing.T) {
	p := &Proxy{Logger: cio.NewLogger("test"), sshTun: socksTestTunnel{}}
	lease, err := p.admitQuota(context.Background())
	if lease != nil || err != nil {
		t.Fatalf("disabled quota returned %v %v", lease, err)
	}
}
