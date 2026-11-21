package tunnel

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/quota"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/sizestr"
	"golang.org/x/crypto/ssh"
)

// sshTunnel exposes a subset of Tunnel to subtypes
type sshTunnel interface {
	getSSH(ctx context.Context) ssh.Conn
}

// Proxy is the inbound portion of a Tunnel
type Proxy struct {
	*cio.Logger
	sshTun sshTunnel
	id     int
	count  int
	remote *settings.Remote
	dialer net.Dialer
	tcp    *net.TCPListener
	udp    *udpListener
	socks  *socksProxy
	mu     sync.Mutex
}

// NewProxy creates a Proxy
func NewProxy(logger *cio.Logger, sshTun sshTunnel, index int, remote *settings.Remote) (*Proxy, error) {
	id := index + 1
	p := &Proxy{
		Logger: logger.Fork("proxy#%s", remote.String()),
		sshTun: sshTun,
		id:     id,
		remote: remote,
	}
	return p, p.listen()
}

func (p *Proxy) listen() error {
	if p.remote.Stdio {
		//TODO check if pipes active?
	} else if p.remote.LocalProto == "tcp" {
		addr, err := net.ResolveTCPAddr("tcp", p.remote.LocalHost+":"+p.remote.LocalPort)
		if err != nil {
			return p.Errorf("resolve: %s", err)
		}
		if p.remote.UDPSocks && addr.Port == 0 {
			return p.Errorf("udpsocks requires a nonzero listening port")
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return p.Errorf("tcp: %s", err)
		}
		p.Infof("Listening")
		p.tcp = l
		if p.remote.UDPSocks {
			p.socks = newSocksProxy(p)
		}
	} else if p.remote.LocalProto == "udp" {
		l, err := listenUDP(p.Logger, p.sshTun, p.remote)
		if err != nil {
			return err
		}
		p.Infof("Listening")
		p.udp = l
	} else {
		return p.Errorf("unknown local proto")
	}
	return nil
}

// Close unbinds the proxy's listeners. proxies which have
// been Run are instead closed by cancelling their context.
func (p *Proxy) Close() error {
	var err error
	if p.tcp != nil {
		err = p.tcp.Close()
	}
	if p.socks != nil && p.socks.udp != nil {
		if e := p.socks.udp.Close(); err == nil {
			err = e
		}
	}
	if p.udp != nil {
		return p.udp.inbound.Close()
	}
	return err
}

// Run enables the proxy and blocks while its active,
// close the proxy by cancelling the context.
func (p *Proxy) Run(ctx context.Context) error {
	if p.remote.Stdio {
		return p.runStdio(ctx)
	} else if p.remote.LocalProto == "tcp" {
		if p.socks != nil {
			return p.socks.run(ctx)
		}
		return p.runTCP(ctx)
	} else if p.remote.LocalProto == "udp" {
		return p.udp.run(ctx)
	}
	panic("should not get here")
}

func (p *Proxy) runStdio(ctx context.Context) error {
	defer p.Infof("Closed")
	for {
		p.pipeRemote(ctx, cio.Stdio)
		select {
		case <-ctx.Done():
			return nil
		default:
			// the connection is not ready yet, keep waiting
		}
	}
}

func (p *Proxy) runTCP(ctx context.Context) error {
	done := make(chan struct{})
	//implements missing net.ListenContext
	go func() {
		select {
		case <-ctx.Done():
			p.tcp.Close()
		case <-done:
		}
	}()
	for {
		src, err := p.tcp.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				//listener closed
				err = nil
			default:
				p.Infof("Accept error: %s", err)
			}
			close(done)
			return err
		}
		if p.socks != nil {
			p.socks.workers.Add(1)
			go p.socks.serve(ctx, src.(*net.TCPConn))
		} else {
			go p.pipeRemote(ctx, src)
		}
	}
}

func (p *Proxy) pipeRemote(ctx context.Context, src io.ReadWriteCloser) {
	//Quota admission happens before any SSH channel is opened, so a
	//saturated channel never consumes a slot on the shared SSH connection.
	//With quotas disabled this returns (nil, nil) and nothing changes.
	lease, err := p.admitQuota(ctx)
	if err != nil {
		//the quota slot is not held yet; reject just this connection
		p.Infof("Quota rejected connection: %s", err)
		src.Close()
		return
	}
	//Release runs on every path below (dial failure, stream error, reset),
	//so a failed forward cannot leak the slot. Nil leases are no-ops.
	defer lease.Release()

	defer src.Close()

	p.mu.Lock()
	p.count++
	cid := p.count
	p.mu.Unlock()

	l := p.Fork("conn#%d", cid)
	l.Debugf("Open")
	sshConn := p.sshTun.getSSH(ctx)
	if sshConn == nil {
		l.Debugf("No remote connection")
		return
	}
	//ssh request for tcp connection for this proxy's remote
	dst, reqs, err := sshConn.OpenChannel("chisel", []byte(p.remote.Remote()))
	if err != nil {
		l.Infof("Stream error: %s", err)
		return
	}
	go ssh.DiscardRequests(reqs)
	//then pipe, through the quota wrapper when enabled. Both src and dst are
	//wrapped but only writes are counted, so each direction counts once.
	var source, target io.ReadWriteCloser = src, dst
	if lease != nil {
		source = lease.Wrap(src)
		target = lease.Wrap(dst)
	}
	s, r := cio.Pipe(source, target)
	l.Debugf("Close (sent %s received %s)", sizestr.ToString(s), sizestr.ToString(r))
}

// admitQuota asks the tunnel-wide quota set for a slot on this remote's
// channel. It returns (nil, nil) when quotas are disabled or the tunnel is
// not a real Tunnel (as in unit tests), keeping the forwarding path unchanged.
func (p *Proxy) admitQuota(ctx context.Context) (*quota.Lease, error) {
	t, ok := p.sshTun.(*Tunnel)
	if !ok || t.Config.Quota == nil {
		return nil, nil
	}
	//the key is the remote's String form (the same "3000=>host:port" label
	//used by the proxy log line), so the same remote keeps its quota across
	//SSH reconnects; the scope separates tenants which declare the same
	//remote (on the server, the authenticated user)
	key := p.remote.String()
	if t.Config.QuotaScope != "" {
		key = t.Config.QuotaScope + "/" + key
	}
	return t.Config.Quota.Acquire(ctx, key)
}
