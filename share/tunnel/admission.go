package tunnel

import (
	"context"
	"errors"
	"io"

	"github.com/jpillora/chisel/share/quota"
	"golang.org/x/crypto/ssh"
)

// SSH rejection messages are stable, safe and free of addresses/credentials.
// They deliberately carry a machine-readable prefix so a new peer can map a
// ResourceShortage rejection to the exact quota category.
const (
	rejectClientQuota = "quota: client limit"
	rejectGlobalQuota = "quota: global capacity"
	rejectTargetQuota = "quota: target limit"
)

func (t *Tunnel) quotaMetrics() *quota.Metrics {
	if t.Config.Metrics != nil {
		return t.Config.Metrics
	}
	return t.Config.Admission.Metrics()
}

// Optional capabilities implemented by *Tunnel. Keeping these out of the base
// sshTunnel interface preserves compatibility with narrow test doubles and
// alternative implementations.
type channelOpener interface {
	openChannel(ctx context.Context, kind quota.Kind, target string, payload []byte) (ssh.Channel, <-chan *ssh.Request, *quota.Lease, error)
}

type streamWrapper interface {
	wrapStream(base io.ReadWriteCloser) io.ReadWriteCloser
}

type trafficConfigProvider interface {
	trafficConfig() quota.Config
}

type metricsProvider interface {
	quotaMetrics() *quota.Metrics
}

func openSSHChannel(t sshTunnel, ctx context.Context, kind quota.Kind, target string, payload []byte) (ssh.Channel, <-chan *ssh.Request, *quota.Lease, error) {
	if o, ok := t.(channelOpener); ok {
		return o.openChannel(ctx, kind, target, payload)
	}
	sshConn := t.getSSH(ctx)
	if sshConn == nil {
		return nil, nil, nil, quota.ErrUnavailable
	}
	ch, reqs, err := sshConn.OpenChannel("chisel", payload)
	return ch, reqs, nil, err
}

func wrapSSHStream(t sshTunnel, base io.ReadWriteCloser) io.ReadWriteCloser {
	if w, ok := t.(streamWrapper); ok {
		return w.wrapStream(base)
	}
	return base
}

func tunnelTrafficConfig(t sshTunnel) quota.Config {
	if c, ok := t.(trafficConfigProvider); ok {
		return c.trafficConfig()
	}
	return quota.Config{}
}

func tunnelMetrics(t sshTunnel) *quota.Metrics {
	if m, ok := t.(metricsProvider); ok {
		return m.quotaMetrics()
	}
	return nil
}

func (t *Tunnel) trafficConfig() quota.Config {
	if m := t.Config.Admission.Manager(); m != nil {
		return m.Config
	}
	return t.Config.Quota.ApplyEnvDefaults().WithDefaults()
}

func (t *Tunnel) installScheduler() {
	cfg := t.trafficConfig()
	if !cfg.Active() || cfg.MaxPendingBytes <= 0 {
		return
	}
	t.scheduler = quota.NewScheduler(cfg, t.quotaMetrics())
}

func (t *Tunnel) closeScheduler() {
	if t.scheduler != nil {
		t.scheduler.Close()
		t.scheduler = nil
	}
}

// wrapStream installs bounded backlog/fair writes when protection is enabled.
// The returned value still implements CloseWrite whenever base does.
func (t *Tunnel) wrapStream(base io.ReadWriteCloser) io.ReadWriteCloser {
	if t.scheduler == nil {
		return base
	}
	hc, ok := base.(quota.HalfCloseConn)
	if !ok {
		return base
	}
	return t.scheduler.Wrap(hc)
}

// openChannel is the single outgoing SSH channel establishment authority.
// Every forward, reverse, proxy and datagram open path must call it so quota
// admission and exactly-once terminal release cannot be bypassed.
func (t *Tunnel) openChannel(ctx context.Context, kind quota.Kind, target string, payload []byte) (ssh.Channel, <-chan *ssh.Request, *quota.Lease, error) {
	sshConn := t.getSSH(ctx)
	if sshConn == nil {
		return nil, nil, nil, quota.ErrUnavailable
	}
	lease, err := t.Config.Admission.Admit(ctx, kind, quota.DirectionOut, target)
	if err != nil {
		return nil, nil, nil, err
	}
	ch, reqs, err := sshConn.OpenChannel("chisel", payload)
	if err != nil {
		t.Debugf("channel open failed: %s", err)
		lease.Release()
		return nil, nil, nil, categorizeOpenError(err)
	}
	return ch, reqs, lease, nil
}

type categorizedOpenError struct {
	category *quota.Error
	cause    error
}

func (e *categorizedOpenError) Error() string { return e.cause.Error() }
func (e *categorizedOpenError) Unwrap() error { return e.cause }

// As exposes both the quota category and the underlying ssh.OpenChannelError
// to callers that need protocol-level compatibility.
func (e *categorizedOpenError) As(target any) bool {
	switch x := target.(type) {
	case **quota.Error:
		*x = e.category
		return true
	case **ssh.OpenChannelError:
		var oe *ssh.OpenChannelError
		if errors.As(e.cause, &oe) {
			*x = oe
			return true
		}
	}
	return false
}

func categorizeOpenError(err error) error {
	var oe *ssh.OpenChannelError
	if !errors.As(err, &oe) {
		return err
	}
	var qe *quota.Error
	switch {
	case oe.Message == rejectClientQuota:
		qe = quota.ErrClientQuota
	case oe.Message == rejectGlobalQuota:
		qe = quota.ErrGlobalQuota
	case oe.Message == rejectTargetQuota:
		qe = quota.ErrTargetQuota
	case oe.Reason == ssh.Prohibited:
		qe = quota.ErrAccessDenied
	case oe.Reason == ssh.ResourceShortage:
		qe = quota.ErrGlobalQuota
	default:
		return err
	}
	return &categorizedOpenError{category: qe, cause: err}
}

func quotaRejectMessage(err error) (ssh.RejectionReason, string) {
	switch quota.CategoryOf(err) {
	case quota.CategoryClient:
		return ssh.ResourceShortage, rejectClientQuota
	case quota.CategoryTarget:
		return ssh.ResourceShortage, rejectTargetQuota
	case quota.CategoryGlobal:
		return ssh.ResourceShortage, rejectGlobalQuota
	case quota.CategoryAccess:
		return ssh.Prohibited, "access denied"
	default:
		return ssh.ResourceShortage, rejectGlobalQuota
	}
}
