package chserver

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jpillora/chisel/server/authlimit"
	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/requestlog"
	"golang.org/x/crypto/ssh"
)

// Config is the configuration for the chisel service
type Config struct {
	KeySeed   string        `opts:"name=key,short=-" help:"(deprecated use --keygen and --keyfile instead) An optional string to seed the generation of a ECDSA public and private key pair. All communications will be secured using this key pair. Share the subsequent fingerprint with clients to enable detection of man-in-the-middle attacks (defaults to the CHISEL_KEY environment variable, otherwise a new key is generate each run)."`
	KeyFile   string        `opts:"name=keyfile,short=-" help:"An optional path to a PEM-encoded SSH private key. When this flag is set, the --key option is ignored, and the provided private key is used to secure all communications. (defaults to the CHISEL_KEY_FILE environment variable). Since ECDSA keys are short, you may also set keyfile to the inline key string itself, exactly as printed by --keygen (a base64 string with a \"ck-\" prefix); no extra base64 encoding is needed."`
	AuthFile  string        `opts:"name=authfile,short=-" help:"An optional path to a users.json file. This file should be an object with users defined like:\n  {\n    \"<user:pass>\": [\"<addr-regex>\",\"<addr-regex>\"]\n  }\nwhen <user> connects, their <pass> will be verified and then each of the remote addresses will be compared against the list of address regular expressions for a match. Patterns are NOT anchored by default: \"10.0.0.1:80\" also matches \"210.0.0.1:8080\", and \".\" matches any character. Anchor your patterns, e.g. \"^10\\.0\\.0\\.1:80$\". The empty string \"\" matches every address. Addresses will always come in the form \"<remote-host>:<remote-port>\" for normal remotes, \"R:<local-interface>:<local-port>\" for reverse port forwarding remotes, and \"socks\" for SOCKS5 proxy access. Note that SOCKS5 access previously bypassed this list; existing authfiles which should allow SOCKS5 must add an entry matching \"socks\" (the empty wildcard \"\" matches everything, including \"socks\"). This file will be automatically reloaded on change. Reloads apply to new connections and to new tunnels of connected clients; established tunnels are not interrupted."`
	Auth      string        `opts:"name=auth,short=-" help:"An optional string representing a single user with full access, in the form of <user:pass>. It is equivalent to creating an authfile with {\"<user:pass>\": [\"\"]}. If unset, it will use the environment variable AUTH."`
	Proxy     string        `opts:"name=backend,short=-" help:"Specifies another HTTP server to proxy requests to when chisel receives a normal HTTP request. Useful for hiding chisel in plain sight. --proxy is accepted as an alias for this flag."`
	Socks5    bool          `opts:"name=socks5,short=-" help:"Allow clients to access the internal SOCKS5 proxy. See chisel client --help for more information."`
	Reverse   bool          `opts:"name=reverse,short=-" help:"Allow clients to specify reverse port forwarding remotes in addition to normal remotes."`
	KeepAlive time.Duration `opts:"name=keepalive,short=-" help:"An optional keepalive interval. Since the underlying transport is HTTP, in many instances we'll be traversing through proxies, often these proxies will close idle connections. You must specify a time with a unit, for example '5s' or '2m'. Defaults to '25s' (set to 0s to disable)."`
	// AuthLimit tunes authentication failure lockouts. The zero value is
	// replaced with safe defaults in NewServer when any authentication is
	// configured; it is inert when authentication is disabled.
	AuthLimit AuthLimitConfig `opts:"mode=embedded"`
	TLS       TLSConfig       `opts:"mode=embedded"`
}

// AuthLimitConfig controls the in-memory authentication failure limiter.
// Failures are counted per source address and per account over a sliding
// window; crossing a threshold arms a cooldown during which every attempt
// (including correct passwords) is rejected before the SSH handshake
// completes. All state is in-memory and is lost on restart.
type AuthLimitConfig struct {
	SourceFailures  int           `opts:"name=auth-limit-source-failures,short=-" help:"Number of failed authentications from one source address within the auth-limit window before the source is put into cooldown. Default 10 (env CHISEL_AUTH_LIMIT_SOURCE_FAILURES)."`
	AccountFailures int           `opts:"name=auth-limit-account-failures,short=-" help:"Number of failed authentications against one account within the auth-limit window before the account is put into cooldown. Default 10 (env CHISEL_AUTH_LIMIT_ACCOUNT_FAILURES)."`
	Window          time.Duration `opts:"name=auth-limit-window,short=-" help:"Sliding window over which authentication failures are counted. Default 5m (env CHISEL_AUTH_LIMIT_WINDOW)."`
	Cooldown        time.Duration `opts:"name=auth-limit-cooldown,short=-" help:"Duration of the cooldown armed when a failure threshold is crossed. During cooldown every attempt is rejected, including attempts with the correct password. Default 10m (env CHISEL_AUTH_LIMIT_COOLDOWN)."`
	MaxSources      int           `opts:"name=auth-limit-max-sources,short=-" help:"Maximum number of source addresses whose failure state is tracked. Default 10000 (env CHISEL_AUTH_LIMIT_MAX_SOURCES). When the cap is hit, expired then oldest-unlocked entries are evicted and an alert is logged; locked entries are never evicted."`
	MaxAccounts     int           `opts:"name=auth-limit-max-accounts,short=-" help:"Maximum number of accounts whose failure state is tracked. Default 10000 (env CHISEL_AUTH_LIMIT_MAX_ACCOUNTS). Eviction behaves like --auth-limit-max-sources."`
	// AdminAddr optionally enables a local operator HTTP endpoint on the
	// given host:port for viewing counters and manually clearing cooldowns.
	// Empty disables it. Intended to be bound to localhost.
	AdminAddr string `opts:"name=auth-admin,short=-" help:"Optional host:port for the local authentication-lockout administration endpoint (view current counters and clear cooldowns). Disabled by default (env CHISEL_AUTH_ADMIN); bind to localhost only."`
}

// Server represent a chisel service
type Server struct {
	*cio.Logger
	config       *Config
	fingerprint  string
	httpServer   *cnet.HTTPServer
	reverseProxy *httputil.ReverseProxy
	sessCount    int32
	sshConfig    *ssh.ServerConfig
	users        *settings.UserIndex
	authLimiter  *authlimit.Limiter
	authAdmin    *authAdmin
	adminCancel  context.CancelFunc
}

var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  settings.EnvInt("WS_BUFF_SIZE", 0),
	WriteBufferSize: settings.EnvInt("WS_BUFF_SIZE", 0),
}

// NewServer creates and returns a new chisel server
func NewServer(c *Config) (*Server, error) {
	server := &Server{
		config:     c,
		httpServer: cnet.NewHTTPServer(),
		Logger:     cio.NewLogger("server"),
	}
	server.Info = true
	server.users = settings.NewUserIndex(server.Logger)
	//pin the --auth user first so authfile reloads cannot drop it
	if c.Auth != "" {
		u := &settings.User{Addrs: []*regexp.Regexp{settings.UserAllowAll}}
		u.Name, u.Pass = settings.ParseAuth(c.Auth)
		if u.Name == "" {
			return nil, server.Errorf("invalid auth string, expected <user>:<pass>")
		}
		server.users.PinUser(u)
	}
	if c.AuthFile != "" {
		if err := server.users.LoadUsers(c.AuthFile); err != nil {
			return nil, err
		}
	}

	// Build the authentication failure limiter. It only participates when
	// user authentication is enabled (see authUser's allow-all shortcut),
	// so no-auth deployments keep their existing behaviour exactly.
	if err := validateAuthLimitInputs(c.AuthLimit); err != nil {
		return nil, server.Errorf("%s", err)
	}
	limiterCfg := authLimitConfig(c.AuthLimit)
	if err := limiterCfg.Validate(); err != nil {
		return nil, server.Errorf("%s", err)
	}
	limiter, err := authlimit.New(limiterCfg, server.Logger)
	if err != nil {
		return nil, server.Errorf("%s", err)
	}
	server.authLimiter = limiter

	var pemBytes []byte
	if c.KeyFile != "" {
		var key []byte

		if ccrypto.IsChiselKey([]byte(c.KeyFile)) {
			key = []byte(c.KeyFile)
		} else {
			key, err = os.ReadFile(c.KeyFile)
			if err != nil {
				return nil, server.Errorf("Failed to read key file %s: %s", c.KeyFile, err)
			}
		}

		pemBytes = key
		if ccrypto.IsChiselKey(key) {
			pemBytes, err = ccrypto.ChiselKey2PEM(key)
			if err != nil {
				return nil, server.Errorf("Invalid chisel key: %s", err)
			}
		}
	} else {
		//generate private key (optionally using seed)
		pemBytes, err = ccrypto.Seed2PEM(c.KeySeed)
		if err != nil {
			return nil, server.Errorf("Failed to generate key: %s", err)
		}
	}

	//convert into ssh.PrivateKey
	private, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, server.Errorf("Failed to parse key: %s", err)
	}
	//fingerprint this key
	server.fingerprint = ccrypto.FingerprintKey(private.PublicKey())
	//create ssh config
	server.sshConfig = &ssh.ServerConfig{
		ServerVersion:    "SSH-" + chshare.ProtocolVersion + "-server",
		PasswordCallback: server.authUser,
	}
	server.sshConfig.AddHostKey(private)
	//setup reverse proxy
	if c.Proxy != "" {
		u, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, err
		}
		if u.Host == "" {
			return nil, server.Errorf("Missing protocol (%s)", u)
		}
		server.reverseProxy = httputil.NewSingleHostReverseProxy(u)
		//always use proxy host
		server.reverseProxy.Director = func(r *http.Request) {
			//enforce origin, keep path
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
			r.Host = u.Host
		}
	}
	//print when reverse tunnelling is enabled
	if c.Reverse {
		server.Infof("Reverse tunnelling enabled")
	}
	return server, nil
}

// Run is responsible for starting the chisel service.
// Internally this calls Start then Wait.
func (s *Server) Run(host, port string) error {
	if err := s.Start(host, port); err != nil {
		return err
	}
	return s.Wait()
}

// Start is responsible for kicking off the http server
func (s *Server) Start(host, port string) error {
	return s.StartContext(context.Background(), host, port)
}

// StartContext is responsible for kicking off the http server,
// and can be closed by cancelling the provided context
func (s *Server) StartContext(ctx context.Context, host, port string) error {
	s.Infof("Fingerprint %s", s.fingerprint)
	if s.users.Len() > 0 {
		eff := authLimitConfig(s.config.AuthLimit)
		s.Infof("User authentication enabled")
		s.Infof("Auth failure lockout: %d failures/source or %d failures/account "+
			"within %s arms a %s cooldown",
			eff.SourceFailures, eff.AccountFailures, eff.Window, eff.Cooldown)
	}
	if s.reverseProxy != nil {
		s.Infof("Reverse proxy enabled")
	}
	//start the background reaper and optional admin endpoint for the
	//in-memory auth failure store; both are inert when auth is disabled
	reaperCtx, cancel := context.WithCancel(ctx)
	s.adminCancel = cancel
	s.authLimiter.StartReaper(reaperCtx, time.Minute)
	if s.config.AuthLimit.AdminAddr != "" {
		if err := s.startAuthAdmin(reaperCtx); err != nil {
			cancel()
			return err
		}
	}
	l, err := s.listener(host, port)
	if err != nil {
		cancel()
		return err
	}
	h := http.Handler(http.HandlerFunc(s.handleClientHandler))
	if s.Debug {
		o := requestlog.DefaultOptions
		o.TrustProxy = true
		h = requestlog.WrapWith(h, o)
	}
	return s.httpServer.GoServe(ctx, l, h)
}

// Wait waits for the http server to close
func (s *Server) Wait() error {
	return s.httpServer.Wait()
}

// Close forcibly closes the http server
func (s *Server) Close() error {
	if s.adminCancel != nil {
		s.adminCancel()
	}
	return s.httpServer.Close()
}

// UnlockSource clears a source address's cooldown and failure history so
// operators can manually restore a blocked source. Returns whether the
// source was tracked.
func (s *Server) UnlockSource(source string) bool {
	return s.authLimiter.UnlockSource(source)
}

// UnlockAccount clears an account's cooldown and failure history so
// operators can manually restore a locked account. Returns whether the
// account was tracked.
func (s *Server) UnlockAccount(account string) bool {
	return s.authLimiter.UnlockAccount(account)
}

// AuthLimitSnapshot returns a point-in-time copy of the lockout counters
// and tracked entries for inspection.
func (s *Server) AuthLimitSnapshot() authlimit.Snapshot {
	return s.authLimiter.Snapshot()
}

// GetFingerprint is used to access the server fingerprint
func (s *Server) GetFingerprint() string {
	return s.fingerprint
}

// authUser is responsible for validating the ssh user / password combination
func (s *Server) authUser(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	// check if user authentication is enabled and if not, allow all
	if s.users.Len() == 0 {
		return nil, nil
	}
	n := c.User()
	source := authlimit.SourceKey(c.RemoteAddr())

	// Evaluate existing cooldowns first. A locked source or account is
	// rejected before any state changes, and the response text is
	// independent of whether the username exists, so a locked source
	// cannot probe account existence.
	decision := s.authLimiter.Evaluate(source, n)
	if decision.SourceLocked {
		s.Infof("Login rejected: source %s is in cooldown (%s remaining)",
			source, roundRemain(decision.SourceRemaining))
		return nil, fmt.Errorf("authentication temporarily unavailable from this source, retry in %s",
			roundRemain(decision.SourceRemaining))
	}
	if decision.AccountLocked {
		s.Infof("Login rejected: account %q is in cooldown (%s remaining)",
			n, roundRemain(decision.AccountRemaining))
		return nil, fmt.Errorf("authentication temporarily unavailable for this account, retry in %s",
			roundRemain(decision.AccountRemaining))
	}

	// check the user exists and has matching password. The comparison
	// always runs (including for unknown users, against a nil slice) so
	// the control-flow timing does not advertise account existence.
	user, found := s.users.Get(n)
	passwordOK := found && subtle.ConstantTimeCompare([]byte(user.Pass), password) == 1
	if !passwordOK {
		// record on both dimensions; an internal state error fails closed
		if _, _, _, _, err := s.authLimiter.RecordFailure(source, n); err != nil {
			s.Infof("Login failed for user %q (%s); auth limiter internal error: %s", n, source, err)
			return nil, fmt.Errorf("internal authentication failure, retry later")
		}
		//info level: operators should see failed attempts (#521).
		//Never log the password, its length, or any derived material.
		s.Infof("Login failed for user %q (%s)", n, source)
		return nil, fmt.Errorf("invalid authentication for username: %s", n)
	}

	// correct password: clear this account's failure history; the source
	// counter stays and decays with the window on its own
	s.authLimiter.RecordSuccess(source, n)
	// pass the username through to the handshake handler, which
	// re-resolves the user (no session state to leak or race)
	return &ssh.Permissions{
		Extensions: map[string]string{"user": n},
	}, nil
}

// roundRemain renders a cooldown remainder at second granularity so logs
// and error messages stay stable across repeated calls.
func roundRemain(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d.Round(time.Second)
}

// validateAuthLimitInputs rejects explicitly-illegal (negative) values
// before zero fields are replaced with defaults. A zero value means
// "unset" and is filled with a safe default by authLimitConfig; a negative
// value is an unambiguous operator error and must stop startup.
func validateAuthLimitInputs(in AuthLimitConfig) error {
	if in.SourceFailures < 0 {
		return fmt.Errorf("auth-limit: source failure threshold must be >= 1, got %d", in.SourceFailures)
	}
	if in.AccountFailures < 0 {
		return fmt.Errorf("auth-limit: account failure threshold must be >= 1, got %d", in.AccountFailures)
	}
	if in.Window < 0 {
		return fmt.Errorf("auth-limit: window must be > 0, got %s", in.Window)
	}
	if in.Cooldown < 0 {
		return fmt.Errorf("auth-limit: cooldown must be > 0, got %s", in.Cooldown)
	}
	if in.MaxSources < 0 {
		return fmt.Errorf("auth-limit: max sources must be >= 1, got %d", in.MaxSources)
	}
	if in.MaxAccounts < 0 {
		return fmt.Errorf("auth-limit: max accounts must be >= 1, got %d", in.MaxAccounts)
	}
	return nil
}

// authLimitConfig fills safe defaults for any unset limiter field.
func authLimitConfig(in AuthLimitConfig) authlimit.Config {
	def := authlimit.DefaultConfig()
	out := authlimit.Config{
		SourceFailures:  in.SourceFailures,
		AccountFailures: in.AccountFailures,
		Window:          in.Window,
		Cooldown:        in.Cooldown,
		MaxSources:      in.MaxSources,
		MaxAccounts:     in.MaxAccounts,
	}
	if out.SourceFailures == 0 {
		out.SourceFailures = def.SourceFailures
	}
	if out.AccountFailures == 0 {
		out.AccountFailures = def.AccountFailures
	}
	if out.Window == 0 {
		out.Window = def.Window
	}
	if out.Cooldown == 0 {
		out.Cooldown = def.Cooldown
	}
	if out.MaxSources == 0 {
		out.MaxSources = def.MaxSources
	}
	if out.MaxAccounts == 0 {
		out.MaxAccounts = def.MaxAccounts
	}
	return out
}

// AddUser adds a new user into the server user index
func (s *Server) AddUser(user, pass string, addrs ...string) error {
	authorizedAddrs := []*regexp.Regexp{}
	for _, addr := range addrs {
		authorizedAddr, err := regexp.Compile(addr)
		if err != nil {
			return err
		}
		authorizedAddrs = append(authorizedAddrs, authorizedAddr)
	}
	s.users.AddUser(&settings.User{
		Name:  user,
		Pass:  pass,
		Addrs: authorizedAddrs,
	})
	return nil
}

// DeleteUser removes a user from the server user index
func (s *Server) DeleteUser(user string) {
	s.users.Del(user)
}

// ResetUsers in the server user index.
// Use nil to remove all.
func (s *Server) ResetUsers(users []*settings.User) {
	s.users.Reset(users)
}
