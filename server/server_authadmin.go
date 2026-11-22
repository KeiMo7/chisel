package chserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
)

// authAdmin exposes the in-memory lockout state on a separate, optionally
// enabled HTTP listener. It is deliberately not part of the tunnel
// handler: the main port keeps its existing surface unchanged, and the
// admin listener is expected to bind to localhost.
type authAdmin struct {
	server  *Server
	httpSrv *http.Server
	ln      net.Listener
}

// startAuthAdmin binds the administration listener and serves it until
// ctx is cancelled.
func (s *Server) startAuthAdmin(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.config.AuthLimit.AdminAddr)
	if err != nil {
		return s.Errorf("auth admin listener: %s", err)
	}
	a := &authAdmin{
		server: s,
		ln:     ln,
		httpSrv: &http.Server{
			Handler: http.HandlerFunc(s.handleAuthAdmin),
		},
	}
	s.authAdmin = a
	go func() {
		_ = a.httpSrv.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		a.httpSrv.Close()
	}()
	s.Infof("Auth lockout admin endpoint listening on http://%s", ln.Addr())
	return nil
}

func (s *Server) handleAuthAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/snapshot"):
		writeJSON(w, http.StatusOK, s.authLimiter.Snapshot())
		return
	case r.Method == http.MethodGet && r.URL.Path == "/metrics":
		writeJSON(w, http.StatusOK, s.authLimiter.MetricsNow())
		return
	case r.Method == http.MethodPost && r.URL.Path == "/unlock-source":
		key := r.URL.Query().Get("source")
		if key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing source query parameter"})
			return
		}
		found := s.authLimiter.UnlockSource(key)
		s.Infof("Auth admin: source %q manually unlocked (tracked=%t)", key, found)
		writeJSON(w, http.StatusOK, map[string]any{"source": key, "tracked": found})
		return
	case r.Method == http.MethodPost && r.URL.Path == "/unlock-account":
		key := r.URL.Query().Get("account")
		if key == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing account query parameter"})
			return
		}
		found := s.authLimiter.UnlockAccount(key)
		s.Infof("Auth admin: account %q manually unlocked (tracked=%t)", key, found)
		writeJSON(w, http.StatusOK, map[string]any{"account": key, "tracked": found})
		return
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not found",
			"routes": "GET /snapshot, GET /metrics, " +
				"POST /unlock-source?source=host, POST /unlock-account?account=name",
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
