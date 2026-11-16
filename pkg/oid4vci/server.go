package oid4vci

import (
	"context"
	"errors"
	"net"
	"net/http"
)

// Server =====================================================================================================================

// Server runs an AuthorizationServer's HTTP route table — the thing a
// Kubernetes Deployment runs as this process's main workload. Nothing about
// AuthorizationServer itself knows about sockets; Server is the only place
// in this package that does, so it's the one piece a future Vault plugin
// transport would never reuse.
type Server struct {
	httpServer *http.Server
}

// NewServer constructs a Server for as, listening on addr (e.g. ":8080")
// once Serve is called.
func NewServer(addr string, as *AuthorizationServer) *Server {
	return &Server{httpServer: &http.Server{Addr: addr, Handler: NewMux(as)}}
}

// Serve starts s listening on its configured address, blocking until
// Shutdown is called or an unrecoverable error occurs.
func (s *Server) Serve() error {
	return ignoreServerClosed(s.httpServer.ListenAndServe())
}

// ServeListener starts s on an already-bound listener instead of binding
// its own configured address — e.g. for a caller that needs to know the
// bound address (an OS-assigned ephemeral port) before the first request
// arrives.
func (s *Server) ServeListener(ln net.Listener) error {
	return ignoreServerClosed(s.httpServer.Serve(ln))
}

// Shutdown gracefully stops s, per net/http.Server.Shutdown's semantics.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Functions -------------------------------------------------------------------------------------------------------------

// ignoreServerClosed maps the sentinel error net/http.Server always returns
// after a successful Shutdown back to nil, so callers only see a real error.
func ignoreServerClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
