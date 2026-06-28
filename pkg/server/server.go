package server

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Server wraps an http.Server with the configured mux and auth middleware.
type Server struct {
	http *http.Server
}

// New creates a Server with the given listen address and Bearer token.
// Routes are registered via the returned *http.ServeMux so callers can
// attach additional handlers before calling Start.
//
// The server applies a rate limit of 10 requests/second with a burst of 30
// before authentication, so unauthenticated spam is also limited.
func New(listenAddr, authToken string) (*Server, *http.ServeMux) {
	mux := http.NewServeMux()

	limiter := rate.NewLimiter(10, 30)

	handler := rateLimit(limiter, mux)
	if authToken != "" {
		handler = rateLimit(limiter, bearerAuth(authToken, mux))
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return &Server{http: srv}, mux
}

// Serve starts the server and blocks until ctx is cancelled, then shuts down
// gracefully with a 10-second drain window.
//
// If certFile and keyFile are both non-empty, the server uses TLS
// (ListenAndServeTLS). Otherwise it falls back to plain HTTP (ListenAndServe).
// Dynamic ACME provisioning for the server itself is intentionally not
// supported — the server may not be publicly reachable, which makes it
// unsuitable as an ACME responder.
func (s *Server) Serve(ctx context.Context, certFile, keyFile string) error {
	errCh := make(chan error, 1)

	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			slog.Info("HTTPS server listening", "addr", s.http.Addr)
			err = s.http.ListenAndServeTLS(certFile, keyFile)
		} else {
			slog.Info("HTTP server listening", "addr", s.http.Addr)
			err = s.http.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	slog.Info("server shutting down")
	return s.http.Shutdown(shutCtx)
}

// rateLimit returns middleware that rejects requests exceeding the limiter's quota.
func rateLimit(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerAuth returns middleware that requires a valid Authorization: Bearer <token> header.
func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || subtle.ConstantTimeCompare([]byte(parts[1]), []byte(token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
