package server

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Server wraps an http.Server with the configured mux and auth middleware.
type Server struct {
	http *http.Server
}

// New creates a Server with the given listen address and Bearer token.
// Routes are registered via the returned *http.ServeMux so callers can
// attach additional handlers before calling Start.
func New(listenAddr, authToken string) (*Server, *http.ServeMux) {
	mux := http.NewServeMux()

	var handler http.Handler = mux
	if authToken != "" {
		handler = bearerAuth(authToken, mux)
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

// Start begins serving and blocks until ctx is cancelled, then shuts down
// gracefully with a 10-second drain window.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTP server listening", "addr", s.http.Addr)
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
	slog.Info("HTTP server shutting down")
	return s.http.Shutdown(shutCtx)
}

// StartTLS is identical to Start but uses the provided cert and key files.
func (s *Server) StartTLS(ctx context.Context, certFile, keyFile string) error {
	errCh := make(chan error, 1)
	go func() {
		slog.Info("HTTPS server listening", "addr", s.http.Addr)
		if err := s.http.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
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
	slog.Info("HTTPS server shutting down")
	return s.http.Shutdown(shutCtx)
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
