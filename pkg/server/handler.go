package server

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/persist"
)

// CertResponse is the JSON payload returned by GET /api/v1/certs/{domain}.
type CertResponse struct {
	Certificate string `json:"certificate"` // base64-encoded PEM bundle (cert + chain)
	PrivateKey  string `json:"private_key"` // base64-encoded PEM private key
}

// CertHandler serves certificates from an in-memory cache and exposes
// Update and CacheCert methods for hot reloads and post-renewal updates.
type CertHandler struct {
	mu    sync.RWMutex
	index map[string]string       // domain → dir
	cache map[string]*CertResponse // dir   → pre-encoded response
}

// Update atomically replaces the domain→directory index and pre-populates
// the cache for any directories that have cert files on disk.
func (h *CertHandler) Update(globalStoragePath string, certs []config.CertificateConfig) {
	idx := buildDomainIndex(globalStoragePath, certs)

	h.mu.Lock()
	defer h.mu.Unlock()

	// Carry over entries that are still referenced by the new index.
	dirs := make(map[string]struct{}, len(idx))
	for _, dir := range idx {
		dirs[dir] = struct{}{}
	}
	newCache := make(map[string]*CertResponse, len(dirs))
	for dir := range dirs {
		if h.cache != nil {
			if entry, ok := h.cache[dir]; ok {
				newCache[dir] = entry
				continue
			}
		}
		// Not in cache yet — try loading from disk (best-effort at startup).
		if entry := loadFromDisk(dir); entry != nil {
			newCache[dir] = entry
		}
	}

	h.index = idx
	h.cache = newCache
}

// CacheCert stores a freshly renewed certificate in the in-memory cache.
// It is called by the Updater save function immediately after persisting to disk.
func (h *CertHandler) CacheCert(dir string, certPEM, keyPEM []byte) {
	entry := &CertResponse{
		Certificate: base64.StdEncoding.EncodeToString(certPEM),
		PrivateKey:  base64.StdEncoding.EncodeToString(keyPEM),
	}
	h.mu.Lock()
	if h.cache == nil {
		h.cache = make(map[string]*CertResponse)
	}
	h.cache[dir] = entry
	h.mu.Unlock()
}

// RegisterCertHandler registers GET /api/v1/certs/{domain} on mux and returns
// the handler so callers can call Update and CacheCert.
func RegisterCertHandler(mux *http.ServeMux, globalStoragePath string, certs []config.CertificateConfig) *CertHandler {
	h := &CertHandler{}
	h.Update(globalStoragePath, certs)

	mux.HandleFunc("GET /api/v1/certs/{domain}", func(w http.ResponseWriter, r *http.Request) {
		domain := r.PathValue("domain")

		h.mu.RLock()
		dir, ok := h.index[domain]
		var entry *CertResponse
		if ok {
			entry = h.cache[dir]
		}
		h.mu.RUnlock()

		if !ok {
			jsonError(w, "certificate not found", http.StatusNotFound)
			return
		}

		if entry == nil {
			// Cache miss: cert not yet issued or not loaded at startup.
			entry = loadFromDisk(dir)
			if entry == nil {
				jsonError(w, "certificate not yet available", http.StatusNotFound)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(entry); err != nil {
			slog.Error("encoding cert response", "domain", domain, "err", err)
		}
	})

	return h
}

// loadFromDisk reads cert.pem and key.pem from dir and returns a pre-encoded
// CertResponse. Returns nil if either file is missing or unreadable.
func loadFromDisk(dir string) *CertResponse {
	certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return nil
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil
	}
	return &CertResponse{
		Certificate: base64.StdEncoding.EncodeToString(certPEM),
		PrivateKey:  base64.StdEncoding.EncodeToString(keyPEM),
	}
}

// buildDomainIndex maps every domain (primary and SANs) configured in certs
// to the directory where its files are stored.
func buildDomainIndex(globalStoragePath string, certs []config.CertificateConfig) map[string]string {
	index := make(map[string]string, len(certs))
	for _, cert := range certs {
		dir := persist.CertDir(globalStoragePath, cert)
		// Index by each raw domain for direct lookups, and also by the
		// sanitized primary key (_wildcard.*) so wildcard cert clients
		// can fetch without '*' in the URL path.
		for _, domain := range cert.Domains {
			index[domain] = dir
		}
		index[persist.CertDir("", cert)] = dir
	}
	return index
}
