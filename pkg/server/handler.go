package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kreicer/triplec/pkg/config"
	"github.com/kreicer/triplec/pkg/persist"
)

// CertResponse is the JSON payload returned by GET /api/v1/certs/{domain}.
type CertResponse struct {
	Certificate string `json:"certificate"` // base64-encoded PEM bundle (cert + chain)
	PrivateKey  string `json:"private_key"` // base64-encoded PEM private key
}

// RegisterCertHandler registers GET /api/v1/certs/{domain} on mux.
func RegisterCertHandler(mux *http.ServeMux, globalStoragePath string, certs []config.CertificateConfig) {
	index := buildDomainIndex(globalStoragePath, certs)

	mux.HandleFunc("GET /api/v1/certs/{domain}", func(w http.ResponseWriter, r *http.Request) {
		domain := r.PathValue("domain")
		dir, ok := index[domain]
		if !ok {
			http.Error(w, "certificate not found", http.StatusNotFound)
			return
		}

		certPEM, err := os.ReadFile(filepath.Join(dir, "cert.pem"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "certificate not yet available", http.StatusNotFound)
				return
			}
			slog.Error("reading cert.pem", "dir", dir, "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		keyPEM, err := os.ReadFile(filepath.Join(dir, "key.pem"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "certificate not yet available", http.StatusNotFound)
				return
			}
			slog.Error("reading key.pem", "dir", dir, "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		resp := CertResponse{
			Certificate: base64.StdEncoding.EncodeToString(certPEM),
			PrivateKey:  base64.StdEncoding.EncodeToString(keyPEM),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("encoding cert response", "domain", domain, "err", err)
		}
	})
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
