package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/registration"
)

// User implements registration.User for lego's ACME client.
type User struct {
	email        string
	registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *User) GetEmail() string                        { return u.email }
func (u *User) GetRegistration() *registration.Resource { return u.registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// SetRegistration stores the ACME registration resource returned after account creation.
func (u *User) SetRegistration(r *registration.Resource) { u.registration = r }

// LoadOrCreateUser loads an existing ECDSA P-384 account key from keyPath, or
// generates a new one and saves it to disk.
func LoadOrCreateUser(email, keyPath string) (*User, error) {
	key, err := loadKey(keyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading account key: %w", err)
		}
		key, err = generateAndSaveKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("generating account key: %w", err)
		}
	}
	return &User{email: email, key: key}, nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing EC key: %w", err)
	}
	return key, nil
}

func generateAndSaveKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating key directory: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling key: %w", err)
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating key file: %w", err)
	}

	if err := pem.Encode(f, block); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("writing key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("closing key file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("renaming key file: %w", err)
	}

	return key, nil
}
