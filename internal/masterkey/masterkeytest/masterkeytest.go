// Package masterkeytest provides a KMS and a STACKIT service account key for tests.
package masterkeytest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sync"
)

// FakeKMS encrypts with AES-GCM under a random key per KMS version. It implements masterkey.KMS. It can fail the next
// decrypt calls, and it counts them.
type FakeKMS struct {
	mu          sync.Mutex
	keys        map[int64]cipher.AEAD
	failDecrypt int
	decrypts    int
}

// NewFakeKMS returns a FakeKMS with fresh keys.
func NewFakeKMS() *FakeKMS {
	return &FakeKMS{keys: map[int64]cipher.AEAD{}}
}

func (f *FakeKMS) aead(version int64) cipher.AEAD {
	if f.keys[version] == nil {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		if f.keys[version], err = cipher.NewGCM(block); err != nil {
			panic(err)
		}
	}
	return f.keys[version]
}

// Encrypt implements masterkey.KMS.
func (f *FakeKMS) Encrypt(_ context.Context, version int64, plaintext []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.aead(version)
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	return a.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt implements masterkey.KMS.
func (f *FakeKMS) Decrypt(_ context.Context, version int64, ciphertext []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decrypts++
	if f.failDecrypt > 0 {
		f.failDecrypt--
		return nil, errors.New("fake KMS unavailable")
	}
	a := f.aead(version)
	if len(ciphertext) < a.NonceSize() {
		return nil, errors.New("fake KMS: ciphertext too short")
	}
	return a.Open(nil, ciphertext[:a.NonceSize()], ciphertext[a.NonceSize():], nil)
}

// FailDecrypt makes the next n decrypt calls fail.
func (f *FakeKMS) FailDecrypt(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDecrypt = n
}

// DecryptCalls returns the number of decrypt calls so far.
func (f *FakeKMS) DecryptCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decrypts
}

// ServiceAccountKey returns the JSON key of a STACKIT service account with a new RSA private key. The STACKIT SDK
// accepts it, and fetches tokens from tokenEndpoint, which a test points to an address that is not served.
func ServiceAccountKey(tokenEndpoint string) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	privateKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	out, err := json.Marshal(map[string]any{
		"active":       true,
		"keyAlgorithm": "RSA_2048",
		"keyOrigin":    "GENERATED",
		"keyType":      "USER_MANAGED",
		"credentials": map[string]any{
			"aud":           "https://stackit-service-account-prod.apps.01.cf.eu01.stackit.cloud",
			"iss":           "test@sa.stackit.cloud",
			"kid":           "00000000-0000-4000-8000-000000000001",
			"privateKey":    privateKey,
			"sub":           "00000000-0000-4000-8000-000000000002",
			"tokenEndpoint": tokenEndpoint,
		},
	})
	if err != nil {
		panic(err)
	}
	return string(out)
}
