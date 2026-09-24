// Package masterkey keeps the master keys of the service. They are stored encrypted by a key management service
// (KMS) and decrypted once per version at start, because the KMS is rate limited. The decrypted keys are kept outside
// the Go heap, in memory that is locked against swapping and excluded from core dumps where the platform allows it.
//
// Key files name the version of the master key they were made with. The service keeps all active versions and uses
// the current one for new key files.
package masterkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Size is the size of a master key.
const Size = 32

// sealPrefix names the format of a sealed master key, the plaintext that the KMS encrypts: the prefix, the key version
// (4 bytes, big endian) and the master key. Because the version is inside the ciphertext, an entry whose version was
// changed or swapped with another is detected at start instead of yielding wrong keys.
const sealPrefix = "natrium-recovery-master-v1"

const sealedSize = len(sealPrefix) + 4 + Size

const (
	// kmsTimeout bounds one call to the KMS.
	kmsTimeout = 30 * time.Second
	// minBackoff and maxBackoff bound the wait between failed attempts to decrypt a master key.
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// KMS encrypts and decrypts with one key of a key management service. kmsVersion is the version of that key.
type KMS interface {
	Encrypt(ctx context.Context, kmsVersion int64, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, kmsVersion int64, ciphertext []byte) ([]byte, error)
}

// Entry is one version of the master key as configured: the version that key files name, the version of the KMS key
// that encrypted it, and the ciphertext.
type Entry struct {
	KeyVersion uint32
	KMSVersion int64
	Ciphertext []byte
}

// String returns the entry in the form ParseEntries reads: <keyVersion>:<kmsVersion>:<base64 ciphertext>.
func (e Entry) String() string {
	return fmt.Sprintf("%d:%d:%s", e.KeyVersion, e.KMSVersion, base64.StdEncoding.EncodeToString(e.Ciphertext))
}

// ParseEntries reads comma-separated entries of the form <keyVersion>:<kmsVersion>:<base64 ciphertext>. The ciphertext
// is standard base64 with padding. Spaces around an entry are ignored. It checks the entries with Check.
func ParseEntries(s string) ([]Entry, error) {
	var entries []Entry
	for i, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("entry %d: must be <keyVersion>:<kmsVersion>:<base64 ciphertext>", i+1)
		}
		keyVersion, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("entry %d: key version %q is not a number", i+1, parts[0])
		}
		kmsVersion, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("entry %d: KMS version %q is not a number", i+1, parts[1])
		}
		ciphertext, err := base64.StdEncoding.Strict().DecodeString(parts[2])
		if err != nil {
			return nil, fmt.Errorf("entry %d: the ciphertext is not base64", i+1)
		}
		entries = append(entries, Entry{KeyVersion: uint32(keyVersion), KMSVersion: kmsVersion, Ciphertext: ciphertext})
	}
	return entries, Check(entries)
}

// Check reports whether entries can be loaded: at least one entry, versions from 1, no key version twice and a
// ciphertext in each.
func Check(entries []Entry) error {
	if len(entries) == 0 {
		return errors.New("at least one master key is required")
	}
	seen := map[uint32]bool{}
	for _, e := range entries {
		switch {
		case e.KeyVersion == 0:
			return errors.New("key versions start at 1")
		case e.KMSVersion < 1:
			return fmt.Errorf("key version %d: KMS versions start at 1", e.KeyVersion)
		case len(e.Ciphertext) == 0:
			return fmt.Errorf("key version %d: the ciphertext is empty", e.KeyVersion)
		case seen[e.KeyVersion]:
			return fmt.Errorf("key version %d appears twice", e.KeyVersion)
		}
		seen[e.KeyVersion] = true
	}
	return nil
}

// seal returns the plaintext that the KMS encrypts for master under keyVersion.
func seal(keyVersion uint32, master []byte) []byte {
	out := make([]byte, 0, sealedSize)
	out = append(out, sealPrefix...)
	out = binary.BigEndian.AppendUint32(out, keyVersion)
	return append(out, master...)
}

// open returns the master key in plaintext, a slice of it, if plaintext is a sealed master key for keyVersion. Errors
// never contain the plaintext.
func open(plaintext []byte, keyVersion uint32) ([]byte, error) {
	switch {
	case len(plaintext) != sealedSize || !bytes.HasPrefix(plaintext, []byte(sealPrefix)):
		return nil, fmt.Errorf("key version %d: the decrypted value is not a sealed master key", keyVersion)
	case binary.BigEndian.Uint32(plaintext[len(sealPrefix):]) != keyVersion:
		return nil, fmt.Errorf("key version %d: the ciphertext belongs to key version %d",
			keyVersion, binary.BigEndian.Uint32(plaintext[len(sealPrefix):]))
	}
	return plaintext[len(sealPrefix)+4:], nil
}

// Generate creates a master key with crypto/rand and has the KMS encrypt it for keyVersion under kmsVersion. It then
// decrypts the ciphertext again to check the entry and returns it. The master key exists only in memory and is
// overwritten before Generate returns.
func Generate(ctx context.Context, kms KMS, keyVersion uint32, kmsVersion int64) (Entry, error) {
	entry := Entry{KeyVersion: keyVersion, KMSVersion: kmsVersion, Ciphertext: []byte{0}}
	if err := Check([]Entry{entry}); err != nil {
		return Entry{}, err
	}
	master := make([]byte, Size)
	defer clear(master)
	if _, err := rand.Read(master); err != nil {
		return Entry{}, err
	}
	sealed := seal(keyVersion, master)
	defer clear(sealed)

	ciphertext, err := kms.Encrypt(ctx, kmsVersion, sealed)
	if err != nil {
		return Entry{}, err
	}
	plaintext, err := kms.Decrypt(ctx, kmsVersion, ciphertext)
	if err != nil {
		return Entry{}, fmt.Errorf("decrypt the new ciphertext: %w", err)
	}
	defer clear(plaintext)
	opened, err := open(plaintext, keyVersion)
	if err != nil {
		return Entry{}, err
	}
	if subtle.ConstantTimeCompare(opened, master) != 1 {
		return Entry{}, errors.New("the KMS returned another value than it encrypted")
	}
	entry.Ciphertext = ciphertext
	return entry, nil
}

// Keys holds the decrypted master keys.
type Keys struct {
	kms     KMS
	entries []Entry
	current uint32
	log     *slog.Logger

	minBackoff, maxBackoff time.Duration

	// memory holds all master keys, Size bytes each, in the order of entries. masters points into it and is set once
	// all keys are loaded.
	memory  *lockedMemory
	masters atomic.Pointer[map[uint32][]byte]
}

// New returns Keys for entries, which Check must accept, with current among them. Load decrypts them.
func New(kms KMS, entries []Entry, current uint32, log *slog.Logger) *Keys {
	return &Keys{
		kms: kms, entries: entries, current: current, log: log,
		minBackoff: minBackoff, maxBackoff: maxBackoff,
	}
}

// Load decrypts all master keys, one KMS call per version. A failed call is retried with exponential backoff until ctx
// is canceled; ready stays false meanwhile. An entry that decrypts to anything other than a sealed master key of its
// version is a configuration error that retrying does not fix: Load then returns an error.
func (k *Keys) Load(ctx context.Context) error {
	memory, err := allocLocked(len(k.entries) * Size)
	if err != nil {
		return fmt.Errorf("allocate memory for the master keys: %w", err)
	}
	if !memory.locked {
		k.log.Warn("master keys are not locked in memory and could be swapped out", "reason", memory.reason)
	}
	masters := make(map[uint32][]byte, len(k.entries))
	for i, e := range k.entries {
		slot := memory.buf[i*Size : (i+1)*Size : (i+1)*Size]
		if err := k.loadOne(ctx, e, slot); err != nil {
			memory.free()
			return err
		}
		masters[e.KeyVersion] = slot
	}
	k.memory = memory
	k.masters.Store(&masters)
	k.log.Info("master keys loaded", "versions", len(masters), "current_version", k.current, "locked", memory.locked)
	return nil
}

// loadOne decrypts e into slot.
func (k *Keys) loadOne(ctx context.Context, e Entry, slot []byte) error {
	backoff := k.minBackoff
	for {
		callCtx, cancel := context.WithTimeout(ctx, kmsTimeout)
		plaintext, err := k.kms.Decrypt(callCtx, e.KMSVersion, e.Ciphertext)
		cancel()
		if err == nil {
			master, err := open(plaintext, e.KeyVersion)
			if err == nil {
				copy(slot, master)
			}
			clear(plaintext)
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		k.log.Error("decrypting a master key failed, retrying",
			"key_version", e.KeyVersion, "kms_version", e.KMSVersion, "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, k.maxBackoff)
	}
}

// Loaded reports whether all master keys are loaded.
func (k *Keys) Loaded() bool {
	return k.masters.Load() != nil
}

// Ready returns an error until all master keys are loaded. It serves the readiness probe.
func (k *Keys) Ready(context.Context) error {
	if !k.Loaded() {
		return errors.New("master keys are not loaded yet")
	}
	return nil
}

// Current returns the version for new key files.
func (k *Keys) Current() uint32 {
	return k.current
}

// Versions returns the number of loaded versions.
func (k *Keys) Versions() int {
	if m := k.masters.Load(); m != nil {
		return len(*m)
	}
	return 0
}

// Get returns the master key of version, if it is loaded. The slice points into the locked memory: the caller must
// not change or keep it, and must not use it after Close.
func (k *Keys) Get(version uint32) ([]byte, bool) {
	m := k.masters.Load()
	if m == nil {
		return nil, false
	}
	master, ok := (*m)[version]
	return master, ok
}

// Close overwrites the master keys and releases their memory. It must not be called while Load runs or a key from Get
// is in use.
func (k *Keys) Close() {
	k.masters.Store(nil)
	if k.memory != nil {
		k.memory.free()
		k.memory = nil
	}
}
