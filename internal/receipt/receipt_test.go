package receipt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	domain    = "wire.example"
	userID    = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	attemptID = "9mY0r1bKQwS2c1v3Zk8hJA=="
)

// newKey returns a key pair and the compressed public key.
func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	x, y := elliptic.Unmarshal(elliptic.P256(), public) //nolint:staticcheck // only to compress the test key
	return priv, elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

// sign returns r||s over the receipt message.
func sign(t *testing.T, priv *ecdsa.PrivateKey, attempt string) []byte {
	t.Helper()
	digest := sha256.Sum256(Message(domain, userID, attempt))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	signature := make([]byte, SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func TestMessageEncodingIsFixed(t *testing.T) {
	require.Equal(t, "natrium-pin-refund-v1|wire.example|39b7f597-dfd1-4dff-86f5-fe1b79cb70a0|9mY0r1bKQwS2c1v3Zk8hJA==",
		string(Message(domain, userID, attemptID)))
}

func TestVerifyAcceptsOnlyTheSignatureOfTheKey(t *testing.T) {
	priv, key := newKey(t)
	signature := sign(t, priv, attemptID)
	require.True(t, Verify(key, domain, userID, attemptID, signature))

	_, other := newKey(t)
	require.False(t, Verify(other, domain, userID, attemptID, signature), "another key")
	require.False(t, Verify(key, domain, userID, "AAAAAAAAAAAAAAAAAAAAAA==", signature), "another attempt")
	require.False(t, Verify(key, "other.example", userID, attemptID, signature), "another user")
	require.False(t, Verify(key, domain, userID, attemptID, signature[:63]), "a short signature")
	require.False(t, Verify(key, domain, userID, attemptID, make([]byte, SignatureSize)), "r and s zero")
}

func TestParseKeyRejectsOtherEncodings(t *testing.T) {
	_, key := newKey(t)
	_, err := ParseKey(key)
	require.NoError(t, err)

	notOnCurve := func() []byte {
		for x := byte(1); x < 255; x++ {
			b := make([]byte, KeySize)
			b[0], b[KeySize-1] = 2, x
			if _, err := ParseKey(b); err != nil {
				return b
			}
		}
		t.Fatal("no x off the curve found")
		return nil
	}()
	uncompressed := append([]byte{4}, make([]byte, 64)...)
	wrongPrefix := append([]byte{5}, key[1:]...)
	for name, b := range map[string][]byte{
		"empty":        nil,
		"short":        key[:32],
		"long":         append(append([]byte{}, key...), 0),
		"uncompressed": uncompressed,
		"wrong prefix": wrongPrefix,
		"not on curve": notOnCurve,
	} {
		_, err := ParseKey(b)
		require.ErrorIs(t, err, ErrInvalidKey, name)
	}
}
