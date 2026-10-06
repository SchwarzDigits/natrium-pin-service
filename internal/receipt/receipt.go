// Package receipt checks the receipts with which a client gives an attempt back: after it opened or made a key file,
// it signs the attempt with the private key of the receipt key pair, which it derives from the secret in the key
// file. Without the right PIN there is no secret and so no signature.
//
// A receipt key is a public ECDSA key on P-256, a signature ECDSA with SHA-256 (FIPS 186-5). The encodings and the
// signed message are part of the contract with the clients.
package receipt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

// KeySize is the size of a receipt key: a compressed SEC1 point of P-256.
const KeySize = 33

// SignatureSize is the size of a signature: r and s of ECDSA, 32 bytes each, big-endian.
const SignatureSize = 64

// messagePrefix names the signed message and the version of its encoding.
const messagePrefix = "natrium-pin-refund-v1"

// ErrInvalidKey reports a receipt key that is not a compressed point of P-256.
var ErrInvalidKey = errors.New("receipt: not a compressed point of P-256")

// ParseKey decodes a receipt key: a compressed SEC1 point of P-256. The point at infinity has no compressed form.
func ParseKey(key []byte) (*ecdsa.PublicKey, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
	if x == nil {
		return nil, ErrInvalidKey
	}
	uncompressed := make([]byte, 1+2*32)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:])
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return pub, nil
}

// Message returns the signed message of a receipt:
//
//	"natrium-pin-refund-v1|" + domain + "|" + userID + "|" + attemptID
//
// with the user's qualified ID as in the info string of the evaluation and attemptID exactly as the service returned
// it, in standard base64 with padding.
func Message(domain, userID, attemptID string) []byte {
	return []byte(messagePrefix + "|" + domain + "|" + userID + "|" + attemptID)
}

// Verify reports whether signature, r||s, is a valid ECDSA signature with SHA-256 by key over the message of the
// receipt.
func Verify(key []byte, domain, userID, attemptID string, signature []byte) bool {
	pub, err := ParseKey(key)
	if err != nil || len(signature) != SignatureSize {
		return false
	}
	digest := sha256.Sum256(Message(domain, userID, attemptID))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}
