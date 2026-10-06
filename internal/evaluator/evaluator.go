// Package evaluator is the server side of the OPRF (RFC 9497, mode OPRF, suite P256-SHA256). It derives the key of
// a user's key files from a master key and an info string of the user and the key files' receipt key, and evaluates
// a blinded element with it.
//
// The encoding of the info string is part of the contract with the clients: a change makes every existing key file
// unreadable.
package evaluator

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
)

// ElementSize is the size of a serialized element: a compressed SEC1 point of P-256.
const ElementSize = 33

// MasterSize is the size of a master key, the seed of DeriveKeyPair.
const MasterSize = 32

// RefundKeySize is the size of a receipt key in the info string: a compressed point of P-256.
const RefundKeySize = 33

// infoPrefix names this use of the OPRF and the version of the info encoding. Version 2 added the receipt key.
const infoPrefix = "natrium-recovery-v2"

// legacyInfoPrefix is the info encoding of version 1, without receipt key. See LegacyInfo.
const legacyInfoPrefix = "natrium-recovery-v1"

// infoSeparator separates the fields of the info string. It cannot occur in a domain or a user ID.
const infoSeparator = "|"

var suite = oprf.SuiteP256

// ErrInvalidElement reports a blinded element that is not the encoding of a point of P-256 other than the identity.
var ErrInvalidElement = errors.New("evaluator: not a valid blinded element")

// Element is a blinded element that ParseElement accepted.
type Element struct {
	e group.Element
}

// ParseElement decodes a blinded element: a compressed point of P-256 (DeserializeElement in RFC 9497). It rejects
// other lengths, uncompressed points, points not on the curve and the identity.
func ParseElement(b []byte) (Element, error) {
	if len(b) != ElementSize {
		return Element{}, ErrInvalidElement
	}
	e := suite.Group().NewElement()
	if err := e.UnmarshalBinary(b); err != nil || e.IsIdentity() {
		return Element{}, ErrInvalidElement
	}
	return Element{e: e}, nil
}

// Info returns the info string of DeriveKeyPair for the key files of a user with the receipt key refundKey:
//
//	"natrium-recovery-v2|" + domain + "|" + userID + "|" + epoch + "|" + base64(refundKey)
//
// domain is the lowercase domain of the user's qualified ID, userID the lowercase user ID in the canonical form
// 8-4-4-4-12, epoch is written in decimal without leading zeros, and refundKey, 33 bytes, in standard base64 with
// padding. Other forms are rejected rather than converted, so that a user's key files of one secret have exactly one
// info string.
func Info(domain, userID string, epoch uint64, refundKey []byte) ([]byte, error) {
	if !isDomain(domain) {
		return nil, fmt.Errorf("evaluator: domain %q is not a lowercase domain name", domain)
	}
	if !isCanonicalUUID(userID) {
		return nil, fmt.Errorf("evaluator: user ID %q is not a lowercase UUID in canonical form", userID)
	}
	if len(refundKey) != RefundKeySize {
		return nil, fmt.Errorf("evaluator: refund key must be %d bytes, got %d", RefundKeySize, len(refundKey))
	}
	info := infoPrefix + infoSeparator + domain + infoSeparator + userID + infoSeparator +
		strconv.FormatUint(epoch, 10) + infoSeparator + base64.StdEncoding.EncodeToString(refundKey)
	return []byte(info), nil
}

// LegacyInfo returns the info string of version 1, without receipt key:
//
//	"natrium-recovery-v1|" + domain + "|" + userID + "|" + epoch
//
// It serves clients that do not send a receipt key yet, and their key files, until they have moved to version 2.
// It will be removed then.
func LegacyInfo(domain, userID string, epoch uint64) ([]byte, error) {
	if !isDomain(domain) {
		return nil, fmt.Errorf("evaluator: domain %q is not a lowercase domain name", domain)
	}
	if !isCanonicalUUID(userID) {
		return nil, fmt.Errorf("evaluator: user ID %q is not a lowercase UUID in canonical form", userID)
	}
	info := legacyInfoPrefix + infoSeparator + domain + infoSeparator + userID + infoSeparator +
		strconv.FormatUint(epoch, 10)
	return []byte(info), nil
}

// Evaluate derives the user's key from master and info (DeriveKeyPair in RFC 9497) and returns the serialized
// evaluated element for blinded (BlindEvaluate).
func Evaluate(master, info []byte, blinded Element) ([]byte, error) {
	if blinded.e == nil {
		return nil, ErrInvalidElement
	}
	key, err := deriveKey(master, info)
	if err != nil {
		return nil, err
	}
	evaluation, err := oprf.NewServer(suite, key).Evaluate(&oprf.EvaluationRequest{Elements: []oprf.Blinded{blinded.e}})
	if err != nil {
		return nil, fmt.Errorf("evaluator: evaluate: %w", err)
	}
	return evaluation.Elements[0].MarshalBinaryCompress()
}

func deriveKey(master, info []byte) (*oprf.PrivateKey, error) {
	if len(master) != MasterSize {
		return nil, fmt.Errorf("evaluator: master key must be %d bytes, got %d", MasterSize, len(master))
	}
	key, err := oprf.DeriveKey(suite, oprf.BaseMode, master, info)
	if err != nil {
		return nil, fmt.Errorf("evaluator: derive key: %w", err)
	}
	return key, nil
}

// isDomain reports whether s consists of lowercase letters, digits, hyphens and dots, at most 253 characters, as a
// domain name in its canonical form does.
func isDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// isCanonicalUUID reports whether s is a UUID in the form 8-4-4-4-12 with lowercase hexadecimal digits.
func isCanonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
