package evaluator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"

	"github.com/SchwarzDigits/natrium-pin-service/internal/receipt"
)

var update = flag.Bool("update", false, "rewrite testdata/interop.json")

// interopFile holds fixed values of the whole exchange, with the receipt: the receipt key pair derived from the
// secret, the info string with the public key, the evaluation and a signature of the receipt. interop/check.mjs
// recomputes the client side with @noble/curves, the library Natrium uses, and must arrive at the same values.
var interopFile = filepath.Join("testdata", "interop.json")

type interopVector struct {
	Name   string `json:"name"`
	Master string `json:"master"`
	Domain string `json:"domain"`
	UserID string `json:"userId"`
	Epoch  uint64 `json:"epoch"`
	// Secret is the secret in the key file, from which the client derives the receipt key pair.
	Secret           string `json:"secret"`
	RefundSeed       string `json:"refundSeed"`
	RefundPrivateKey string `json:"refundPrivateKey"`
	RefundKey        string `json:"refundKey"`
	Info             string `json:"info"`
	SecretKey        string `json:"secretKey"`
	PIN              string `json:"pin"`
	Input            string `json:"input"`
	Blind            string `json:"blind"`
	BlindedElement   string `json:"blindedElement"`
	EvaluatedElement string `json:"evaluatedElement"`
	Output           string `json:"output"`
	// AttemptID, RefundMessage and Signature are the receipt of the attempt. The signature is one valid signature:
	// ECDSA signatures are randomized, so a client checks it by verifying it.
	AttemptID     string `json:"attemptId"`
	RefundMessage string `json:"refundMessage"`
	Signature     string `json:"signature"`
}

// refundInfoPrefix is the info of the derivation of the receipt key pair.
const refundInfoPrefix = "natrium-pin-refund-v1"

// refundKeyPair derives the receipt key pair of the client from the secret in the key file (docs/protocol.md,
// Receipts): refundSeed by HKDF-SHA256 without salt, then the private key by DeriveKeyPair of RFC 9497 with the
// suite P256-SHA256. It returns refundSeed, the private key and the compressed public key.
func refundKeyPair(t *testing.T, secret []byte, domain, userID string) ([]byte, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	seed, err := hkdf.Key(sha256.New, secret, nil, refundInfoPrefix+"|"+domain+"|"+userID, 32)
	require.NoError(t, err)
	key, err := oprf.DeriveKey(suite, oprf.BaseMode, seed, []byte(refundInfoPrefix))
	require.NoError(t, err)
	scalar, err := key.MarshalBinary()
	require.NoError(t, err)
	private, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	require.NoError(t, err)
	public, err := private.PublicKey.Bytes()
	require.NoError(t, err)
	x, y := elliptic.Unmarshal(elliptic.P256(), public) //nolint:staticcheck // only to compress the public key
	return seed, private, elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

// signReceipt returns r||s of ECDSA with SHA-256 over message. ECDSA signatures are randomized.
func signReceipt(t *testing.T, private *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
	require.NoError(t, err)
	signature := make([]byte, receipt.SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func interopVectors(t *testing.T) []interopVector {
	t.Helper()
	counting := make([]byte, MasterSize)
	for i := range counting {
		counting[i] = byte(i)
	}
	return []interopVector{
		makeVector(t, "digits", counting, "wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0", "123456",
			"3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364", 0xa0, 0x00),
		// The PIN is given decomposed; the client normalizes it to NFC before it encodes it as UTF-8.
		makeVector(t, "unicode", counting[16:], "schwarz-dev-wire.runs.onstackit.cloud",
			"0f5c3a1e-7b2d-4c8e-9a6f-2d4b8e1c7a90", "Grüße 2026",
			"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", 0xc0, 0xf0),
	}
}

// makeVector computes one vector. The secret counts up from secretStart, the attempt ID from attemptStart.
func makeVector(t *testing.T, name string, masterPart []byte, domain, userID, pin, blindHex string,
	secretStart, attemptStart byte) interopVector {
	t.Helper()
	master := append(append([]byte{}, masterPart...), masterPart...)[:MasterSize]
	secret := make([]byte, 32)
	attemptID := make([]byte, 16)
	for i := range secret {
		secret[i] = secretStart + byte(i)
	}
	for i := range attemptID {
		attemptID[i] = attemptStart + byte(i)
	}
	refundSeed, refundPrivate, refundKey := refundKeyPair(t, secret, domain, userID)
	scalar, err := refundPrivate.Bytes()
	require.NoError(t, err)
	info, err := Info(domain, userID, 0, refundKey)
	require.NoError(t, err)
	key, err := deriveKey(master, info)
	require.NoError(t, err)
	secretKey, err := key.MarshalBinary()
	require.NoError(t, err)
	input := norm.NFC.Bytes([]byte(pin))

	blindBytes, err := hex.DecodeString(blindHex)
	require.NoError(t, err)
	var blinded, evaluated []byte
	output := clientOutput(t, blindBytes, input, func(b []byte) []byte {
		blinded = b
		element, err := ParseElement(b)
		require.NoError(t, err)
		evaluated, err = Evaluate(master, info, element)
		require.NoError(t, err)
		return evaluated
	})
	attempt := base64.StdEncoding.EncodeToString(attemptID)
	message := refundInfoPrefix + "|" + domain + "|" + userID + "|" + attempt
	return interopVector{
		Name:             name,
		Master:           hex.EncodeToString(master),
		Domain:           domain,
		UserID:           userID,
		Epoch:            0,
		Secret:           hex.EncodeToString(secret),
		RefundSeed:       hex.EncodeToString(refundSeed),
		RefundPrivateKey: hex.EncodeToString(scalar),
		RefundKey:        base64.StdEncoding.EncodeToString(refundKey),
		Info:             string(info),
		SecretKey:        hex.EncodeToString(secretKey),
		PIN:              pin,
		Input:            hex.EncodeToString(input),
		Blind:            blindHex,
		BlindedElement:   base64.StdEncoding.EncodeToString(blinded),
		EvaluatedElement: base64.StdEncoding.EncodeToString(evaluated),
		Output:           hex.EncodeToString(output),
		AttemptID:        attempt,
		RefundMessage:    message,
		Signature:        base64.StdEncoding.EncodeToString(signReceipt(t, refundPrivate, []byte(message))),
	}
}

// The committed values must not change: key files depend on them. go test -run TestInteropVectors -update rewrites
// the file, after which interop/check.mjs must be run again.
//
// ECDSA signatures are randomized, so the committed signature is checked by verifying it, not by comparing it. A
// valid committed signature is kept on update.
func TestInteropVectors(t *testing.T) {
	vectors := interopVectors(t)
	var committed []interopVector
	if data, err := os.ReadFile(interopFile); err == nil {
		require.NoError(t, json.Unmarshal(data, &committed))
	}
	for i, v := range vectors {
		if i >= len(committed) {
			continue
		}
		key, _ := base64.StdEncoding.DecodeString(v.RefundKey)
		signature, _ := base64.StdEncoding.DecodeString(committed[i].Signature)
		if receipt.Verify(key, v.Domain, v.UserID, v.AttemptID, signature) {
			vectors[i].Signature = committed[i].Signature
		}
	}
	got, err := json.MarshalIndent(vectors, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(interopFile, got, 0o644))
	}
	want, err := os.ReadFile(interopFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "the committed values must stay and the signature must verify")
}

// The vectors also hold with a random blind: the output depends only on master, info and PIN.
func TestInteropOutputDoesNotDependOnTheBlind(t *testing.T) {
	for _, v := range interopVectors(t) {
		master, _ := hex.DecodeString(v.Master)
		input, _ := hex.DecodeString(v.Input)
		client := oprf.NewClient(suite)
		finalize, request, err := client.Blind([][]byte{input})
		require.NoError(t, err)
		blinded, err := request.Elements[0].MarshalBinaryCompress()
		require.NoError(t, err)
		element, err := ParseElement(blinded)
		require.NoError(t, err)
		evaluated, err := Evaluate(master, []byte(v.Info), element)
		require.NoError(t, err)
		e := suite.Group().NewElement()
		require.NoError(t, e.UnmarshalBinary(evaluated))
		outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
		require.NoError(t, err)
		require.Equal(t, v.Output, hex.EncodeToString(outputs[0]), v.Name)
	}
}
