package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/masterkey/masterkeytest"
	"github.com/SchwarzDigits/natrium-pin-service/internal/receipt"
)

const (
	tokenIssuer   = "https://token.example"
	tokenAudience = "https://pin.example"
)

// fakeExchange serves the key set of a fake natrium-token-exchange and issues its tokens. While down is set, the key
// set answers 503.
type fakeExchange struct {
	server  *httptest.Server
	private ed25519.PrivateKey
	down    atomic.Bool
}

func newFakeExchange(t *testing.T) *fakeExchange {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	e := &fakeExchange{private: private}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		if e.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":%q}]}`,
			base64.RawURLEncoding.EncodeToString(public))
	})
	e.server = httptest.NewTLSServer(mux)
	t.Cleanup(e.server.Close)
	return e
}

// use points cfg and deps at the exchange.
func (e *fakeExchange) use(cfg *Config, deps *dependencies) {
	cfg.TokenJWKSURL = e.server.URL + "/.well-known/jwks.json"
	deps.jwksHTTP = e.server.Client()
}

// token returns a PIN token for the user with the given ID.
func (e *fakeExchange) token(t *testing.T, userID string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": tokenIssuer, "aud": tokenAudience, "sub": userID + "@wire.example",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(e.private)
	require.NoError(t, err)
	return s
}

func newUserID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// evaluate runs the client side for pin against the server at addr and returns the status, the Retry-After header
// and, for 200, the OPRF output.
func evaluate(t *testing.T, addr, token, pin string) (int, string, []byte) {
	status, retryAfter, output, _ := evaluateCounting(t, addr, token, pin)
	return status, retryAfter, output
}

// evaluateCounting is evaluate that also returns the attempts left of a 200 answer.
func evaluateCounting(t *testing.T, addr, token, pin string) (int, string, []byte, int) {
	status, retryAfter, output, left, _ := evaluateAttempt(t, addr, token, pin)
	return status, retryAfter, output, left
}

// receiptKey is the receipt key pair of the key files in these tests.
var receiptKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

// compressedReceiptKey returns the public receipt key, compressed, in standard base64.
func compressedReceiptKey(t *testing.T) string {
	t.Helper()
	public, err := receiptKey.PublicKey.Bytes()
	require.NoError(t, err)
	x, y := elliptic.Unmarshal(elliptic.P256(), public) //nolint:staticcheck // only to compress the test key
	return base64.StdEncoding.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), x, y))
}

// evaluateAttempt is evaluateCounting that also returns the attempt ID of a 200 answer.
func evaluateAttempt(t *testing.T, addr, token, pin string) (int, string, []byte, int, string) {
	t.Helper()
	client := oprf.NewClient(oprf.SuiteP256)
	finalize, request, err := client.Blind([][]byte{[]byte(pin)})
	require.NoError(t, err)
	blinded, err := request.Elements[0].MarshalBinaryCompress()
	require.NoError(t, err)

	body := `{"refundKey":"` + compressedReceiptKey(t) + `","blindedElement":"` +
		base64.StdEncoding.EncodeToString(blinded) + `"}`
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+PathEvaluate, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header.Get("Retry-After"), nil, 0, ""
	}

	var answer struct {
		KeyVersion        uint32 `json:"keyVersion"`
		EvaluatedElement  string `json:"evaluatedElement"`
		AttemptsRemaining int    `json:"attemptsRemaining"`
		AttemptID         string `json:"attemptId"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	evaluated, err := base64.StdEncoding.DecodeString(answer.EvaluatedElement)
	require.NoError(t, err)
	e := oprf.SuiteP256.Group().NewElement()
	require.NoError(t, e.UnmarshalBinary(evaluated))
	outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
	require.NoError(t, err)
	return resp.StatusCode, "", outputs[0], answer.AttemptsRemaining, answer.AttemptID
}

// refund sends the receipt for attemptID of userID to the server at addr and returns the status and the attempts
// left of a 200 answer.
func refund(t *testing.T, addr, token, userID, attemptID string) (int, int) {
	t.Helper()
	digest := sha256.Sum256(receipt.Message("wire.example", userID, attemptID))
	r, s, err := ecdsa.Sign(rand.Reader, receiptKey, digest[:])
	require.NoError(t, err)
	signature := make([]byte, receipt.SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	body := `{"attemptId":"` + attemptID + `","signature":"` + base64.StdEncoding.EncodeToString(signature) + `"}`
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+PathRefund, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		AttemptsRemaining int `json:"attemptsRemaining"`
	}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	}
	return resp.StatusCode, answer.AttemptsRemaining
}

// Two instances at one database: they give the same output for the same PIN, and together they allow 5 attempts per
// user and hour. The 6th is answered with 429 and Retry-After, and another user is not affected.
func TestTwoInstancesShareTheLimit(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	exchange := newFakeExchange(t)
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1)
	deps := dependencies{kms: kms}
	exchange.use(&cfg, &deps)
	instances := []*running{start(t, cfg, deps), start(t, cfg, deps)}
	for _, r := range instances {
		require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
			10*time.Second, 20*time.Millisecond)
	}

	token := exchange.token(t, newUserID())
	var first []byte
	for i := range 5 {
		status, _, output, left := evaluateCounting(t, instances[i%2].addr, token, "123456")
		require.Equal(t, http.StatusOK, status, "attempt %d", i+1)
		require.Equal(t, 4-i, left, "attempts left after attempt %d, counted across both instances", i+1)
		if first == nil {
			first = output
		}
		require.Equal(t, first, output, "attempt %d", i+1)
	}

	status, retryAfter, _ := evaluate(t, instances[0].addr, token, "123456")
	require.Equal(t, http.StatusTooManyRequests, status)
	seconds, err := strconv.Atoi(retryAfter)
	require.NoError(t, err)
	require.Greater(t, seconds, 60*60-60)
	require.LessOrEqual(t, seconds, 60*60)

	status, _, _ = evaluate(t, instances[1].addr, exchange.token(t, newUserID()), "123456")
	require.Equal(t, http.StatusOK, status)

	status, _, _ = evaluate(t, instances[1].addr, "not-a-token", "123456")
	require.Equal(t, http.StatusUnauthorized, status)
}

// A receipt sent to one instance gives back an attempt counted by another: after the limit, a receipt makes room for
// one more attempt.
func TestReceiptGivesTheAttemptBackAcrossInstances(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	exchange := newFakeExchange(t)
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1)
	deps := dependencies{kms: kms}
	exchange.use(&cfg, &deps)
	instances := []*running{start(t, cfg, deps), start(t, cfg, deps)}
	for _, r := range instances {
		require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
			10*time.Second, 20*time.Millisecond)
	}

	userID := newUserID()
	token := exchange.token(t, userID)
	var last string
	for i := range 5 {
		status, _, _, _, attemptID := evaluateAttempt(t, instances[0].addr, token, "123456")
		require.Equal(t, http.StatusOK, status, "attempt %d", i+1)
		last = attemptID
	}
	status, _, _ := evaluate(t, instances[0].addr, token, "123456")
	require.Equal(t, http.StatusTooManyRequests, status)

	status, left := refund(t, instances[1].addr, token, userID, last)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, 1, left)
	status, _ = refund(t, instances[0].addr, token, userID, last)
	require.Equal(t, http.StatusNotFound, status, "given back once")

	status, _, _ = evaluate(t, instances[0].addr, token, "123456")
	require.Equal(t, http.StatusOK, status, "the receipt made room for one attempt")
}
