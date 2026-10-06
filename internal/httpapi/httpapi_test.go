package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/attempts"
	"github.com/SchwarzDigits/natrium-pin-service/internal/evaluator"
	"github.com/SchwarzDigits/natrium-pin-service/internal/receipt"
	"github.com/SchwarzDigits/natrium-pin-service/internal/tokenauth"
)

const (
	token        = "token-of-alice"
	pin          = "123456"
	aliceID      = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	aliceDomain  = "wire.example"
	currentKey   = uint32(2)
	previousKey  = uint32(1)
	unknownKey   = uint32(3)
	blindedValid = "A3I6HlwJuLnBjR3LyinoAH6V8U9HMtk0bUkP/BlREDaN" // RFC 9497 A.3.1.1, BlindedElement
	// refundKeyValid is the receipt key of the first vector in internal/evaluator/testdata/interop.json.
	refundKeyValid = "A7RAoFrwwW6LPWoswV51l5MYJ3IkumhNz2Wk3KgW8xku"
)

var alice = tokenauth.QualifiedID{Domain: aliceDomain, ID: aliceID}

type fakeAuth struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeAuth) Authenticate(_ context.Context, t string) (tokenauth.QualifiedID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return tokenauth.QualifiedID{}, f.err
	}
	if t != token {
		return tokenauth.QualifiedID{}, tokenauth.ErrUnauthorized
	}
	return alice, nil
}

type fakeCounter struct {
	mu         sync.Mutex
	limit      int
	counts     map[string]int
	retryAfter time.Duration
	err        error
	// open holds the open attempts by ID: the user and the receipt key.
	open   map[string][2]string
	nextID byte
}

func (f *fakeCounter) Take(_ context.Context, domain, userID string, refundKey []byte) (attempts.Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return attempts.Decision{}, f.err
	}
	f.counts[userID+"@"+domain]++
	n := f.counts[userID+"@"+domain]
	if n > f.limit {
		f.counts[userID+"@"+domain]--
		return attempts.Decision{RetryAfter: f.retryAfter}, nil
	}
	decision := attempts.Decision{Allowed: true, Remaining: f.limit - f.counts[userID+"@"+domain]}
	if refundKey != nil {
		f.nextID++
		decision.AttemptID = bytes.Repeat([]byte{f.nextID}, attempts.AttemptIDSize)
		f.open[string(decision.AttemptID)] = [2]string{userID + "@" + domain, string(refundKey)}
	}
	return decision, nil
}

func (f *fakeCounter) Refund(_ context.Context, domain, userID string, attemptID []byte,
	valid func(refundKey []byte) bool) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	attempt, ok := f.open[string(attemptID)]
	if !ok || attempt[0] != userID+"@"+domain {
		return 0, attempts.ErrUnknownAttempt
	}
	if !valid([]byte(attempt[1])) {
		return 0, attempts.ErrInvalidReceipt
	}
	delete(f.open, string(attemptID))
	f.counts[userID+"@"+domain]--
	return f.limit - f.counts[userID+"@"+domain], nil
}

func (f *fakeCounter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[aliceID+"@"+aliceDomain]
}

type fakeKeys struct {
	loaded  bool
	masters map[uint32][]byte
}

func (f *fakeKeys) Loaded() bool    { return f.loaded }
func (f *fakeKeys) Current() uint32 { return currentKey }
func (f *fakeKeys) Get(v uint32) ([]byte, bool) {
	m, ok := f.masters[v]
	return m, ok && f.loaded
}

type fixture struct {
	handler http.Handler
	auth    *fakeAuth
	counter *fakeCounter
	keys    *fakeKeys
	logs    *bytes.Buffer
	api     *Handler
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		auth: &fakeAuth{},
		counter: &fakeCounter{limit: 10, counts: map[string]int{}, open: map[string][2]string{},
			retryAfter: 90*time.Second + time.Millisecond},
		keys: &fakeKeys{loaded: true, masters: map[uint32][]byte{
			previousKey: bytes.Repeat([]byte{1}, 32),
			currentKey:  bytes.Repeat([]byte{2}, 32),
		}},
		logs: &bytes.Buffer{},
	}
	f.api = New(Options{
		Auth: f.auth, Counter: f.counter, Keys: f.keys,
		Log:     slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Metrics: prometheus.NewRegistry(),
	})
	mux := http.NewServeMux()
	f.api.Register(mux)
	f.handler = mux
	return f
}

func (f *fixture) do(t *testing.T, method, auth, body string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doPath(t, PathEvaluate, method, auth, body, header...)
}

func (f *fixture) doPath(t *testing.T, path, method, auth, body string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) post(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.do(t, http.MethodPost, "Bearer "+token, body)
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body, 1)
	return body["error"]
}

func evaluateResult(t *testing.T, rec *httptest.ResponseRecorder) (uint32, []byte) {
	version, evaluated, _ := evaluateAnswer(t, rec)
	return version, evaluated
}

func evaluateAnswer(t *testing.T, rec *httptest.ResponseRecorder) (uint32, []byte, int) {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	var resp struct {
		KeyVersion        uint32 `json:"keyVersion"`
		EvaluatedElement  string `json:"evaluatedElement"`
		AttemptsRemaining *int   `json:"attemptsRemaining"`
		AttemptID         string `json:"attemptId"`
	}
	require.NoError(t, dec.Decode(&resp))
	attemptID, err := base64.StdEncoding.Strict().DecodeString(resp.AttemptID)
	require.NoError(t, err)
	require.Len(t, attemptID, attempts.AttemptIDSize)
	evaluated, err := base64.StdEncoding.Strict().DecodeString(resp.EvaluatedElement)
	require.NoError(t, err)
	require.Len(t, evaluated, evaluator.ElementSize)
	require.NotNil(t, resp.AttemptsRemaining, "attemptsRemaining is always present")
	return resp.KeyVersion, evaluated, *resp.AttemptsRemaining
}

func expected(t *testing.T, master []byte, blinded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(blinded)
	require.NoError(t, err)
	element, err := evaluator.ParseElement(raw)
	require.NoError(t, err)
	refundKey, err := base64.StdEncoding.DecodeString(refundKeyValid)
	require.NoError(t, err)
	info, err := evaluator.Info(aliceDomain, aliceID, 0, refundKey)
	require.NoError(t, err)
	out, err := evaluator.Evaluate(master, info, element)
	require.NoError(t, err)
	return out
}

func TestEvaluateReportsTheAttemptsLeft(t *testing.T) {
	f := newFixture(t)
	f.counter.limit = 3
	for want := 2; want >= 0; want-- {
		_, _, left := evaluateAnswer(t, f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`))
		require.Equal(t, want, left)
	}
	require.Equal(t, http.StatusTooManyRequests, f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`).Code)
}

func TestEvaluateWithTheCurrentVersion(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	version, evaluated := evaluateResult(t, rec)
	require.Equal(t, currentKey, version)
	require.Equal(t, expected(t, f.keys.masters[currentKey], blindedValid), evaluated)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, 1, f.counter.count())
}

func TestEvaluateWithAnOlderVersion(t *testing.T) {
	f := newFixture(t)
	version, evaluated := evaluateResult(t, f.post(t, `{"keyVersion":1,"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`))
	require.Equal(t, previousKey, version)
	require.Equal(t, expected(t, f.keys.masters[previousKey], blindedValid), evaluated)
}

// A full run with the CIRCL client: the output for the same PIN is the same in two requests.
func TestClientGetsTheSameOutputTwice(t *testing.T) {
	f := newFixture(t)
	output := func() []byte {
		client := oprf.NewClient(oprf.SuiteP256)
		finalize, request, err := client.Blind([][]byte{[]byte(pin)})
		require.NoError(t, err)
		blinded, err := request.Elements[0].MarshalBinaryCompress()
		require.NoError(t, err)
		_, evaluated := evaluateResult(t, f.post(t,
			`{"refundKey":"`+refundKeyValid+`","blindedElement":"`+base64.StdEncoding.EncodeToString(blinded)+`"}`))
		e := oprf.SuiteP256.Group().NewElement()
		require.NoError(t, e.UnmarshalBinary(evaluated))
		outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
		require.NoError(t, err)
		return outputs[0]
	}
	require.Equal(t, output(), output())
}

func TestBadRequestsAreNotCounted(t *testing.T) {
	identity := base64.StdEncoding.EncodeToString([]byte{0})
	notOnCurve := base64.StdEncoding.EncodeToString(append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...))
	uncompressed, _ := hex.DecodeString("04" + strings.Repeat("00", 64))
	for name, body := range map[string]string{
		"empty":                 ``,
		"not JSON":              `blindedElement`,
		"array":                 `[]`,
		"unknown field":         `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `","pin":"1"}`,
		"data after object":     `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}{}`,
		"missing element":       `{"keyVersion":2}`,
		"refund key not base64": `{"refundKey":"***","blindedElement":"` + blindedValid + `"}`,
		"refund key short":      `{"refundKey":"` + refundKeyValid[:40] + `","blindedElement":"` + blindedValid + `"}`,
		"refund key off curve":  `{"refundKey":"` + notOnCurve + `","blindedElement":"` + blindedValid + `"}`,
		"refund key uncompressed": `{"refundKey":"` + base64.StdEncoding.EncodeToString(uncompressed) +
			`","blindedElement":"` + blindedValid + `"}`,
		"null element":        `{"refundKey":"` + refundKeyValid + `","blindedElement":null}`,
		"element not string":  `{"refundKey":"` + refundKeyValid + `","blindedElement":42}`,
		"not base64":          `{"refundKey":"` + refundKeyValid + `","blindedElement":"***"}`,
		"base64 extra pad":    `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `=="}`,
		"URL-safe base64":     `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + strings.NewReplacer("+", "-", "/", "_").Replace(blindedValid) + `"}`,
		"identity":            `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + identity + `"}`,
		"not on curve":        `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + notOnCurve + `"}`,
		"uncompressed":        `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + base64.StdEncoding.EncodeToString(uncompressed) + `"}`,
		"key version 0":       `{"keyVersion":0,"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}`,
		"key version -1":      `{"keyVersion":-1,"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}`,
		"key version text":    `{"keyVersion":"2","refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}`,
		"key version decimal": `{"keyVersion":1.5,"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}`,
		"too large":           `{"refundKey":"` + refundKeyValid + `","blindedElement":"` + blindedValid + `"}` + strings.Repeat(" ", maxBodyBytes),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			rec := f.post(t, body)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Equal(t, codeBadRequest, errorCode(t, rec))
			require.Zero(t, f.counter.count())
		})
	}
}

func TestUnauthorizedRequestsAreNotCounted(t *testing.T) {
	for name, auth := range map[string]string{
		"no header":                  "",
		"basic":                      "Basic dXNlcjpwYXNz",
		"empty bearer":               "Bearer ",
		"bearer only":                "Bearer",
		"rejected":                   "Bearer another-token",
		"rejected, lowercase scheme": "bearer another-token",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			rec := f.do(t, http.MethodPost, auth, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.Equal(t, codeUnauthorized, errorCode(t, rec))
			require.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			require.Zero(t, f.counter.count())
		})
	}
}

func TestTheSchemeIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	evaluateResult(t, f.do(t, http.MethodPost, "bearer "+token, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`))
}

func TestTokenIsCheckedBeforeTheBody(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodPost, "Bearer another-token", `not JSON`)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestUnknownKeyVersionIsNotCounted(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, `{"keyVersion":3,"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	require.Equal(t, http.StatusGone, rec.Code)
	require.Equal(t, codeKeyVersionUnavailable, errorCode(t, rec))
	require.Zero(t, f.counter.count())
	require.Contains(t, f.logs.String(), `"key_version":3`)
}

func TestTheLimitAnswers429WithRetryAfter(t *testing.T) {
	f := newFixture(t)
	f.counter.limit = 2
	for range 2 {
		evaluateResult(t, f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`))
	}
	rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, codeTooManyAttempts, errorCode(t, rec))
	require.Equal(t, "91", rec.Header().Get("Retry-After"), "rounded up to whole seconds")
	require.Equal(t, 2, f.counter.count(), "a refused attempt is not counted")
}

func TestRetryAfterSeconds(t *testing.T) {
	require.Equal(t, 1, retryAfterSeconds(0))
	require.Equal(t, 1, retryAfterSeconds(time.Millisecond))
	require.Equal(t, 1, retryAfterSeconds(time.Second))
	require.Equal(t, 2, retryAfterSeconds(time.Second+time.Nanosecond))
	require.Equal(t, 86400, retryAfterSeconds(24*time.Hour))
}

func TestUnavailable(t *testing.T) {
	t.Run("master keys not loaded", func(t *testing.T) {
		f := newFixture(t)
		f.keys.loaded = false
		rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, codeUnavailable, errorCode(t, rec))
		require.Zero(t, f.auth.calls, "Wire is not asked")
		require.Zero(t, f.counter.count())
	})
	t.Run("Wire unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.auth.err = tokenauth.ErrUnavailable
		rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, codeUnavailable, errorCode(t, rec))
		require.Zero(t, f.counter.count())
	})
	t.Run("database unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.counter.err = errors.New("connection refused")
		rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, codeUnavailable, errorCode(t, rec))
	})
}

func TestOnlyPOST(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := f.do(t, method, "Bearer "+token, "")
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, method)
	}
	require.Zero(t, f.counter.count())
}

// Pages of any origin may call the API, without credentials, and read Retry-After.
func TestCORS(t *testing.T) {
	f := newFixture(t)
	for _, origin := range []string{"https://app.example", "https://evil.example", "null"} {
		rec := f.do(t, http.MethodOptions, "", "", "Origin", origin,
			"Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "authorization,content-type")
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		require.Equal(t, "POST", rec.Header().Get("Access-Control-Allow-Methods"))
		require.Equal(t, "Authorization, Content-Type", rec.Header().Get("Access-Control-Allow-Headers"))
		require.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	}
	require.Zero(t, f.auth.calls, "the preflight does not reach Wire")

	f.counter.limit = 1
	for _, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		rec := f.do(t, http.MethodPost, "Bearer "+token, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`,
			"Origin", "https://app.example")
		require.Equal(t, want, rec.Code)
		require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		require.Equal(t, "Retry-After", rec.Header().Get("Access-Control-Expose-Headers"))
		require.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	}
}

// One log line per request with result, user and key version, and never the token or the elements.
func TestLogsAndMetrics(t *testing.T) {
	f := newFixture(t)
	f.counter.limit = 1
	rec := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	_, evaluated := evaluateResult(t, rec)
	f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	f.do(t, http.MethodPost, "Bearer another-token", `{}`)
	f.post(t, `{"keyVersion":3,"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	f.post(t, `{}`)

	lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
	require.Len(t, lines, 5)
	for i, want := range []string{
		`"msg":"evaluate","result":"ok","user":"` + aliceID + `@` + aliceDomain + `","key_version":2`,
		`"result":"limited","user":"` + aliceID + `@` + aliceDomain + `","key_version":2`,
		`"result":"unauthorized"`,
		`"result":"key_version_unavailable","user":"` + aliceID + `@` + aliceDomain + `","key_version":3`,
		`"result":"bad_request","user":"` + aliceID + `@` + aliceDomain + `"`,
	} {
		require.Contains(t, lines[i], want)
	}
	for _, secret := range []string{token, "another-token", blindedValid, base64.StdEncoding.EncodeToString(evaluated)} {
		require.NotContains(t, f.logs.String(), secret)
	}

	for result, want := range map[string]float64{
		resultOK: 1, resultLimited: 1, resultUnauthorized: 1, resultKeyVersionUnavailable: 1, resultBadRequest: 1,
		resultUnavailable: 0, resultInternal: 0,
	} {
		require.Equal(t, want, testutil.ToFloat64(f.api.requests.WithLabelValues(result)), result)
	}
	var wire dto.Metric
	require.NoError(t, f.api.tokenCheck.Write(&wire))
	require.EqualValues(t, 5, wire.GetHistogram().GetSampleCount(), "every request with a token asked Wire")
}

// receiptKey is a client's receipt key pair: the private key and the compressed public key in base64.
type receiptKey struct {
	private *ecdsa.PrivateKey
	public  string
}

func newReceiptKey(t *testing.T) receiptKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := private.PublicKey.Bytes()
	require.NoError(t, err)
	x, y := elliptic.Unmarshal(elliptic.P256(), public) //nolint:staticcheck // only to compress the test key
	return receiptKey{private: private, public: base64.StdEncoding.EncodeToString(elliptic.MarshalCompressed(
		elliptic.P256(), x, y))}
}

// sign returns the receipt body for attemptID, signed by k.
func (k receiptKey) sign(t *testing.T, attemptID string) string {
	t.Helper()
	digest := sha256.Sum256(receipt.Message(aliceDomain, aliceID, attemptID))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	require.NoError(t, err)
	signature := make([]byte, receipt.SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return `{"attemptId":"` + attemptID + `","signature":"` + base64.StdEncoding.EncodeToString(signature) + `"}`
}

// evaluateWith evaluates with the receipt key k and returns the attempt ID.
func (f *fixture) evaluateWith(t *testing.T, k receiptKey) string {
	t.Helper()
	rec := f.post(t, `{"refundKey":"`+k.public+`","blindedElement":"`+blindedValid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		AttemptID string `json:"attemptId"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.AttemptID
}

func (f *fixture) refund(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doPath(t, PathRefund, http.MethodPost, "Bearer "+token, body)
}

func TestReceiptGivesTheAttemptBack(t *testing.T) {
	f := newFixture(t)
	k := newReceiptKey(t)
	f.evaluateWith(t, k)
	id := f.evaluateWith(t, k)
	require.Equal(t, 2, f.counter.count())

	rec := f.refund(t, k.sign(t, id))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.JSONEq(t, `{"attemptsRemaining":9}`, rec.Body.String())
	require.Equal(t, 1, f.counter.count(), "only the attempt of the receipt")

	rec = f.refund(t, k.sign(t, id))
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, codeUnknownAttempt, errorCode(t, rec))
}

func TestReceiptNeedsTheSignatureOfTheAttemptsKey(t *testing.T) {
	f := newFixture(t)
	k := newReceiptKey(t)
	id := f.evaluateWith(t, k)
	other := f.evaluateWith(t, k)

	for name, body := range map[string]string{
		"another key":     newReceiptKey(t).sign(t, id),
		"another attempt": strings.Replace(k.sign(t, other), other, id, 1),
	} {
		rec := f.refund(t, body)
		require.Equal(t, http.StatusForbidden, rec.Code, name)
		require.Equal(t, codeInvalidSignature, errorCode(t, rec), name)
	}
	require.Equal(t, 2, f.counter.count(), "nothing given back")
	require.Equal(t, http.StatusOK, f.refund(t, k.sign(t, id)).Code, "the attempt stays open")
}

func TestRefundRejectsBadRequests(t *testing.T) {
	f := newFixture(t)
	k := newReceiptKey(t)
	id := f.evaluateWith(t, k)
	valid := k.sign(t, id)
	for name, body := range map[string]string{
		"empty":             ``,
		"no signature":      `{"attemptId":"` + id + `"}`,
		"no attempt":        `{"signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`,
		"short attempt":     strings.Replace(valid, id, base64.StdEncoding.EncodeToString(make([]byte, 15)), 1),
		"short signature":   `{"attemptId":"` + id + `","signature":"` + base64.StdEncoding.EncodeToString(make([]byte, 63)) + `"}`,
		"unknown field":     strings.Replace(valid, `{`, `{"pin":"1",`, 1),
		"data after object": valid + `{}`,
	} {
		rec := f.refund(t, body)
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		require.Equal(t, codeBadRequest, errorCode(t, rec), name)
	}

	rec := f.refund(t, strings.Replace(valid, id, base64.StdEncoding.EncodeToString(make([]byte, 16)), 1))
	require.Equal(t, http.StatusNotFound, rec.Code, "an unknown attempt")

	rec = f.doPath(t, PathRefund, http.MethodPost, "Bearer another-token", valid)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Equal(t, 1, f.counter.count())
}

// The key of the evaluation depends on the receipt key: an answer for one receipt key is of no use for a key file
// with another.
func TestTheReceiptKeyChangesTheEvaluation(t *testing.T) {
	f := newFixture(t)
	first := f.post(t, `{"refundKey":"`+refundKeyValid+`","blindedElement":"`+blindedValid+`"}`)
	second := f.post(t, `{"refundKey":"`+newReceiptKey(t).public+`","blindedElement":"`+blindedValid+`"}`)
	_, a := evaluateResult(t, first)
	_, b := evaluateResult(t, second)
	require.NotEqual(t, a, b)
}

func TestRefundPreflightAndMetrics(t *testing.T) {
	f := newFixture(t)
	rec := f.doPath(t, PathRefund, http.MethodOptions, "", "", "Origin", "https://app.example",
		"Access-Control-Request-Method", "POST", "Access-Control-Request-Headers", "authorization,content-type")
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))

	k := newReceiptKey(t)
	id := f.evaluateWith(t, k)
	body := k.sign(t, id)
	f.refund(t, body)
	f.refund(t, body)
	require.EqualValues(t, 1, testutil.ToFloat64(f.api.refunds.WithLabelValues(resultOK)))
	require.EqualValues(t, 1, testutil.ToFloat64(f.api.refunds.WithLabelValues(resultUnknownAttempt)))

	var signature struct {
		Signature string `json:"signature"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &signature))
	require.NotContains(t, f.logs.String(), signature.Signature)
	require.Contains(t, f.logs.String(), `"msg":"refund"`)
}

// A client that does not send a receipt key yet gets the evaluation of version 1, which its key files were made
// with, and no attempt ID. Until the clients have moved, this path stays.
func TestEvaluationWithoutReceiptKeyUsesVersion1(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotContains(t, resp, "attemptId")

	raw, err := base64.StdEncoding.DecodeString(blindedValid)
	require.NoError(t, err)
	element, err := evaluator.ParseElement(raw)
	require.NoError(t, err)
	info, err := evaluator.LegacyInfo(aliceDomain, aliceID, 0)
	require.NoError(t, err)
	want, err := evaluator.Evaluate(f.keys.masters[currentKey], info, element)
	require.NoError(t, err)
	require.Equal(t, base64.StdEncoding.EncodeToString(want), resp["evaluatedElement"])
	require.Equal(t, 1, f.counter.count(), "the attempt is counted")
}
