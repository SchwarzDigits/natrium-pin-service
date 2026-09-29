package httpapi

import (
	"bytes"
	"context"
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
}

func (f *fakeCounter) Take(_ context.Context, domain, userID string) (attempts.Decision, error) {
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
	return attempts.Decision{Allowed: true, Remaining: f.limit - f.counts[userID+"@"+domain]}, nil
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
		auth:    &fakeAuth{},
		counter: &fakeCounter{limit: 10, counts: map[string]int{}, retryAfter: 90*time.Second + time.Millisecond},
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
	req := httptest.NewRequest(method, PathEvaluate, strings.NewReader(body))
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
	}
	require.NoError(t, dec.Decode(&resp))
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
	info, err := evaluator.Info(aliceDomain, aliceID, 0)
	require.NoError(t, err)
	out, err := evaluator.Evaluate(master, info, element)
	require.NoError(t, err)
	return out
}

func TestEvaluateReportsTheAttemptsLeft(t *testing.T) {
	f := newFixture(t)
	f.counter.limit = 3
	for want := 2; want >= 0; want-- {
		_, _, left := evaluateAnswer(t, f.post(t, `{"blindedElement":"`+blindedValid+`"}`))
		require.Equal(t, want, left)
	}
	require.Equal(t, http.StatusTooManyRequests, f.post(t, `{"blindedElement":"`+blindedValid+`"}`).Code)
}

func TestEvaluateWithTheCurrentVersion(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
	version, evaluated := evaluateResult(t, rec)
	require.Equal(t, currentKey, version)
	require.Equal(t, expected(t, f.keys.masters[currentKey], blindedValid), evaluated)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, 1, f.counter.count())
}

func TestEvaluateWithAnOlderVersion(t *testing.T) {
	f := newFixture(t)
	version, evaluated := evaluateResult(t, f.post(t, `{"keyVersion":1,"blindedElement":"`+blindedValid+`"}`))
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
			`{"blindedElement":"`+base64.StdEncoding.EncodeToString(blinded)+`"}`))
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
		"empty":               ``,
		"not JSON":            `blindedElement`,
		"array":               `[]`,
		"unknown field":       `{"blindedElement":"` + blindedValid + `","pin":"1"}`,
		"data after object":   `{"blindedElement":"` + blindedValid + `"}{}`,
		"missing element":     `{"keyVersion":2}`,
		"null element":        `{"blindedElement":null}`,
		"element not string":  `{"blindedElement":42}`,
		"not base64":          `{"blindedElement":"***"}`,
		"base64 extra pad":    `{"blindedElement":"` + blindedValid + `=="}`,
		"URL-safe base64":     `{"blindedElement":"` + strings.NewReplacer("+", "-", "/", "_").Replace(blindedValid) + `"}`,
		"identity":            `{"blindedElement":"` + identity + `"}`,
		"not on curve":        `{"blindedElement":"` + notOnCurve + `"}`,
		"uncompressed":        `{"blindedElement":"` + base64.StdEncoding.EncodeToString(uncompressed) + `"}`,
		"key version 0":       `{"keyVersion":0,"blindedElement":"` + blindedValid + `"}`,
		"key version -1":      `{"keyVersion":-1,"blindedElement":"` + blindedValid + `"}`,
		"key version text":    `{"keyVersion":"2","blindedElement":"` + blindedValid + `"}`,
		"key version decimal": `{"keyVersion":1.5,"blindedElement":"` + blindedValid + `"}`,
		"too large":           `{"blindedElement":"` + blindedValid + `"}` + strings.Repeat(" ", maxBodyBytes),
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
			rec := f.do(t, http.MethodPost, auth, `{"blindedElement":"`+blindedValid+`"}`)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.Equal(t, codeUnauthorized, errorCode(t, rec))
			require.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			require.Zero(t, f.counter.count())
		})
	}
}

func TestTheSchemeIsCaseInsensitive(t *testing.T) {
	f := newFixture(t)
	evaluateResult(t, f.do(t, http.MethodPost, "bearer "+token, `{"blindedElement":"`+blindedValid+`"}`))
}

func TestTokenIsCheckedBeforeTheBody(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodPost, "Bearer another-token", `not JSON`)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestUnknownKeyVersionIsNotCounted(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, `{"keyVersion":3,"blindedElement":"`+blindedValid+`"}`)
	require.Equal(t, http.StatusGone, rec.Code)
	require.Equal(t, codeKeyVersionUnavailable, errorCode(t, rec))
	require.Zero(t, f.counter.count())
	require.Contains(t, f.logs.String(), `"key_version":3`)
}

func TestTheLimitAnswers429WithRetryAfter(t *testing.T) {
	f := newFixture(t)
	f.counter.limit = 2
	for range 2 {
		evaluateResult(t, f.post(t, `{"blindedElement":"`+blindedValid+`"}`))
	}
	rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
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
		rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, codeUnavailable, errorCode(t, rec))
		require.Zero(t, f.auth.calls, "Wire is not asked")
		require.Zero(t, f.counter.count())
	})
	t.Run("Wire unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.auth.err = tokenauth.ErrUnavailable
		rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Equal(t, codeUnavailable, errorCode(t, rec))
		require.Zero(t, f.counter.count())
	})
	t.Run("database unavailable", func(t *testing.T) {
		f := newFixture(t)
		f.counter.err = errors.New("connection refused")
		rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
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
		rec := f.do(t, http.MethodPost, "Bearer "+token, `{"blindedElement":"`+blindedValid+`"}`,
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
	rec := f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
	_, evaluated := evaluateResult(t, rec)
	f.post(t, `{"blindedElement":"`+blindedValid+`"}`)
	f.do(t, http.MethodPost, "Bearer another-token", `{}`)
	f.post(t, `{"keyVersion":3,"blindedElement":"`+blindedValid+`"}`)
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
