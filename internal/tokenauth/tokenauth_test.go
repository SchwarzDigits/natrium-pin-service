package tokenauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	issuer   = "https://token.example"
	audience = "https://pin.example"
	aliceID  = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	domain   = "wire.example"
)

var alice = QualifiedID{Domain: domain, ID: aliceID}

// clock is a settable time.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// signingKey is a key of the fake exchange.
type signingKey struct {
	kid     string
	private ed25519.PrivateKey
}

func newSigningKey(t *testing.T, kid string) signingKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return signingKey{kid: kid, private: private}
}

func (k signingKey) jwk() map[string]string {
	return map[string]string{
		"kty": "OKP", "crv": "Ed25519", "kid": k.kid, "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(k.private.Public().(ed25519.PublicKey)),
	}
}

// sign returns a token with the usual claims at now, changed by change.
func (k signingKey) sign(t *testing.T, now time.Time, change func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": alice.String(),
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": "x",
	}
	if change != nil {
		change(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = k.kid
	s, err := tok.SignedString(k.private)
	require.NoError(t, err)
	return s
}

// exchange is a fake key set endpoint.
type exchange struct {
	server       *httptest.Server
	mu           sync.Mutex
	body         []byte
	status       int
	cacheControl string
	fetches      atomic.Int32
}

func newExchange(t *testing.T, keys ...signingKey) *exchange {
	t.Helper()
	e := &exchange{status: http.StatusOK, cacheControl: "public, max-age=300"}
	e.serve(keys...)
	e.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.fetches.Add(1)
		e.mu.Lock()
		defer e.mu.Unlock()
		if r.URL.Path != "/.well-known/jwks.json" {
			http.Redirect(w, r, "/.well-known/jwks.json", http.StatusFound)
			return
		}
		w.Header().Set("Cache-Control", e.cacheControl)
		w.WriteHeader(e.status)
		_, _ = w.Write(e.body)
	}))
	t.Cleanup(e.server.Close)
	return e
}

func (e *exchange) serve(keys ...signingKey) {
	set := map[string][]map[string]string{"keys": {}}
	for _, k := range keys {
		set["keys"] = append(set["keys"], k.jwk())
	}
	body, _ := json.Marshal(set)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.body = body
}

func (e *exchange) fail(status int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status = status
}

func (e *exchange) verifier(t *testing.T, c *clock) *Verifier {
	t.Helper()
	v, err := New(Config{
		JWKSURL:  e.server.URL + "/.well-known/jwks.json",
		Issuer:   issuer,
		Audience: audience,
		HTTP:     e.server.Client(),
		Now:      c.Now,
	})
	require.NoError(t, err)
	return v
}

func loaded(t *testing.T, e *exchange, c *clock) *Verifier {
	t.Helper()
	v := e.verifier(t, c)
	require.NoError(t, v.fetch(context.Background()))
	require.NoError(t, v.Ready(context.Background()))
	return v
}

var start = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// A token that natrium-token-exchange issued, with its key set: the two implementations agree.
func TestAcceptsATokenOfTheExchange(t *testing.T) {
	raw, err := os.ReadFile("testdata/exchange.json")
	require.NoError(t, err)
	var vector struct {
		Audience string          `json:"audience"`
		Issuer   string          `json:"issuer"`
		IssuedAt int64           `json:"issuedAt"`
		JWKS     json.RawMessage `json:"jwks"`
		Token    string          `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &vector))
	e := newExchange(t)
	e.body = vector.JWKS
	c := &clock{now: time.Unix(vector.IssuedAt, 0).Add(time.Minute)}
	v, err := New(Config{JWKSURL: e.server.URL + "/.well-known/jwks.json", Issuer: vector.Issuer,
		Audience: vector.Audience, HTTP: e.server.Client(), Now: c.Now})
	require.NoError(t, err)
	require.NoError(t, v.fetch(context.Background()))

	id, err := v.Authenticate(context.Background(), vector.Token)
	require.NoError(t, err)
	require.Equal(t, alice, id)

	c.advance(10 * time.Minute)
	_, err = v.Authenticate(context.Background(), vector.Token)
	require.ErrorIs(t, err, ErrUnauthorized, "expired after its 10 minutes")
}

func TestAcceptsAValidToken(t *testing.T) {
	k := newSigningKey(t, "k1")
	c := &clock{now: start}
	v := loaded(t, newExchange(t, k), c)
	id, err := v.Authenticate(context.Background(), k.sign(t, start, nil))
	require.NoError(t, err)
	require.Equal(t, alice, id)

	id, err = v.Authenticate(context.Background(), k.sign(t, start, func(c jwt.MapClaims) {
		c["sub"] = strings.ToUpper(aliceID) + "@Wire.Example"
		c["aud"] = []string{"https://other.example", audience}
	}))
	require.NoError(t, err, "sub is read in lowercase, aud may be a list that contains ours")
	require.Equal(t, alice, id)
}

func TestRejectsTokens(t *testing.T) {
	k := newSigningKey(t, "k1")
	other := newSigningKey(t, "k1")
	c := &clock{now: start}
	v := loaded(t, newExchange(t, k), c)

	hs256 := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": issuer, "aud": audience, "sub": alice.String(), "exp": start.Add(time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString([]byte("secret"))
		require.NoError(t, err)
		return s
	}()
	none := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"iss": issuer, "aud": audience, "sub": alice.String(), "exp": start.Add(time.Minute).Unix(),
		})
		s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)
		return s
	}()
	valid := k.sign(t, start, nil)
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"`+issuer+`","aud":"`+audience+`","sub":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d@wire.example","exp":`+
			"9999999999}")) + "." + parts[2]

	for name, token := range map[string]string{
		"empty":             "",
		"garbage":           "not.a.token",
		"too long":          strings.Repeat("a", maxTokenLength+1),
		"HS256":             hs256,
		"none":              none,
		"other key":         other.sign(t, start, nil),
		"tampered":          tampered,
		"expired":           k.sign(t, start.Add(-20*time.Minute), nil),
		"not yet valid":     k.sign(t, start, func(c jwt.MapClaims) { c["nbf"] = start.Add(time.Minute).Unix() }),
		"issued in future":  k.sign(t, start, func(c jwt.MapClaims) { c["iat"] = start.Add(time.Minute).Unix() }),
		"no exp":            k.sign(t, start, func(c jwt.MapClaims) { delete(c, "exp") }),
		"wrong issuer":      k.sign(t, start, func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }),
		"storage audience":  k.sign(t, start, func(c jwt.MapClaims) { c["aud"] = "wss://vfs.example/v1/ws" }),
		"no audience":       k.sign(t, start, func(c jwt.MapClaims) { delete(c, "aud") }),
		"no sub":            k.sign(t, start, func(c jwt.MapClaims) { delete(c, "sub") }),
		"sub without @":     k.sign(t, start, func(c jwt.MapClaims) { c["sub"] = aliceID }),
		"sub not a UUID":    k.sign(t, start, func(c jwt.MapClaims) { c["sub"] = "alice@wire.example" }),
		"sub bad domain":    k.sign(t, start, func(c jwt.MapClaims) { c["sub"] = aliceID + "@wire|example" }),
		"unknown kid":       newSigningKey(t, "k9").sign(t, start, nil),
		"within the leeway": k.sign(t, start.Add(-10*time.Minute-31*time.Second), nil),
	} {
		_, err := v.Authenticate(context.Background(), token)
		require.ErrorIs(t, err, ErrUnauthorized, name)
		if token != "" {
			require.NotContains(t, err.Error(), token, name)
		}
	}
}

func TestAllowsClockSkew(t *testing.T) {
	k := newSigningKey(t, "k1")
	c := &clock{now: start}
	v := loaded(t, newExchange(t, k), c)
	_, err := v.Authenticate(context.Background(), k.sign(t, start.Add(20*time.Second), nil))
	require.NoError(t, err, "issued 20 seconds ahead of this clock")
	_, err = v.Authenticate(context.Background(), k.sign(t, start.Add(-10*time.Minute-20*time.Second), nil))
	require.NoError(t, err, "expired 20 seconds ago by this clock")
}

func TestUnavailableBeforeTheKeySetIsLoaded(t *testing.T) {
	k := newSigningKey(t, "k1")
	e := newExchange(t, k)
	v := e.verifier(t, &clock{now: start})
	require.ErrorIs(t, v.Ready(context.Background()), ErrUnavailable)
	_, err := v.Authenticate(context.Background(), k.sign(t, start, nil))
	require.ErrorIs(t, err, ErrUnavailable)
	require.Zero(t, e.fetches.Load(), "Authenticate does not load the first key set; Run does")
}

func TestUnknownKidFetchesAgainAtMostOncePerMinute(t *testing.T) {
	old := newSigningKey(t, "old")
	next := newSigningKey(t, "new")
	c := &clock{now: start}
	e := newExchange(t, old)
	v := loaded(t, e, c)
	require.EqualValues(t, 1, e.fetches.Load())

	e.serve(old, next)
	_, err := v.Authenticate(context.Background(), next.sign(t, start, nil))
	require.ErrorIs(t, err, ErrUnauthorized, "the last fetch was less than a minute ago")
	require.EqualValues(t, 1, e.fetches.Load())

	c.advance(time.Minute)
	id, err := v.Authenticate(context.Background(), next.sign(t, c.Now(), nil))
	require.NoError(t, err, "a minute later the unknown kid makes it fetch the published key")
	require.Equal(t, alice, id)
	require.EqualValues(t, 2, e.fetches.Load())

	stranger := newSigningKey(t, "stranger")
	for range 5 {
		_, err = v.Authenticate(context.Background(), stranger.sign(t, c.Now(), nil))
		require.ErrorIs(t, err, ErrUnauthorized)
	}
	require.EqualValues(t, 2, e.fetches.Load(), "unknown kids do not make it fetch more than once per minute")
}

func TestFailedFetchKeepsTheKeySetForAnHour(t *testing.T) {
	k := newSigningKey(t, "k1")
	c := &clock{now: start}
	e := newExchange(t, k)
	v := loaded(t, e, c)
	e.fail(http.StatusInternalServerError)
	require.Error(t, v.fetch(context.Background()))
	_, err := v.Authenticate(context.Background(), k.sign(t, start, nil))
	require.NoError(t, err)

	c.advance(59 * time.Minute)
	_, err = v.Authenticate(context.Background(), k.sign(t, c.Now(), nil))
	require.NoError(t, err, "still within the hour")
	require.NoError(t, v.Ready(context.Background()))

	c.advance(time.Minute)
	_, err = v.Authenticate(context.Background(), k.sign(t, c.Now(), nil))
	require.ErrorIs(t, err, ErrUnavailable, "an hour without a successful fetch")
	require.ErrorIs(t, v.Ready(context.Background()), ErrUnavailable)

	e.fail(http.StatusOK)
	require.NoError(t, v.fetch(context.Background()))
	_, err = v.Authenticate(context.Background(), k.sign(t, c.Now(), nil))
	require.NoError(t, err)
}

func TestFetchRefusesRedirectsAndBadKeySets(t *testing.T) {
	k := newSigningKey(t, "k1")
	e := newExchange(t, k)
	c := &clock{now: start}
	v, err := New(Config{JWKSURL: e.server.URL + "/elsewhere", Issuer: issuer, Audience: audience,
		HTTP: e.server.Client(), Now: c.Now})
	require.NoError(t, err)
	require.Error(t, v.fetch(context.Background()), "redirects are not followed")

	v = e.verifier(t, c)
	for _, body := range []string{``, `{}`, `{"keys":[]}`, `{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"AA"}]}`,
		strings.Repeat(" ", maxKeySetBytes+1)} {
		e.mu.Lock()
		e.body = []byte(body)
		e.mu.Unlock()
		require.Error(t, v.fetch(context.Background()), body[:min(len(body), 40)])
	}
	require.Error(t, v.Ready(context.Background()))
}

func TestRunLoadsWithRetryAndStops(t *testing.T) {
	k := newSigningKey(t, "k1")
	e := newExchange(t, k)
	e.fail(http.StatusServiceUnavailable)
	v, err := New(Config{JWKSURL: e.server.URL + "/.well-known/jwks.json", Issuer: issuer, Audience: audience,
		HTTP: e.server.Client()})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		v.Run(ctx)
		close(done)
	}()
	require.Eventually(t, func() bool { return e.fetches.Load() >= 1 }, 5*time.Second, 10*time.Millisecond)
	e.fail(http.StatusOK)
	require.Eventually(t, func() bool { return v.Ready(ctx) == nil }, 10*time.Second, 20*time.Millisecond)
	cancel()
	<-done
}

func TestParseKeySetSkipsUnusableKeys(t *testing.T) {
	good := newSigningKey(t, "good").jwk()
	keys, err := parseKeySet(mustJSON(t, map[string]any{"keys": []any{
		good,
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "no-alg", "x": good["x"]},
		map[string]string{"kty": "OKP", "crv": "X25519", "kid": "x25519", "x": good["x"]},
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "", "x": good["x"]},
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "es256", "alg": "ES256", "x": good["x"]},
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "enc", "use": "enc", "x": good["x"]},
		map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": "short", "x": "AAAA"},
	}}))
	require.NoError(t, err)
	require.Len(t, keys, 2)
	require.Contains(t, keys, "good")
	require.Contains(t, keys, "no-alg")
}

func TestMaxAge(t *testing.T) {
	for header, want := range map[string]time.Duration{
		"":                        maxRefresh,
		"no-store":                maxRefresh,
		"public, max-age=120":     2 * time.Minute,
		"max-age=5":               minRefresh,
		"MAX-AGE=86400":           maxRefresh,
		"max-age=x, max-age=60":   maxRefresh,
		"s-maxage=10, max-age=60": time.Minute,
	} {
		require.Equal(t, want, maxAge(header), header)
	}
}

func TestNewChecksTheConfiguration(t *testing.T) {
	for _, bad := range []Config{
		{JWKSURL: "", Issuer: issuer, Audience: audience},
		{JWKSURL: "http://token.example/.well-known/jwks.json", Issuer: issuer, Audience: audience},
		{JWKSURL: "https://user@token.example/jwks", Issuer: issuer, Audience: audience},
		{JWKSURL: "https://token.example/jwks#x", Issuer: issuer, Audience: audience},
		{JWKSURL: "https://token.example/jwks", Audience: audience},
		{JWKSURL: "https://token.example/jwks", Issuer: issuer},
	} {
		_, err := New(bad)
		require.Error(t, err, bad.JWKSURL)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.TrimSpace(b)
}
