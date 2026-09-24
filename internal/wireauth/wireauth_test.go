package wireauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// token has the form of a Wire access token, with a signature of 64 zero bytes that no backend accepts.
const token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" +
	".v=1.k=1.d=1893456000.t=a.l=.u=39b7f597-dfd1-4dff-86f5-fe1b79cb70a0.c=42"

// fakeWire is a Wire backend that answers GET /v15/self with handler and counts the requests.
type fakeWire struct {
	server   *httptest.Server
	requests atomic.Int32
}

func newFakeWire(t *testing.T, handler http.HandlerFunc) *fakeWire {
	t.Helper()
	f := &fakeWire{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v15/self", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		handler(w, r)
	})
	mux.HandleFunc("/elsewhere", func(http.ResponseWriter, *http.Request) {
		t.Error("the client followed a redirect")
	})
	f.server = httptest.NewTLSServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeWire) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.server.URL+"/v15", f.server.Client())
	require.NoError(t, err)
	return c
}

func answer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func TestAuthenticateReturnsTheQualifiedID(t *testing.T) {
	wire := newFakeWire(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		answer(http.StatusOK, `{"id":"39b7f597-dfd1-4dff-86f5-fe1b79cb70a0","name":"A",`+
			`"qualified_id":{"domain":"Wire.Example","id":"39B7F597-DFD1-4DFF-86F5-FE1B79CB70A0"},"team":"x"}`)(w, r)
	})
	id, err := wire.client(t).Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, QualifiedID{Domain: "wire.example", ID: "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"}, id)
	require.Equal(t, "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0@wire.example", id.String())
}

func TestAuthenticateSeparatesRejectionFromUnavailability(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{"401", answer(http.StatusUnauthorized, `{"code":401,"label":"invalid-credentials"}`), ErrUnauthorized},
		{"403", answer(http.StatusForbidden, `{"code":403}`), ErrUnauthorized},
		{"404", answer(http.StatusNotFound, `{"code":404,"label":"no-endpoint"}`), ErrUnavailable},
		{"500", answer(http.StatusInternalServerError, ``), ErrUnavailable},
		{"502", answer(http.StatusBadGateway, `Bad Gateway`), ErrUnavailable},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, ErrUnavailable},
		{"not JSON", answer(http.StatusOK, `<html>`), ErrUnavailable},
		{"no qualified_id", answer(http.StatusOK, `{"id":"39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"}`), ErrUnavailable},
		{"ID not a UUID", answer(http.StatusOK, `{"qualified_id":{"domain":"wire.example","id":"42"}}`), ErrUnavailable},
		{"bad domain", answer(http.StatusOK,
			`{"qualified_id":{"domain":"wire|example","id":"39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"}}`), ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newFakeWire(t, tc.handler)
			_, err := wire.client(t).Authenticate(context.Background(), token)
			require.ErrorIs(t, err, tc.want)
			require.NotContains(t, err.Error(), token)
			require.EqualValues(t, 1, wire.requests.Load())
		})
	}
}

func TestAuthenticateRejectsImplausibleTokensWithoutAsking(t *testing.T) {
	wire := newFakeWire(t, answer(http.StatusOK, `{}`))
	c := wire.client(t)
	for _, bad := range []string{"", "with space", "line\nbreak", "ümlaut", strings.Repeat("a", maxTokenLength+1)} {
		_, err := c.Authenticate(context.Background(), bad)
		require.ErrorIs(t, err, ErrUnauthorized, "%q", bad)
	}
	require.Zero(t, wire.requests.Load())
}

func TestAuthenticateTimesOut(t *testing.T) {
	release := make(chan struct{})
	wire := newFakeWire(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	c := wire.client(t)
	c.timeout = 50 * time.Millisecond

	start := time.Now()
	_, err := c.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestAuthenticateWithUnreachableBackend(t *testing.T) {
	wire := newFakeWire(t, answer(http.StatusOK, `{}`))
	c := wire.client(t)
	wire.server.Close()
	_, err := c.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotContains(t, err.Error(), token)
}

func TestNewChecksTheURL(t *testing.T) {
	for _, bad := range []string{
		"",
		"nginz-https.wire.example/v15",
		"http://nginz-https.wire.example/v15",
		"https:///v15",
		"https://nginz-https.wire.example/v15?x=1",
		"https://nginz-https.wire.example/v15#x",
		"https://user:pass@nginz-https.wire.example/v15",
	} {
		_, err := New(bad, nil)
		require.Error(t, err, bad)
	}
	c, err := New("https://nginz-https.wire.example/v15/", nil)
	require.NoError(t, err)
	require.Equal(t, "https://nginz-https.wire.example/v15/self", c.selfURL)
}

// The tests against a real backend need NATRIUM_RECOVERY_TEST_WIRE_API_URL, e.g.
// https://nginz-https.wire.example/v15, and are skipped without it.
func liveClient(t *testing.T) *Client {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	apiURL := os.Getenv("NATRIUM_RECOVERY_TEST_WIRE_API_URL")
	if apiURL == "" {
		t.Skip("integration test: NATRIUM_RECOVERY_TEST_WIRE_API_URL is not set")
	}
	c, err := New(apiURL, nil)
	require.NoError(t, err)
	return c
}

// A well-formed token with a signature the backend does not accept is rejected. The test backend answers tokens it
// cannot parse at all, such as "x" or a token with a short signature, with 502, which the client reports as
// ErrUnavailable.
func TestLiveRejectsForeignToken(t *testing.T) {
	c := liveClient(t)
	_, err := c.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnauthorized)
}

// Needs a current access token of the backend in NATRIUM_RECOVERY_TEST_WIRE_TOKEN. It is valid for 15 minutes.
func TestLiveAcceptsToken(t *testing.T) {
	c := liveClient(t)
	liveToken := os.Getenv("NATRIUM_RECOVERY_TEST_WIRE_TOKEN")
	if liveToken == "" {
		t.Skip("integration test: NATRIUM_RECOVERY_TEST_WIRE_TOKEN is not set")
	}
	id, err := c.Authenticate(context.Background(), liveToken)
	require.NoError(t, err)
	require.True(t, isUUID(id.ID))
	require.True(t, isDomain(id.Domain))
	t.Logf("authenticated %s", id)
}
