package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/config"
	"github.com/SchwarzDigits/natrium-pin-service/internal/masterkey/masterkeytest"
	"github.com/SchwarzDigits/natrium-pin-service/server"
)

// lockedBuffer collects log output written from several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The command started with only its environment variables serves the probes and the metrics, logs JSON and stops
// when its context is canceled. It needs a PostgreSQL database in NATRIUM_PIN_TEST_DATABASE_URL. Its KMS
// service account fetches tokens from an address nothing listens on, so the master keys do not load and the server
// stays not ready.
func TestRunServesWithEnvironmentVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	databaseURL := os.Getenv("NATRIUM_PIN_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("integration test: NATRIUM_PIN_TEST_DATABASE_URL is not set")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	t.Setenv(config.EnvPort, strconv.Itoa(port))
	t.Setenv(config.EnvLogLevel, "info")
	t.Setenv(config.EnvTokenJWKSURL, "https://127.0.0.1:1/.well-known/jwks.json")
	t.Setenv(config.EnvTokenIssuer, "https://token.example")
	t.Setenv(config.EnvTokenAudience, "https://pin.example")
	t.Setenv(config.EnvDatabaseURL, databaseURL)
	t.Setenv(config.EnvKMSProjectID, "project")
	t.Setenv(config.EnvKMSRegion, "eu01")
	t.Setenv(config.EnvKMSKeyRingID, "ring")
	t.Setenv(config.EnvKMSKeyID, "key")
	t.Setenv(config.EnvKMSServiceAccountKey, masterkeytest.ServiceAccountKey("http://127.0.0.1:1/token"))
	t.Setenv(config.EnvMasterKeys, "1:1:AQ==")
	t.Setenv(config.EnvCurrentKeyVersion, "1")

	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, logs) }()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	get := func(path string) int {
		resp, err := http.Get(base + path)
		if err != nil {
			return 0
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	require.Eventually(t, func() bool { return get(server.PathLive) == http.StatusOK },
		10*time.Second, 20*time.Millisecond, "liveness probe must answer 200")
	require.Equal(t, http.StatusServiceUnavailable, get(server.PathReady))
	require.Equal(t, http.StatusOK, get(server.PathMetrics))
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "decrypting a master key failed") },
		10*time.Second, 20*time.Millisecond)

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return after cancel")
	}
	require.Contains(t, logs.String(), `"msg":"starting server"`)
	require.Contains(t, logs.String(), `"msg":"shutting down"`)
}

func TestRunNamesTheInvalidVariable(t *testing.T) {
	t.Setenv(config.EnvPort, "0")
	require.ErrorContains(t, run(context.Background(), io.Discard), config.EnvPort)
}
