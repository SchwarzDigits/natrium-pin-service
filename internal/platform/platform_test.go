package platform_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/platform"
)

func get(t *testing.T, h http.Handler) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Code, rec.Body.String()
}

func ok(context.Context) error { return nil }

func down(context.Context) error { return errors.New("down") }

func TestLiveness(t *testing.T) {
	code, body := get(t, platform.OKHandler())
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "ok", body)
}

func TestReadiness(t *testing.T) {
	code, _ := get(t, platform.ReadyHandler())
	require.Equal(t, http.StatusOK, code, "without checks the server is ready")

	code, _ = get(t, platform.ReadyHandler(ok, ok))
	require.Equal(t, http.StatusOK, code)

	code, body := get(t, platform.ReadyHandler(ok, down))
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, "not ready", body)
}

func TestReadinessChecksHaveADeadline(t *testing.T) {
	var hasDeadline bool
	get(t, platform.ReadyHandler(func(ctx context.Context) error {
		_, hasDeadline = ctx.Deadline()
		return nil
	}))
	require.True(t, hasDeadline)
}

func TestMetricsServeTheRegistry(t *testing.T) {
	code, body := get(t, platform.MetricsHandler(platform.NewRegistry()))
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, body, "go_goroutines")
}

func TestRecoverReturns500OnPanic(t *testing.T) {
	var logs bytes.Buffer
	code, _ := get(t, platform.Recover(platform.NewLogger(&logs, slog.LevelInfo),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })))
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, logs.String(), `"msg":"panic in http handler"`)
}

func TestNewLoggerWritesJSON(t *testing.T) {
	var logs bytes.Buffer
	log := platform.NewLogger(&logs, slog.LevelWarn)
	log.Info("hidden")
	log.Warn("shown", "key", "value")
	require.NotContains(t, logs.String(), "hidden")
	require.Contains(t, logs.String(), `"msg":"shown","key":"value"`)
}

func TestServeReturnsListenErrors(t *testing.T) {
	log := platform.NewLogger(io.Discard, slog.LevelInfo)
	require.Error(t, platform.Serve(context.Background(), log, "127.0.0.1:-1", platform.OKHandler()))
}
