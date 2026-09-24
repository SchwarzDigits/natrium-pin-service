package config_test

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/config"
	"github.com/SchwarzDigits/natrium-recovery-server/server"
)

const (
	wireAPIURL        = "https://nginz-https.wire.example/v15"
	databaseURL       = "postgres://recovery@db.example/recovery"
	serviceAccountKey = `{"credentials":{"privateKey":"key"}}`
)

func setMinimal(t *testing.T) {
	t.Helper()
	t.Setenv(config.EnvWireAPIURL, wireAPIURL)
	t.Setenv(config.EnvDatabaseURL, databaseURL)
	t.Setenv(config.EnvKMSProjectID, "project")
	t.Setenv(config.EnvKMSRegion, "eu01")
	t.Setenv(config.EnvKMSKeyRingID, "ring")
	t.Setenv(config.EnvKMSKeyID, "key")
	t.Setenv(config.EnvKMSServiceAccountKey, serviceAccountKey)
	t.Setenv(config.EnvMasterKeys, "1:1:AQ==")
	t.Setenv(config.EnvCurrentKeyVersion, "1")
}

func TestDefaults(t *testing.T) {
	setMinimal(t)
	cfg, err := config.Load()
	require.NoError(t, err)
	want := server.DefaultConfig()
	want.Addr = ":8080"
	want.WireAPIURL = wireAPIURL
	want.DatabaseURL = databaseURL
	want.KMSProjectID, want.KMSRegion, want.KMSKeyRingID, want.KMSKeyID = "project", "eu01", "ring", "key"
	want.KMSServiceAccountKey = serviceAccountKey
	want.MasterKeys = []server.MasterKey{{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte{1}}}
	want.CurrentKeyVersion = 1
	require.Equal(t, config.Config{Server: want, LogLevel: slog.LevelInfo}, cfg)
}

func TestOverrides(t *testing.T) {
	setMinimal(t)
	t.Setenv(config.EnvPort, "9000")
	t.Setenv(config.EnvLogLevel, "debug")
	t.Setenv(config.EnvLimits, "3/10m, 20/168h")
	t.Setenv(config.EnvMasterKeys, "1:1:AQ==, 2:3:Ag==")
	t.Setenv(config.EnvCurrentKeyVersion, "2")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, ":9000", cfg.Server.Addr)
	require.Equal(t, slog.LevelDebug, cfg.LogLevel)
	require.Equal(t, []server.Limit{{Attempts: 3, Window: 10 * time.Minute}, {Attempts: 20, Window: 168 * time.Hour}},
		cfg.Server.Limits)
	require.Equal(t, []server.MasterKey{
		{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte{1}},
		{KeyVersion: 2, KMSVersion: 3, Ciphertext: []byte{2}},
	}, cfg.Server.MasterKeys)
	require.Equal(t, uint32(2), cfg.Server.CurrentKeyVersion)
}

func TestLoadKMS(t *testing.T) {
	setMinimal(t)
	kms, err := config.LoadKMS()
	require.NoError(t, err)
	require.Equal(t, "project", kms.ProjectID)
	require.Equal(t, "eu01", kms.Region)
	require.Equal(t, "ring", kms.KeyRingID)
	require.Equal(t, "key", kms.KeyID)
	require.Equal(t, serviceAccountKey, kms.ServiceAccountKey)

	for _, name := range []string{config.EnvKMSProjectID, config.EnvKMSRegion, config.EnvKMSKeyRingID,
		config.EnvKMSKeyID, config.EnvKMSServiceAccountKey} {
		t.Run(name, func(t *testing.T) {
			setMinimal(t)
			t.Setenv(name, "")
			_, err := config.LoadKMS()
			require.ErrorContains(t, err, name)
		})
	}
}

func TestNamedReplacesTheFieldWithTheVariable(t *testing.T) {
	err := config.Named(&server.ConfigError{Field: "DatabaseURL", Problem: "is required"})
	require.EqualError(t, err, config.EnvDatabaseURL+": is required")

	unknown := &server.ConfigError{Field: "Unknown", Problem: "is wrong"}
	require.Equal(t, error(unknown), config.Named(unknown))

	other := errors.New("connection refused")
	require.Equal(t, other, config.Named(other))
	require.NoError(t, config.Named(nil))
}

func TestInvalidVariableIsNamedInError(t *testing.T) {
	for _, tc := range []struct {
		name, value string
	}{
		{config.EnvPort, "0"},
		{config.EnvPort, "65536"},
		{config.EnvPort, "http"},
		{config.EnvLogLevel, "loud"},
		{config.EnvWireAPIURL, ""},
		{config.EnvWireAPIURL, "http://nginz-https.wire.example/v15"},
		{config.EnvDatabaseURL, ""},
		{config.EnvLimits, ","},
		{config.EnvLimits, "5"},
		{config.EnvLimits, "0/1h"},
		{config.EnvLimits, "5/1ms"},
		{config.EnvLimits, "5/a day"},
		{config.EnvLimits, "5/1h,6/60m"},
		{config.EnvKMSProjectID, ""},
		{config.EnvKMSRegion, ""},
		{config.EnvKMSKeyRingID, ""},
		{config.EnvKMSKeyID, ""},
		{config.EnvKMSServiceAccountKey, ""},
		{config.EnvMasterKeys, ""},
		{config.EnvMasterKeys, "1:1"},
		{config.EnvMasterKeys, "1:1:AQ==,1:2:AQ=="},
		{config.EnvCurrentKeyVersion, ""},
		{config.EnvCurrentKeyVersion, "2"},
		{config.EnvCurrentKeyVersion, "-1"},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			setMinimal(t)
			t.Setenv(tc.name, tc.value)
			_, err := config.Load()
			require.ErrorContains(t, err, tc.name)
		})
	}
}
