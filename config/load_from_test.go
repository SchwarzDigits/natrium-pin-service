package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/config"
)

func TestLoadFromReadsThroughTheGivenFunction(t *testing.T) {
	vars := map[string]string{
		config.EnvPort:                 "9001",
		config.EnvTokenJWKSURL:         jwksURL,
		config.EnvTokenIssuer:          tokenIssuer,
		config.EnvTokenAudience:        tokenAudience,
		config.EnvDatabaseURL:          databaseURL,
		config.EnvKMSProjectID:         "project",
		config.EnvKMSRegion:            "eu01",
		config.EnvKMSKeyRingID:         "ring",
		config.EnvKMSKeyID:             "key",
		config.EnvKMSServiceAccountKey: serviceAccountKey,
		config.EnvMasterKeys:           "1:1:AQ==",
		config.EnvCurrentKeyVersion:    "1",
	}
	getenv := func(name string) string { return vars[name] }
	cfg, err := config.LoadFrom(getenv)
	require.NoError(t, err)
	require.Equal(t, ":9001", cfg.Server.Addr)
	require.Equal(t, tokenAudience, cfg.Server.TokenAudience)

	kms, err := config.LoadKMSFrom(getenv)
	require.NoError(t, err)
	require.Equal(t, "ring", kms.KeyRingID)

	delete(vars, config.EnvKMSKeyID)
	_, err = config.LoadKMSFrom(getenv)
	require.ErrorContains(t, err, config.EnvKMSKeyID)
}
