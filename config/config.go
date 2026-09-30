// Package config reads the NATRIUM_PIN_* environment variables of the command. No other package reads the
// environment. Load parses them into a server.Config, validates it and names the variable in every error.
//
// A program that receives the settings under other names, e.g. from a platform, calls LoadFrom and LoadKMSFrom with a
// function that translates the names.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/SchwarzDigits/natrium-pin-service/internal/masterkey"
	"github.com/SchwarzDigits/natrium-pin-service/server"
)

// Environment variable names.
const (
	EnvPort     = "NATRIUM_PIN_PORT"
	EnvLogLevel = "NATRIUM_PIN_LOG_LEVEL"
	// EnvTokenJWKSURL, EnvTokenIssuer and EnvTokenAudience configure the check of the tokens of
	// natrium-token-exchange.
	EnvTokenJWKSURL  = "NATRIUM_PIN_TOKEN_JWKS_URL"
	EnvTokenIssuer   = "NATRIUM_PIN_TOKEN_ISSUER"
	EnvTokenAudience = "NATRIUM_PIN_TOKEN_AUDIENCE"
	EnvDatabaseURL   = "NATRIUM_PIN_DATABASE_URL"
	// EnvLimits is a comma-separated list of <attempts>/<window>, e.g. 5/1h,12/24h.
	EnvLimits = "NATRIUM_PIN_LIMITS"

	EnvKMSProjectID = "NATRIUM_PIN_KMS_PROJECT_ID"
	EnvKMSRegion    = "NATRIUM_PIN_KMS_REGION"
	EnvKMSKeyRingID = "NATRIUM_PIN_KMS_KEY_RING_ID"
	EnvKMSKeyID     = "NATRIUM_PIN_KMS_KEY_ID"
	// EnvKMSServiceAccountKey is the JSON key of the service account, not a path, as JSON or base64-encoded.
	EnvKMSServiceAccountKey = "NATRIUM_PIN_KMS_SERVICE_ACCOUNT_KEY"
	// EnvMasterKeys is a comma-separated list of <keyVersion>:<kmsVersion>:<base64 ciphertext>.
	EnvMasterKeys        = "NATRIUM_PIN_MASTER_KEYS"
	EnvCurrentKeyVersion = "NATRIUM_PIN_CURRENT_KEY_VERSION"
)

const defaultPort = 8080

// envOf maps the fields of server.Config to the variables that set them, for error messages.
var envOf = map[string]string{
	"Addr":          EnvPort,
	"TokenJWKSURL":  EnvTokenJWKSURL,
	"TokenIssuer":   EnvTokenIssuer,
	"TokenAudience": EnvTokenAudience,
	"DatabaseURL":   EnvDatabaseURL,
	"Limits":        EnvLimits,

	"KMSProjectID":         EnvKMSProjectID,
	"KMSRegion":            EnvKMSRegion,
	"KMSKeyRingID":         EnvKMSKeyRingID,
	"KMSKeyID":             EnvKMSKeyID,
	"KMSServiceAccountKey": EnvKMSServiceAccountKey,
	"MasterKeys":           EnvMasterKeys,
	"CurrentKeyVersion":    EnvCurrentKeyVersion,
}

// Config is the configuration of the command.
type Config struct {
	Server   server.Config
	LogLevel slog.Level
}

// Load reads and validates the environment variables.
func Load() (Config, error) {
	return LoadFrom(os.Getenv)
}

// LoadFrom reads and validates the variables through getenv, which returns "" for an unset variable.
func LoadFrom(getenv func(string) string) (Config, error) {
	cfg := Config{Server: server.DefaultConfig(), LogLevel: slog.LevelInfo}
	s := &cfg.Server

	port := defaultPort
	if v := getenv(EnvPort); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return Config{}, fmt.Errorf("%s: must be a port from 1 to 65535, got %q", EnvPort, v)
		}
		port = n
	}
	s.Addr = fmt.Sprintf(":%d", port)

	if v := getenv(EnvLogLevel); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvLogLevel, err)
		}
	}

	s.TokenJWKSURL = getenv(EnvTokenJWKSURL)
	s.TokenIssuer = getenv(EnvTokenIssuer)
	s.TokenAudience = getenv(EnvTokenAudience)
	s.DatabaseURL = getenv(EnvDatabaseURL)
	if v := getenv(EnvLimits); v != "" {
		limits, err := server.ParseLimits(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvLimits, err)
		}
		s.Limits = limits
	}

	kms := loadKMS(getenv)
	s.KMSProjectID, s.KMSRegion, s.KMSKeyRingID, s.KMSKeyID = kms.ProjectID, kms.Region, kms.KeyRingID, kms.KeyID
	s.KMSServiceAccountKey = kms.ServiceAccountKey
	if v := getenv(EnvMasterKeys); v != "" {
		keys, err := server.ParseMasterKeys(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvMasterKeys, err)
		}
		s.MasterKeys = keys
	}
	if v := getenv(EnvCurrentKeyVersion); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Config{}, fmt.Errorf("%s: must be a key version, got %q", EnvCurrentKeyVersion, v)
		}
		s.CurrentKeyVersion = uint32(n)
	}

	if err := s.Validate(); err != nil {
		return Config{}, Named(err)
	}
	return cfg, nil
}

// LoadKMS reads the variables that name the KMS key and the service account, for cmd/new-master-key. All are required.
func LoadKMS() (masterkey.StackitConfig, error) {
	return LoadKMSFrom(os.Getenv)
}

// LoadKMSFrom is LoadKMS with the variables read through getenv.
func LoadKMSFrom(getenv func(string) string) (masterkey.StackitConfig, error) {
	kms := loadKMS(getenv)
	for _, v := range []struct{ name, value string }{
		{EnvKMSProjectID, kms.ProjectID},
		{EnvKMSRegion, kms.Region},
		{EnvKMSKeyRingID, kms.KeyRingID},
		{EnvKMSKeyID, kms.KeyID},
		{EnvKMSServiceAccountKey, kms.ServiceAccountKey},
	} {
		if v.value == "" {
			return masterkey.StackitConfig{}, fmt.Errorf("%s is required", v.name)
		}
	}
	return kms, nil
}

func loadKMS(getenv func(string) string) masterkey.StackitConfig {
	return masterkey.StackitConfig{
		ProjectID:         getenv(EnvKMSProjectID),
		Region:            getenv(EnvKMSRegion),
		KeyRingID:         getenv(EnvKMSKeyRingID),
		KeyID:             getenv(EnvKMSKeyID),
		ServiceAccountKey: getenv(EnvKMSServiceAccountKey),
	}
}

// Named replaces the field name in a *server.ConfigError with the variable that sets the field. server.Run returns
// such errors too, for checks it can only make at start. Other errors, and nil, are returned unchanged.
func Named(err error) error {
	var invalid *server.ConfigError
	if errors.As(err, &invalid) {
		if name, ok := envOf[invalid.Field]; ok {
			return fmt.Errorf("%s: %s", name, invalid.Problem)
		}
	}
	return err
}
