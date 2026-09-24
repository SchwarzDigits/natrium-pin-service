// Package server runs the recovery service of Natrium: the server side of an oblivious pseudorandom function
// (RFC 9497) from which a client derives the key of its key file. The service limits the attempts per Wire user and
// serves its API, the health probes and the metrics on one address.
//
// Programs that read their configuration their own way build a Config, starting from DefaultConfig, and call Run.
// The command in cmd/natrium-recovery-server reads it from NATRIUM_RECOVERY_* environment variables.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/attempts"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/httpapi"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/platform"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/wireauth"
)

// Paths served on Config.Addr.
const (
	PathEvaluate = httpapi.PathEvaluate
	PathLive     = platform.PathLive
	PathReady    = platform.PathReady
	PathMetrics  = platform.PathMetrics
)

// cleanupInterval is the interval at which ended attempt windows are deleted.
const cleanupInterval = time.Hour

// MasterKey is one active version of the master key: the version that key files name, the version of the KMS key that
// encrypted it, and the ciphertext. cmd/new-master-key creates one.
type MasterKey = masterkey.Entry

// ParseMasterKeys reads comma-separated master keys of the form <keyVersion>:<kmsVersion>:<base64 ciphertext>, as
// cmd/new-master-key prints them.
func ParseMasterKeys(s string) ([]MasterKey, error) {
	return masterkey.ParseEntries(s)
}

// Limit allows Attempts evaluations per user within Window. A window starts with the first attempt after the previous
// one ended.
type Limit = attempts.Limit

// ParseLimits reads comma-separated limits of the form <attempts>/<window>, e.g. "5/1h,12/24h".
func ParseLimits(s string) ([]Limit, error) {
	return attempts.ParseLimits(s)
}

// Config configures Run. Start from DefaultConfig: its zero value is not valid.
type Config struct {
	// Addr is the TCP address to listen on, e.g. ":8080". Required.
	Addr string
	// WireAPIURL is the base URL of the Wire API including the API version, e.g.
	// https://nginz-https.wire.example/v15. The server checks every access token with GET /self there. Required.
	WireAPIURL string

	// DatabaseURL is the PostgreSQL connection string. The attempts are counted there, so that all instances share
	// them. Required: there is no store in memory.
	DatabaseURL string
	// Limits bound the evaluations per user. An attempt is evaluated, and counted, only if it is within every limit.
	Limits []Limit

	// KMSProjectID, KMSRegion, KMSKeyRingID and KMSKeyID name the key of the STACKIT KMS that encrypted the master
	// keys. Required.
	KMSProjectID string
	KMSRegion    string
	KMSKeyRingID string
	KMSKeyID     string
	// KMSServiceAccountKey is the JSON key of a service account that may decrypt with that key, including its private
	// key. Required.
	KMSServiceAccountKey string
	// MasterKeys are the active versions of the master key. Key files of other versions can no longer be opened.
	// Required.
	MasterKeys []MasterKey
	// CurrentKeyVersion is the version for new key files. It must be among MasterKeys.
	CurrentKeyVersion uint32
}

// DefaultConfig returns the default limits of 5 attempts per hour and 12 per day. The other required fields are left
// to the caller.
func DefaultConfig() Config {
	return Config{
		Limits: []Limit{{Attempts: 5, Window: time.Hour}, {Attempts: 12, Window: 24 * time.Hour}},
	}
}

// ConfigError reports an invalid field of Config. Field is the Go field name, so that a caller that reads the
// configuration from its own sources can name its own setting in the message.
type ConfigError struct {
	Field   string
	Problem string
}

func (e *ConfigError) Error() string {
	return e.Field + ": " + e.Problem
}

func invalid(field, format string, args ...any) error {
	return &ConfigError{Field: field, Problem: fmt.Sprintf(format, args...)}
}

// Validate checks the configuration. It returns a *ConfigError for the first invalid field.
func (c Config) Validate() error {
	switch {
	case c.Addr == "":
		return invalid("Addr", "is required")
	case c.WireAPIURL == "":
		return invalid("WireAPIURL", "is required, e.g. https://nginz-https.wire.example/v15")
	case c.DatabaseURL == "":
		return invalid("DatabaseURL", "is required")
	case c.KMSProjectID == "":
		return invalid("KMSProjectID", "is required")
	case c.KMSRegion == "":
		return invalid("KMSRegion", "is required, e.g. eu01")
	case c.KMSKeyRingID == "":
		return invalid("KMSKeyRingID", "is required")
	case c.KMSKeyID == "":
		return invalid("KMSKeyID", "is required")
	case c.KMSServiceAccountKey == "":
		return invalid("KMSServiceAccountKey", "is required")
	}
	if err := wireauth.CheckAPIURL(c.WireAPIURL); err != nil {
		return invalid("WireAPIURL", "%v", err)
	}
	if err := attempts.CheckLimits(c.Limits); err != nil {
		return invalid("Limits", "%v", err)
	}
	if err := masterkey.Check(c.MasterKeys); err != nil {
		return invalid("MasterKeys", "%v", err)
	}
	if !slices.ContainsFunc(c.MasterKeys, func(k MasterKey) bool { return k.KeyVersion == c.CurrentKeyVersion }) {
		return invalid("CurrentKeyVersion", "must be one of the versions in MasterKeys, got %d", c.CurrentKeyVersion)
	}
	return nil
}

// Run validates the configuration, connects to the database, applies its migrations and serves until ctx is
// canceled. It then waits for running requests and returns after the shutdown.
//
// Run makes the process not dumpable and turns off core dumps (on Linux). It decrypts the master keys with the KMS in
// the background, retrying failed calls; until all are loaded, the server is not ready. If a master key does not
// decrypt to a sealed master key of its version, Run stops with an error.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	kms, err := masterkey.NewStackit(masterkey.StackitConfig{
		ProjectID:         cfg.KMSProjectID,
		Region:            cfg.KMSRegion,
		KeyRingID:         cfg.KMSKeyRingID,
		KeyID:             cfg.KMSKeyID,
		ServiceAccountKey: cfg.KMSServiceAccountKey,
	})
	if err != nil {
		return invalid("KMSServiceAccountKey", "%v", err)
	}
	return run(ctx, cfg, log, dependencies{kms: kms})
}

// dependencies are what Run creates from the configuration and tests replace with fakes.
type dependencies struct {
	kms masterkey.KMS
	// wireHTTP is the HTTP client for the Wire backend. nil uses a client of its own.
	wireHTTP *http.Client
}

func run(ctx context.Context, cfg Config, log *slog.Logger, deps dependencies) error {
	if err := masterkey.ProtectProcess(); err != nil {
		return err
	}
	pool, err := openDatabase(ctx, cfg.DatabaseURL, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	counter := attempts.New(pool, cfg.Limits)
	cleanupCtx, stopCleanup := context.WithCancel(ctx)
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		counter.CleanUp(cleanupCtx, cleanupInterval, log)
	}()
	defer func() {
		stopCleanup()
		<-cleanupDone
	}()

	// If the master keys cannot be loaded because of the configuration, loading cancels serveCtx and Run returns its
	// error.
	serveCtx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	wire, err := wireauth.New(cfg.WireAPIURL, deps.wireHTTP)
	if err != nil {
		return invalid("WireAPIURL", "%v", err)
	}
	keys := masterkey.New(deps.kms, cfg.MasterKeys, cfg.CurrentKeyVersion, log)
	loadErr := make(chan error, 1)
	go func() {
		err := keys.Load(serveCtx)
		if err != nil {
			stopServing()
		}
		loadErr <- err
	}()

	registry := platform.NewRegistry()
	registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "natrium_recovery_master_key_versions",
		Help: "Number of master key versions loaded.",
	}, func() float64 { return float64(keys.Versions()) }))

	mux := http.NewServeMux()
	httpapi.New(httpapi.Options{
		Auth:    wire,
		Counter: counter,
		Keys:    keys,
		Log:     log,
		Metrics: registry,
	}).Register(mux)
	mux.Handle("GET "+PathLive, platform.OKHandler())
	mux.Handle("GET "+PathReady, platform.ReadyHandler(pool.Ping, keys.Ready))
	mux.Handle("GET "+PathMetrics, platform.MetricsHandler(registry))

	log.Info("starting server", "addr", cfg.Addr, "wire_api_url", cfg.WireAPIURL, "limits", fmt.Sprint(cfg.Limits),
		"current_key_version", cfg.CurrentKeyVersion)
	serveErr := platform.Serve(serveCtx, log, cfg.Addr, platform.Recover(log, mux))

	stopServing()
	err = <-loadErr
	keys.Close()
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("load master keys: %w", err)
	}
	return serveErr
}

// openDatabase connects to PostgreSQL and applies the migrations. If several instances start at once, a session lock
// lets one migrate while the others wait.
func openDatabase(ctx context.Context, databaseURL string, log *slog.Logger) (*pgxpool.Pool, error) {
	poolCfg, err := attempts.PoolConfig(databaseURL)
	if err != nil {
		// pgx removes the password from the connection string in its errors.
		return nil, invalid("DatabaseURL", "%v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	if err := attempts.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	log.Info("database ready, migrations applied", "max_conns", poolCfg.MaxConns)
	return pool, nil
}
