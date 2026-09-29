package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-pin-service/internal/masterkey"
	"github.com/SchwarzDigits/natrium-pin-service/internal/masterkey/masterkeytest"
)

const envTestDatabaseURL = "NATRIUM_PIN_TEST_DATABASE_URL"

// closedAddr returns a local address that nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// serviceAccountKey is created once: an RSA key takes a while. Port 1 of the loopback address is not served.
var serviceAccountKey = sync.OnceValue(func() string {
	return masterkeytest.ServiceAccountKey("http://127.0.0.1:1/token")
})

// valid returns a valid configuration. Its service account key fetches tokens from an address nothing listens on, so
// the real KMS client never reaches STACKIT.
func valid(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Addr = ":8080"
	cfg.TokenJWKSURL = "https://token.example/.well-known/jwks.json"
	cfg.TokenIssuer = "https://token.example"
	cfg.TokenAudience = "https://pin.example"
	cfg.DatabaseURL = "postgres://recovery@db.example/recovery"
	cfg.KMSProjectID = "project"
	cfg.KMSRegion = "eu01"
	cfg.KMSKeyRingID = "ring"
	cfg.KMSKeyID = "key"
	cfg.KMSServiceAccountKey = serviceAccountKey()
	cfg.MasterKeys = []MasterKey{{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte{1}}}
	cfg.CurrentKeyVersion = 1
	return cfg
}

// testDatabaseURL returns the test database from NATRIUM_PIN_TEST_DATABASE_URL, and skips the test without it.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	uri := os.Getenv(envTestDatabaseURL)
	if uri == "" {
		t.Skipf("integration test: %s is not set", envTestDatabaseURL)
	}
	return uri
}

// withMasterKeys sets the master keys of cfg to new keys of the given versions, encrypted by kms.
func withMasterKeys(t *testing.T, cfg *Config, kms masterkey.KMS, versions ...uint32) {
	t.Helper()
	cfg.MasterKeys = nil
	for _, v := range versions {
		entry, err := masterkey.Generate(context.Background(), kms, v, 1)
		require.NoError(t, err)
		cfg.MasterKeys = append(cfg.MasterKeys, entry)
	}
	cfg.CurrentKeyVersion = versions[len(versions)-1]
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.Equal(t, []Limit{{Attempts: 5, Window: time.Hour}, {Attempts: 12, Window: 24 * time.Hour}}, cfg.Limits)

	var invalid *ConfigError
	require.ErrorAs(t, cfg.Validate(), &invalid)
	require.NoError(t, valid(t).Validate())
}

func TestValidateNamesTheField(t *testing.T) {
	for _, tc := range []struct {
		field  string
		change func(*Config)
	}{
		{"Addr", func(c *Config) { c.Addr = "" }},
		{"TokenJWKSURL", func(c *Config) { c.TokenJWKSURL = "" }},
		{"TokenJWKSURL", func(c *Config) { c.TokenJWKSURL = "http://token.example/.well-known/jwks.json" }},
		{"TokenIssuer", func(c *Config) { c.TokenIssuer = "" }},
		{"TokenAudience", func(c *Config) { c.TokenAudience = "" }},
		{"DatabaseURL", func(c *Config) { c.DatabaseURL = "" }},
		{"Limits", func(c *Config) { c.Limits = nil }},
		{"Limits", func(c *Config) { c.Limits = []Limit{{Attempts: 0, Window: time.Hour}} }},
		{"Limits", func(c *Config) { c.Limits = []Limit{{Attempts: 5, Window: time.Millisecond}} }},
		{"KMSProjectID", func(c *Config) { c.KMSProjectID = "" }},
		{"KMSRegion", func(c *Config) { c.KMSRegion = "" }},
		{"KMSKeyRingID", func(c *Config) { c.KMSKeyRingID = "" }},
		{"KMSKeyID", func(c *Config) { c.KMSKeyID = "" }},
		{"KMSServiceAccountKey", func(c *Config) { c.KMSServiceAccountKey = "" }},
		{"MasterKeys", func(c *Config) { c.MasterKeys = nil }},
		{"MasterKeys", func(c *Config) { c.MasterKeys = append(c.MasterKeys, c.MasterKeys[0]) }},
		{"CurrentKeyVersion", func(c *Config) { c.CurrentKeyVersion = 2 }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			cfg := valid(t)
			tc.change(&cfg)
			var invalid *ConfigError
			require.ErrorAs(t, cfg.Validate(), &invalid)
			require.Equal(t, tc.field, invalid.Field)
		})
	}
}

func TestParseMasterKeys(t *testing.T) {
	keys, err := ParseMasterKeys("1:1:AQ==, 2:1:Ag==")
	require.NoError(t, err)
	require.Equal(t, []MasterKey{
		{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte{1}},
		{KeyVersion: 2, KMSVersion: 1, Ciphertext: []byte{2}},
	}, keys)
}

func TestRunRejectsInvalidConfig(t *testing.T) {
	var invalid *ConfigError
	err := Run(context.Background(), DefaultConfig(), slog.New(slog.DiscardHandler))
	require.ErrorAs(t, err, &invalid)
}

func TestRunRejectsAServiceAccountKeyWithoutPrivateKey(t *testing.T) {
	cfg := valid(t)
	cfg.KMSServiceAccountKey = `{"credentials":{}}`
	var invalid *ConfigError
	require.ErrorAs(t, Run(context.Background(), cfg, slog.New(slog.DiscardHandler)), &invalid)
	require.Equal(t, "KMSServiceAccountKey", invalid.Field)
}

func TestRunNamesAnUnparsableDatabaseURL(t *testing.T) {
	cfg := valid(t)
	cfg.DatabaseURL = "postgres://recovery:secret-password@db.example:port/recovery"
	var invalid *ConfigError
	err := Run(context.Background(), cfg, slog.New(slog.DiscardHandler))
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "DatabaseURL", invalid.Field)
	require.NotContains(t, err.Error(), "secret-password")
}

func TestRunFailsWithoutDatabase(t *testing.T) {
	cfg := valid(t)
	cfg.DatabaseURL = "postgres://recovery:secret-password@" + closedAddr(t) + "/recovery?connect_timeout=2"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := Run(ctx, cfg, slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret-password")
}

// get returns the status code of a GET request, or 0 if the request fails.
func get(url string) int {
	resp, err := http.Get(url)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// running is a server started by start.
type running struct {
	addr   string
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// wait returns run's result once it has returned, and fails the test if that takes longer than 15 seconds.
func (r *running) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-r.done:
		return r.err
	case <-time.After(15 * time.Second):
		t.Fatal("run did not return")
		return nil
	}
}

// start runs the server with deps until the test ends.
func start(t *testing.T, cfg Config, deps dependencies) *running {
	t.Helper()
	cfg.Addr = closedAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{addr: cfg.Addr, cancel: cancel, done: make(chan struct{})}
	go func() {
		r.err = run(ctx, cfg, slog.New(slog.DiscardHandler), deps)
		close(r.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

func TestRunServesUntilCanceled(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1, 2)
	deps := dependencies{kms: kms}
	newFakeExchange(t).use(&cfg, &deps)
	r := start(t, cfg, deps)

	require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
		10*time.Second, 20*time.Millisecond, "readiness probe must answer 200")
	require.Equal(t, http.StatusOK, get("http://"+r.addr+PathLive))
	require.Equal(t, http.StatusOK, get("http://"+r.addr+PathMetrics))
	require.Equal(t, http.StatusNotFound, get("http://"+r.addr+"/unknown"))

	r.cancel()
	require.NoError(t, r.wait(t))
	require.Zero(t, get("http://"+r.addr+PathLive), "the server must not accept connections after run returned")
}

func TestRunIsNotReadyUntilTheMasterKeysAreLoaded(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1)
	kms.FailDecrypt(1)
	deps := dependencies{kms: kms}
	newFakeExchange(t).use(&cfg, &deps)
	r := start(t, cfg, deps)

	require.Eventually(t, func() bool { return get("http://"+r.addr+PathLive) == http.StatusOK },
		10*time.Second, 20*time.Millisecond)
	require.Equal(t, http.StatusServiceUnavailable, get("http://"+r.addr+PathReady))
	// The first decrypt failed; the retry after one second succeeds.
	require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
		10*time.Second, 50*time.Millisecond)
}

func TestRunIsNotReadyUntilTheKeySetIsLoaded(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1)
	deps := dependencies{kms: kms}
	exchange := newFakeExchange(t)
	exchange.down.Store(true)
	exchange.use(&cfg, &deps)
	r := start(t, cfg, deps)

	require.Eventually(t, func() bool { return get("http://"+r.addr+PathLive) == http.StatusOK },
		10*time.Second, 20*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, http.StatusServiceUnavailable, get("http://"+r.addr+PathReady), "no key set yet")
	exchange.down.Store(false)
	require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
		10*time.Second, 50*time.Millisecond, "the key set is fetched again with backoff")
}

func TestRunStopsOnAMasterKeyOfAnotherVersion(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	withMasterKeys(t, &cfg, kms, 1, 2)
	cfg.MasterKeys[0].Ciphertext, cfg.MasterKeys[1].Ciphertext = cfg.MasterKeys[1].Ciphertext, cfg.MasterKeys[0].Ciphertext
	r := start(t, cfg, dependencies{kms: kms})
	require.ErrorContains(t, r.wait(t), "belongs to key version 2")
}
