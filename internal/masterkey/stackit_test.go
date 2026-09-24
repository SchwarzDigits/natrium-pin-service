package masterkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	"github.com/stretchr/testify/require"
)

var testStackitConfig = StackitConfig{
	ProjectID:         "project",
	Region:            "eu01",
	KeyRingID:         "ring",
	KeyID:             "key",
	ServiceAccountKey: `{"credentials":{"privateKey":"-----BEGIN PRIVATE KEY-----"}}`,
}

// fakeStackit answers the encrypt and decrypt endpoints of the STACKIT KMS. Its "encryption" reverses the bytes.
func fakeStackit(t *testing.T, status int) *httptest.Server {
	t.Helper()
	handle := func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		version, err := strconv.Atoi(r.PathValue("version"))
		require.NoError(t, err)
		require.Equal(t, 3, version)
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"no"}`))
			return
		}
		var payload struct {
			Data string `json:"data"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		data, err := base64.StdEncoding.DecodeString(payload.Data)
		require.NoError(t, err)
		slices.Reverse(data)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"data": base64.StdEncoding.EncodeToString(data)})
	}
	mux := http.NewServeMux()
	path := "/v1/projects/project/regions/eu01/keyrings/ring/keys/key/versions/{version}/"
	mux.HandleFunc(path+"encrypt", handle)
	mux.HandleFunc(path+"decrypt", handle)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestStackitEncryptsAndDecrypts(t *testing.T) {
	server := fakeStackit(t, http.StatusOK)
	kms, err := newStackit(testStackitConfig, config.WithEndpoint(server.URL), config.WithoutAuthentication())
	require.NoError(t, err)

	ciphertext, err := kms.Encrypt(context.Background(), 3, []byte("abc"))
	require.NoError(t, err)
	require.Equal(t, []byte("cba"), ciphertext)
	plaintext, err := kms.Decrypt(context.Background(), 3, ciphertext)
	require.NoError(t, err)
	require.Equal(t, []byte("abc"), plaintext)
}

func TestStackitReportsErrors(t *testing.T) {
	server := fakeStackit(t, http.StatusForbidden)
	kms, err := newStackit(testStackitConfig, config.WithEndpoint(server.URL), config.WithoutAuthentication())
	require.NoError(t, err)

	_, err = kms.Decrypt(context.Background(), 3, []byte("secret"))
	require.ErrorContains(t, err, "KMS decrypt with key key version 3")
	require.NotContains(t, err.Error(), base64.StdEncoding.EncodeToString([]byte("secret")))
}

func TestStackitNeedsThePrivateKeyInTheServiceAccountKey(t *testing.T) {
	for _, key := range []string{"", "not json", `{"credentials":{}}`} {
		cfg := testStackitConfig
		cfg.ServiceAccountKey = key
		_, err := NewStackit(cfg)
		require.Error(t, err)
	}
}

// Needs a STACKIT KMS key and a service account that may use it:
// NATRIUM_RECOVERY_TEST_KMS_PROJECT_ID, _REGION, _KEY_RING_ID, _KEY_ID, _KEY_VERSION and
// NATRIUM_RECOVERY_TEST_KMS_SERVICE_ACCOUNT_KEY (the JSON key). Skipped without them.
func TestStackitLive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: skipped with -short")
	}
	const prefix = "NATRIUM_RECOVERY_TEST_KMS_"
	cfg := StackitConfig{
		ProjectID:         os.Getenv(prefix + "PROJECT_ID"),
		Region:            os.Getenv(prefix + "REGION"),
		KeyRingID:         os.Getenv(prefix + "KEY_RING_ID"),
		KeyID:             os.Getenv(prefix + "KEY_ID"),
		ServiceAccountKey: os.Getenv(prefix + "SERVICE_ACCOUNT_KEY"),
	}
	version, _ := strconv.ParseInt(os.Getenv(prefix+"KEY_VERSION"), 10, 64)
	if cfg.ProjectID == "" || cfg.ServiceAccountKey == "" || version == 0 {
		t.Skip("integration test: NATRIUM_RECOVERY_TEST_KMS_* is not set")
	}
	kms, err := NewStackit(cfg)
	require.NoError(t, err)
	entry, err := Generate(context.Background(), kms, 1, version)
	require.NoError(t, err)
	keys := New(kms, []Entry{entry}, 1, discard())
	require.NoError(t, keys.Load(context.Background()))
	defer keys.Close()
	require.True(t, keys.Loaded())
}
