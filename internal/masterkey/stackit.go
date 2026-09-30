package masterkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
)

const userAgent = "natrium-pin-service"

// StackitConfig names a key of the STACKIT KMS (purpose symmetric_encrypt_decrypt, algorithm aes_256_gcm) and the
// service account that may use it.
type StackitConfig struct {
	ProjectID string
	Region    string
	KeyRingID string
	KeyID     string
	// ServiceAccountKey is the JSON key of the service account, including its private key, as JSON or
	// base64-encoded.
	ServiceAccountKey string
}

type stackit struct {
	api *kms.APIClient
	cfg StackitConfig
}

// serviceAccountJSON returns the JSON key of the service account. The value is the JSON itself, or the JSON encoded
// in base64, standard or URL alphabet, with or without padding and line breaks. Deployment platforms that cannot keep a
// multi-line or JSON value intact store it as base64.
func serviceAccountJSON(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		return value, nil
	}
	compact := strings.Join(strings.Fields(value), "")
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(compact)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(decoded)), "{") {
			return string(decoded), nil
		}
	}
	return "", errors.New("the service account key is neither JSON nor base64-encoded JSON")
}

// NewStackit returns a KMS that uses the STACKIT KMS.
func NewStackit(cfg StackitConfig) (KMS, error) {
	return newStackit(cfg)
}

// newStackit takes further options for tests, which point the client to a fake.
func newStackit(cfg StackitConfig, opts ...config.ConfigurationOption) (*stackit, error) {
	// The SDK looks for a private key in STACKIT_PRIVATE_KEY, STACKIT_PRIVATE_KEY_PATH and ~/.stackit/credentials.json
	// before it takes the one in the service account key. Passing it explicitly makes the service account key the
	// only source.
	serviceAccountKey, err := serviceAccountJSON(cfg.ServiceAccountKey)
	if err != nil {
		return nil, err
	}
	var key struct {
		Credentials struct {
			PrivateKey string `json:"privateKey"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(serviceAccountKey), &key); err != nil {
		return nil, errors.New("the service account key is not JSON")
	}
	if key.Credentials.PrivateKey == "" {
		return nil, errors.New("the service account key contains no private key")
	}
	// Not config.WithRegion: this API takes the region per call and refuses it on the client.
	options := append([]config.ConfigurationOption{
		config.WithUserAgent(userAgent),
		config.WithServiceAccountKey(serviceAccountKey),
		config.WithPrivateKey(key.Credentials.PrivateKey),
	}, opts...)
	api, err := kms.NewAPIClient(options...)
	if err != nil {
		return nil, fmt.Errorf("create STACKIT KMS client: %w", err)
	}
	return &stackit{api: api, cfg: cfg}, nil
}

func (s *stackit) Encrypt(ctx context.Context, kmsVersion int64, plaintext []byte) ([]byte, error) {
	res, err := s.api.DefaultAPI.
		Encrypt(ctx, s.cfg.ProjectID, s.cfg.Region, s.cfg.KeyRingID, s.cfg.KeyID, kmsVersion).
		EncryptPayload(kms.EncryptPayload{Data: base64.StdEncoding.EncodeToString(plaintext)}).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("KMS encrypt with key %s version %d: %w", s.cfg.KeyID, kmsVersion, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(res.Data)
	if err != nil {
		return nil, errors.New("the KMS returned a ciphertext that is not base64")
	}
	return ciphertext, nil
}

func (s *stackit) Decrypt(ctx context.Context, kmsVersion int64, ciphertext []byte) ([]byte, error) {
	res, err := s.api.DefaultAPI.
		Decrypt(ctx, s.cfg.ProjectID, s.cfg.Region, s.cfg.KeyRingID, s.cfg.KeyID, kmsVersion).
		DecryptPayload(kms.DecryptPayload{Data: base64.StdEncoding.EncodeToString(ciphertext)}).
		Execute()
	if err != nil {
		return nil, fmt.Errorf("KMS decrypt with key %s version %d: %w", s.cfg.KeyID, kmsVersion, err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(res.Data)
	if err != nil {
		return nil, errors.New("the KMS returned a plaintext that is not base64")
	}
	return plaintext, nil
}
