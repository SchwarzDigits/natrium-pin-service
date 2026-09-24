package masterkey

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/stackitcloud/stackit-sdk-go/core/config"
	kms "github.com/stackitcloud/stackit-sdk-go/services/kms/v1api"
)

const userAgent = "natrium-recovery-server"

// StackitConfig names a key of the STACKIT KMS (purpose symmetric_encrypt_decrypt, algorithm aes_256_gcm) and the
// service account that may use it.
type StackitConfig struct {
	ProjectID string
	Region    string
	KeyRingID string
	KeyID     string
	// ServiceAccountKey is the JSON key of the service account, including its private key.
	ServiceAccountKey string
}

type stackit struct {
	api *kms.APIClient
	cfg StackitConfig
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
	var key struct {
		Credentials struct {
			PrivateKey string `json:"privateKey"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal([]byte(cfg.ServiceAccountKey), &key); err != nil {
		return nil, errors.New("the service account key is not JSON")
	}
	if key.Credentials.PrivateKey == "" {
		return nil, errors.New("the service account key contains no private key")
	}
	// Not config.WithRegion: this API takes the region per call and refuses it on the client.
	options := append([]config.ConfigurationOption{
		config.WithUserAgent(userAgent),
		config.WithServiceAccountKey(cfg.ServiceAccountKey),
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
