// Package tokenauth checks the tokens of natrium-token-exchange: JSON Web Tokens signed with EdDSA over Ed25519, which
// the service verifies offline with the exchange's key set. The service never sees a Wire access token.
//
// A token is accepted only if its algorithm is EdDSA, its kid names a key of the key set and the signature verifies,
// iss and aud are the configured ones, and exp, nbf and iat hold with a small allowance for clock skew. The user is
// the qualified ID in sub.
//
// The key set is loaded from an https URL, kept for its max-age (at most five minutes) and then fetched again. A
// token with an unknown kid makes the verifier fetch it again, at most once per minute, so a new signing key is
// accepted soon after it is published. A failed fetch keeps the previous key set, for up to an hour after it was
// loaded; after that the verifier refuses to check tokens until a fetch succeeds, so that a signing key removed after a
// leak cannot stay accepted for good.
package tokenauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	algorithm = "EdDSA"
	// maxRefresh bounds how long a key set is kept, and is used when its answer names no max-age.
	maxRefresh = 5 * time.Minute
	// minRefresh bounds how often the key set is fetched on schedule.
	minRefresh = 30 * time.Second
	// unknownKeyRefetch bounds the extra fetches that tokens with an unknown kid cause.
	unknownKeyRefetch = time.Minute
	// fetchTimeout bounds one fetch of the key set.
	fetchTimeout = 5 * time.Second
	// minRetry and maxRetry bound the wait between failed fetches.
	minRetry = time.Second
	maxRetry = time.Minute
	// maxKeySetBytes bounds the key set that is read.
	maxKeySetBytes = 64 << 10
	// maxTokenLength bounds the tokens that are parsed. A token has about 500 characters.
	maxTokenLength = 4096
	// leeway allows for clock skew between the exchange and this service.
	leeway = 30 * time.Second
	// staleLimit is how long a key set is used when fetching it again fails.
	staleLimit = time.Hour
)

var (
	// ErrUnauthorized reports a missing token or a token that is not accepted.
	ErrUnauthorized = errors.New("tokenauth: the token was rejected")
	// ErrUnavailable reports that no key set has been loaded yet, or that the last one is older than an hour.
	ErrUnavailable = errors.New("tokenauth: no current key set")

	errUnknownKey = errors.New("tokenauth: no key with this kid")
)

// QualifiedID identifies a Wire user across backends. Domain is lowercase and ID is a lowercase UUID in the form
// 8-4-4-4-12.
type QualifiedID struct {
	Domain string
	ID     string
}

// String returns the ID in the form Wire writes it, ID@domain.
func (q QualifiedID) String() string {
	return q.ID + "@" + q.Domain
}

// CheckJWKSURL reports whether s can be the URL of the key set: an https URL with a host and without user
// information or fragment.
func CheckJWKSURL(s string) error {
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return fmt.Errorf("is not a URL: %w", err)
	case u.Scheme != "https" || u.Host == "":
		return errors.New("must be an https URL with a host, e.g. https://token.example/.well-known/jwks.json")
	case u.Fragment != "" || u.User != nil:
		return errors.New("must not have a fragment or user information")
	}
	return nil
}

// Config configures a Verifier.
type Config struct {
	// JWKSURL is the key set of the exchange, e.g. https://token.example/.well-known/jwks.json.
	JWKSURL string
	// Issuer is the expected iss, e.g. https://token.example.
	Issuer string
	// Audience is this service's name, the expected aud, e.g. https://pin.example.
	Audience string
	// HTTP is the client for the key set. nil uses a client of its own. Redirects are never followed.
	HTTP *http.Client
	// Now returns the current time. nil uses time.Now.
	Now func() time.Time
	// Log receives the outcome of fetches. nil discards it.
	Log *slog.Logger
}

// keySet is one loaded key set.
type keySet struct {
	keys     map[string]ed25519.PublicKey
	maxAge   time.Duration
	loadedAt time.Time
}

// Verifier checks tokens. It is safe for concurrent use.
type Verifier struct {
	cfg    Config
	http   *http.Client
	parser *jwt.Parser

	set atomic.Pointer[keySet]
	// fetchMu serializes fetches. lastFetch is the start of the last fetch and is guarded by it.
	fetchMu   sync.Mutex
	lastFetch time.Time
}

// New returns a verifier. It loads no key set; Run does.
func New(cfg Config) (*Verifier, error) {
	if err := CheckJWKSURL(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("tokenauth: key set URL %w", err)
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("tokenauth: issuer and audience are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	c := http.Client{}
	if cfg.HTTP != nil {
		c = *cfg.HTTP
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Verifier{
		cfg:  cfg,
		http: &c,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{algorithm}),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(leeway),
			jwt.WithTimeFunc(cfg.Now),
		),
	}, nil
}

// Run loads the key set, retrying with backoff until it succeeds, and then fetches it again whenever its max-age has
// passed, until ctx is canceled. A failed fetch keeps the previous key set and is retried with backoff.
func (v *Verifier) Run(ctx context.Context) {
	retry := minRetry
	for {
		wait := retry
		if err := v.fetch(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			v.cfg.Log.Warn("key set not loaded", "url", v.cfg.JWKSURL, "error", err, "retry_in", retry.String())
			retry = min(2*retry, maxRetry)
		} else {
			retry = minRetry
			wait = v.set.Load().maxAge
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Ready returns an error while there is no current key set: before the first one is loaded, and when the last one
// is older than an hour. It serves the readiness probe.
func (v *Verifier) Ready(context.Context) error {
	if v.current() == nil {
		return ErrUnavailable
	}
	return nil
}

// current returns the key set if it was loaded less than staleLimit ago.
func (v *Verifier) current() *keySet {
	set := v.set.Load()
	if set == nil || v.cfg.Now().Sub(set.loadedAt) >= staleLimit {
		return nil
	}
	return set
}

// Authenticate returns the user of token. It returns ErrUnavailable if there is no current key set, and
// ErrUnauthorized, wrapped with the reason, for a token that is not accepted. Errors never contain the token.
func (v *Verifier) Authenticate(ctx context.Context, token string) (QualifiedID, error) {
	if v.current() == nil {
		return QualifiedID{}, ErrUnavailable
	}
	if token == "" || len(token) > maxTokenLength {
		return QualifiedID{}, ErrUnauthorized
	}
	var claims jwt.RegisteredClaims
	if _, err := v.parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
		return v.key(ctx, t)
	}); err != nil {
		return QualifiedID{}, fmt.Errorf("%w: %s", ErrUnauthorized, reason(err))
	}
	id, err := parseSubject(claims.Subject)
	if err != nil {
		return QualifiedID{}, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	return id, nil
}

// reason names why the parser refused a token, without the token.
func reason(err error) string {
	for _, known := range []error{
		errUnknownKey, jwt.ErrTokenMalformed, jwt.ErrTokenSignatureInvalid, jwt.ErrTokenExpired,
		jwt.ErrTokenNotValidYet, jwt.ErrTokenUsedBeforeIssued, jwt.ErrTokenInvalidIssuer,
		jwt.ErrTokenInvalidAudience, jwt.ErrTokenRequiredClaimMissing,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "invalid token"
}

// key returns the public key that t names, fetching the key set again if the kid is unknown and the last fetch was at
// least unknownKeyRefetch ago.
func (v *Verifier) key(ctx context.Context, t *jwt.Token) (ed25519.PublicKey, error) {
	kid, _ := t.Header["kid"].(string)
	if k, ok := v.set.Load().keys[kid]; ok {
		return k, nil
	}
	if v.fetchIfStale(ctx) {
		if k, ok := v.set.Load().keys[kid]; ok {
			return k, nil
		}
	}
	return nil, errUnknownKey
}

// fetchIfStale fetches the key set if the last fetch started at least unknownKeyRefetch ago. It reports whether it
// fetched successfully.
func (v *Verifier) fetchIfStale(ctx context.Context) bool {
	v.fetchMu.Lock()
	stale := v.cfg.Now().Sub(v.lastFetch) >= unknownKeyRefetch
	v.fetchMu.Unlock()
	if !stale {
		return false
	}
	if err := v.fetch(ctx); err != nil {
		v.cfg.Log.Warn("key set not refreshed for an unknown kid", "url", v.cfg.JWKSURL, "error", err)
		return false
	}
	return true
}

// fetch loads the key set and replaces the current one.
func (v *Verifier) fetch(ctx context.Context) error {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	v.lastFetch = v.cfg.Now()

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET key set answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxKeySetBytes {
		return fmt.Errorf("the key set is larger than %d bytes", maxKeySetBytes)
	}
	keys, err := parseKeySet(body)
	if err != nil {
		return err
	}
	set := &keySet{keys: keys, maxAge: maxAge(resp.Header.Get("Cache-Control")), loadedAt: v.cfg.Now()}
	v.set.Store(set)
	v.cfg.Log.Info("key set loaded", "keys", len(keys), "max_age", set.maxAge.String())
	return nil
}

// parseKeySet returns the usable keys of a JSON Web Key Set: Ed25519 keys (kty OKP, crv Ed25519) with a kid, whose
// alg and use, if given, are EdDSA and sig. Other keys are skipped. At least one usable key is required.
func parseKeySet(body []byte) (map[string]ed25519.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode the key set: %w", err)
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid == "" || (k.Alg != "" && k.Alg != algorithm) ||
			(k.Use != "" && k.Use != "sig") {
			continue
		}
		x, err := base64.RawURLEncoding.Strict().DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		keys[k.Kid] = ed25519.PublicKey(x)
	}
	if len(keys) == 0 {
		return nil, errors.New("the key set has no usable Ed25519 key")
	}
	return keys, nil
}

// maxAge reads max-age from a Cache-Control header and bounds it to minRefresh and maxRefresh. Without one it is
// maxRefresh.
func maxAge(cacheControl string) time.Duration {
	for _, directive := range strings.Split(cacheControl, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if !ok || !strings.EqualFold(name, "max-age") {
			continue
		}
		seconds, err := strconv.Atoi(value)
		if err != nil {
			break
		}
		return min(max(time.Duration(seconds)*time.Second, minRefresh), maxRefresh)
	}
	return maxRefresh
}

// parseSubject reads sub as a qualified ID <uuid>@<domain>, in lowercase.
func parseSubject(sub string) (QualifiedID, error) {
	id, domain, ok := strings.Cut(strings.ToLower(sub), "@")
	if !ok || !isUUID(id) || !isDomain(domain) {
		return QualifiedID{}, errors.New("sub is not a qualified ID")
	}
	return QualifiedID{Domain: domain, ID: id}, nil
}

// isDomain reports whether s consists of lowercase letters, digits, hyphens and dots, at most 253 characters.
func isDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// isUUID reports whether s is a UUID in the form 8-4-4-4-12 with lowercase hexadecimal digits.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
