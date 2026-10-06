// Package httpapi serves POST /v1/evaluate: it checks the token, the request and the key version, counts the
// attempt and evaluates the blinded element with the key of the user's key files of the given receipt key. It also
// serves POST /v1/refund, which gives an attempt back for a receipt signed with that receipt key.
//
// Any web page may call the API (CORS with origin *). CORS only protects credentials that the browser adds by itself,
// such as cookies. The API has none: the client sets the token in the Authorization header, and a page without
// the token gets no further than 401.
//
// Only a valid, authenticated request with an active key version is counted, and only a counted request within the
// limit is evaluated. The token, the blinded element, the evaluated element and the signature of a receipt never
// appear in logs, errors or metrics.
package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/SchwarzDigits/natrium-pin-service/internal/attempts"
	"github.com/SchwarzDigits/natrium-pin-service/internal/evaluator"
	"github.com/SchwarzDigits/natrium-pin-service/internal/receipt"
	"github.com/SchwarzDigits/natrium-pin-service/internal/tokenauth"
)

// Paths of the API.
const (
	PathEvaluate = "/v1/evaluate"
	PathRefund   = "/v1/refund"
)

// maxBodyBytes bounds the request body. A request has at most about 170 bytes.
const maxBodyBytes = 1024

// epoch is the epoch in the info string. Key files cannot be revoked yet, so it is always 0.
const epoch = 0

// preflightMaxAge is how long a browser may cache the answer to a preflight request, in seconds.
const preflightMaxAge = "600"

// Error codes in the body of error responses, {"error": "<code>"}.
const (
	codeBadRequest            = "bad_request"
	codeUnauthorized          = "unauthorized"
	codeKeyVersionUnavailable = "key_version_unavailable"
	codeTooManyAttempts       = "too_many_attempts"
	codeUnknownAttempt        = "unknown_attempt"
	codeInvalidSignature      = "invalid_signature"
	codeUnavailable           = "unavailable"
	codeInternal              = "internal"
)

// Results of a request, in the log and in the metrics.
const (
	resultOK                    = "ok"
	resultLimited               = "limited"
	resultBadRequest            = codeBadRequest
	resultUnauthorized          = codeUnauthorized
	resultKeyVersionUnavailable = codeKeyVersionUnavailable
	resultUnavailable           = codeUnavailable
	resultInternal              = codeInternal
)

var results = []string{
	resultOK, resultLimited, resultBadRequest, resultUnauthorized, resultKeyVersionUnavailable, resultUnavailable,
	resultInternal,
}

// Results of a refund, in the log and in the metrics.
const (
	resultUnknownAttempt   = codeUnknownAttempt
	resultInvalidSignature = codeInvalidSignature
)

var refundResults = []string{
	resultOK, resultBadRequest, resultUnauthorized, resultUnknownAttempt, resultInvalidSignature, resultUnavailable,
}

// Authenticator returns the user of a token of natrium-token-exchange. See tokenauth.Verifier.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (tokenauth.QualifiedID, error)
}

// Counter records an attempt of a user and gives it back for a valid receipt. See attempts.Counter.
type Counter interface {
	Take(ctx context.Context, domain, userID string, refundKey []byte) (attempts.Decision, error)
	Refund(ctx context.Context, domain, userID string, attemptID []byte, valid func(refundKey []byte) bool) (int, error)
}

// Keys holds the master keys. See masterkey.Keys.
type Keys interface {
	Loaded() bool
	Current() uint32
	Get(version uint32) ([]byte, bool)
}

// Options configure the handler. All fields are required.
type Options struct {
	Auth    Authenticator
	Counter Counter
	Keys    Keys
	Log     *slog.Logger
	Metrics prometheus.Registerer
}

// Handler serves the API.
type Handler struct {
	opts       Options
	requests   *prometheus.CounterVec
	refunds    *prometheus.CounterVec
	tokenCheck prometheus.Histogram
}

// New returns the handler and registers its metrics.
func New(opts Options) *Handler {
	h := &Handler{
		opts: opts,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "natrium_pin_evaluate_requests_total",
			Help: "Requests to " + PathEvaluate + " by result.",
		}, []string{"result"}),
		refunds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "natrium_pin_refund_requests_total",
			Help: "Requests to " + PathRefund + " by result.",
		}, []string{"result"}),
		tokenCheck: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "natrium_pin_token_check_duration_seconds",
			Help:    "Duration of the token check, including a fetch of the key set for an unknown kid.",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}),
	}
	for _, r := range results {
		h.requests.WithLabelValues(r)
	}
	for _, r := range refundResults {
		h.refunds.WithLabelValues(r)
	}
	opts.Metrics.MustRegister(h.requests, h.refunds, h.tokenCheck)
	return h
}

// Register adds the API and its preflights to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+PathEvaluate, h.evaluate)
	mux.HandleFunc("OPTIONS "+PathEvaluate, h.preflight)
	mux.HandleFunc("POST "+PathRefund, h.refund)
	mux.HandleFunc("OPTIONS "+PathRefund, h.preflight)
}

type evaluateRequest struct {
	KeyVersion     *uint32 `json:"keyVersion"`
	RefundKey      *string `json:"refundKey"`
	BlindedElement *string `json:"blindedElement"`
}

type evaluateResponse struct {
	KeyVersion       uint32 `json:"keyVersion"`
	EvaluatedElement string `json:"evaluatedElement"`
	// AttemptsRemaining is how many more attempts the user has before a limit is reached. A client whose PIN turns
	// out to be wrong can show it.
	AttemptsRemaining int `json:"attemptsRemaining"`
	// AttemptID names the attempt for its receipt, in standard base64 with padding.
	AttemptID string `json:"attemptId"`
}

type refundRequest struct {
	AttemptID *string `json:"attemptId"`
	Signature *string `json:"signature"`
}

type refundResponse struct {
	AttemptsRemaining int `json:"attemptsRemaining"`
}

// outcome is what a request logs.
type outcome struct {
	result     string
	user       tokenauth.QualifiedID
	keyVersion uint32
	err        error
}

func (h *Handler) evaluate(w http.ResponseWriter, r *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Cache-Control", "no-store")
	o := h.serve(w, r)
	h.requests.WithLabelValues(o.result).Inc()

	attrs := []any{"result", o.result}
	if o.user.ID != "" {
		attrs = append(attrs, "user", o.user.String())
	}
	if o.keyVersion != 0 {
		attrs = append(attrs, "key_version", o.keyVersion)
	}
	switch {
	case o.result == resultInternal:
		h.opts.Log.Error("evaluate", append(attrs, "error", o.err)...)
	case o.err != nil:
		h.opts.Log.Warn("evaluate", append(attrs, "error", o.err)...)
	default:
		h.opts.Log.Info("evaluate", attrs...)
	}
}

// serve answers the request in the order: master keys loaded, token, body with receipt key and element, key version,
// count, evaluate.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) outcome {
	if !h.opts.Keys.Loaded() {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return outcome{result: resultUnavailable, err: errors.New("master keys are not loaded yet")}
	}

	user, o, ok := h.authenticate(w, r)
	if !ok {
		return o
	}

	req, refundKey, element, err := readRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		o.result = resultBadRequest
		return o
	}
	info, err := evaluator.Info(user.Domain, user.ID, epoch, refundKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		o.result, o.err = resultInternal, err
		return o
	}

	o.keyVersion = h.opts.Keys.Current()
	if req.KeyVersion != nil {
		o.keyVersion = *req.KeyVersion
	}
	master, ok := h.opts.Keys.Get(o.keyVersion)
	if !ok {
		writeError(w, http.StatusGone, codeKeyVersionUnavailable)
		o.result = resultKeyVersionUnavailable
		return o
	}

	decision, err := h.opts.Counter.Take(r.Context(), user.Domain, user.ID, refundKey)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		o.result, o.err = resultUnavailable, err
		return o
	}
	if !decision.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(decision.RetryAfter)))
		writeError(w, http.StatusTooManyRequests, codeTooManyAttempts)
		o.result = resultLimited
		return o
	}

	evaluated, err := evaluator.Evaluate(master, info, element)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		o.result, o.err = resultInternal, err
		return o
	}
	writeJSON(w, http.StatusOK, evaluateResponse{
		KeyVersion:        o.keyVersion,
		EvaluatedElement:  base64.StdEncoding.EncodeToString(evaluated),
		AttemptsRemaining: decision.Remaining,
		AttemptID:         base64.StdEncoding.EncodeToString(decision.AttemptID),
	})
	o.result = resultOK
	return o
}

// authenticate checks the bearer token. If it fails, it has answered the request and returns the outcome.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (tokenauth.QualifiedID, outcome, bool) {
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return tokenauth.QualifiedID{}, outcome{result: resultUnauthorized}, false
	}
	start := time.Now()
	user, err := h.opts.Auth.Authenticate(r.Context(), token)
	h.tokenCheck.Observe(time.Since(start).Seconds())
	switch {
	case errors.Is(err, tokenauth.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return tokenauth.QualifiedID{}, outcome{result: resultUnauthorized}, false
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return tokenauth.QualifiedID{}, outcome{result: resultUnavailable, err: err}, false
	}
	return user, outcome{user: user}, true
}

func (h *Handler) refund(w http.ResponseWriter, r *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Cache-Control", "no-store")
	o := h.serveRefund(w, r)
	h.refunds.WithLabelValues(o.result).Inc()

	attrs := []any{"result", o.result}
	if o.user.ID != "" {
		attrs = append(attrs, "user", o.user.String())
	}
	if o.err != nil {
		h.opts.Log.Warn("refund", append(attrs, "error", o.err)...)
		return
	}
	h.opts.Log.Info("refund", attrs...)
}

// serveRefund answers a receipt in the order: token, body, open attempt and signature, give back.
func (h *Handler) serveRefund(w http.ResponseWriter, r *http.Request) outcome {
	user, o, ok := h.authenticate(w, r)
	if !ok {
		return o
	}
	attemptID, encodedID, signature, err := readRefund(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		o.result = resultBadRequest
		return o
	}
	remaining, err := h.opts.Counter.Refund(r.Context(), user.Domain, user.ID, attemptID, func(refundKey []byte) bool {
		return receipt.Verify(refundKey, user.Domain, user.ID, encodedID, signature)
	})
	switch {
	case errors.Is(err, attempts.ErrUnknownAttempt):
		writeError(w, http.StatusNotFound, codeUnknownAttempt)
		o.result = resultUnknownAttempt
		return o
	case errors.Is(err, attempts.ErrInvalidReceipt):
		writeError(w, http.StatusForbidden, codeInvalidSignature)
		o.result = resultInvalidSignature
		return o
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		o.result, o.err = resultUnavailable, err
		return o
	}
	writeJSON(w, http.StatusOK, refundResponse{AttemptsRemaining: remaining})
	o.result = resultOK
	return o
}

// bearerToken returns the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// readRequest decodes the body strictly: one JSON object with known fields and nothing after it, a key version from 1
// if present, a receipt key that is a compressed point of P-256 and a blinded element that is a valid point, both in
// standard base64 with padding.
func readRequest(w http.ResponseWriter, r *http.Request) (evaluateRequest, []byte, evaluator.Element, error) {
	var req evaluateRequest
	if err := decodeBody(w, r, &req); err != nil {
		return evaluateRequest{}, nil, evaluator.Element{}, err
	}
	if req.KeyVersion != nil && *req.KeyVersion == 0 {
		return evaluateRequest{}, nil, evaluator.Element{}, errors.New("key versions start at 1")
	}
	if req.RefundKey == nil {
		return evaluateRequest{}, nil, evaluator.Element{}, errors.New("refundKey is missing")
	}
	refundKey, err := base64.StdEncoding.Strict().DecodeString(*req.RefundKey)
	if err != nil {
		return evaluateRequest{}, nil, evaluator.Element{}, err
	}
	if _, err := receipt.ParseKey(refundKey); err != nil {
		return evaluateRequest{}, nil, evaluator.Element{}, err
	}
	if req.BlindedElement == nil {
		return evaluateRequest{}, nil, evaluator.Element{}, errors.New("blindedElement is missing")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(*req.BlindedElement)
	if err != nil {
		return evaluateRequest{}, nil, evaluator.Element{}, err
	}
	element, err := evaluator.ParseElement(raw)
	if err != nil {
		return evaluateRequest{}, nil, evaluator.Element{}, err
	}
	return req, refundKey, element, nil
}

// readRefund decodes the body of a receipt strictly: an attempt ID of AttemptIDSize bytes and a signature of
// receipt.SignatureSize bytes, both in standard base64 with padding. It also returns the attempt ID as sent, which
// the signature covers.
func readRefund(w http.ResponseWriter, r *http.Request) ([]byte, string, []byte, error) {
	var req refundRequest
	if err := decodeBody(w, r, &req); err != nil {
		return nil, "", nil, err
	}
	if req.AttemptID == nil || req.Signature == nil {
		return nil, "", nil, errors.New("attemptId or signature is missing")
	}
	attemptID, err := base64.StdEncoding.Strict().DecodeString(*req.AttemptID)
	if err != nil || len(attemptID) != attempts.AttemptIDSize {
		return nil, "", nil, errors.New("attemptId is not 16 bytes in standard base64")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(*req.Signature)
	if err != nil || len(signature) != receipt.SignatureSize {
		return nil, "", nil, errors.New("signature is not 64 bytes in standard base64")
	}
	return attemptID, *req.AttemptID, signature, nil
}

// decodeBody decodes a body of at most maxBodyBytes into v: one JSON object with known fields and nothing after it.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON object")
	}
	return nil
}

// retryAfterSeconds rounds d up to whole seconds, at least 1.
func retryAfterSeconds(d time.Duration) int {
	return max(int(math.Ceil(d.Seconds())), 1)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// preflight answers the CORS preflight of a browser: POST with the headers Authorization and Content-Type is allowed
// from any origin.
func (h *Handler) preflight(w http.ResponseWriter, _ *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
	w.WriteHeader(http.StatusNoContent)
}

// allowAnyOrigin lets pages of any origin read the answer, including Retry-After. Credentials are not allowed; the
// API needs none.
func allowAnyOrigin(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
}
