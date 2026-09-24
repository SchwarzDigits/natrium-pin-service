package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey/masterkeytest"
)

// fakeWire answers GET /v15/self for the token "token-<uuid>" with that user.
func fakeWire(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v15/self", func(w http.ResponseWriter, r *http.Request) {
		id, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer token-")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"qualified_id":{"domain":"wire.example","id":%q}}`, id)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newUserID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// evaluate runs the client side for pin against the server at addr and returns the status, the Retry-After header
// and, for 200, the OPRF output.
func evaluate(t *testing.T, addr, token, pin string) (int, string, []byte) {
	t.Helper()
	client := oprf.NewClient(oprf.SuiteP256)
	finalize, request, err := client.Blind([][]byte{[]byte(pin)})
	require.NoError(t, err)
	blinded, err := request.Elements[0].MarshalBinaryCompress()
	require.NoError(t, err)

	body := `{"blindedElement":"` + base64.StdEncoding.EncodeToString(blinded) + `"}`
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+PathEvaluate, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, resp.Header.Get("Retry-After"), nil
	}

	var answer struct {
		KeyVersion       uint32 `json:"keyVersion"`
		EvaluatedElement string `json:"evaluatedElement"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	evaluated, err := base64.StdEncoding.DecodeString(answer.EvaluatedElement)
	require.NoError(t, err)
	e := oprf.SuiteP256.Group().NewElement()
	require.NoError(t, e.UnmarshalBinary(evaluated))
	outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
	require.NoError(t, err)
	return resp.StatusCode, "", outputs[0]
}

// Two instances at one database: they give the same output for the same PIN, and together they allow 5 attempts per
// user and hour. The 6th is answered with 429 and Retry-After, and another user is not affected.
func TestTwoInstancesShareTheLimit(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	wire := fakeWire(t)
	cfg := valid(t)
	cfg.DatabaseURL = testDatabaseURL(t)
	cfg.WireAPIURL = wire.URL + "/v15"
	withMasterKeys(t, &cfg, kms, 1)
	deps := dependencies{kms: kms, wireHTTP: wire.Client()}
	instances := []*running{start(t, cfg, deps), start(t, cfg, deps)}
	for _, r := range instances {
		require.Eventually(t, func() bool { return get("http://"+r.addr+PathReady) == http.StatusOK },
			10*time.Second, 20*time.Millisecond)
	}

	token := "token-" + newUserID()
	var first []byte
	for i := range 5 {
		status, _, output := evaluate(t, instances[i%2].addr, token, "123456")
		require.Equal(t, http.StatusOK, status, "attempt %d", i+1)
		if first == nil {
			first = output
		}
		require.Equal(t, first, output, "attempt %d", i+1)
	}

	status, retryAfter, _ := evaluate(t, instances[0].addr, token, "123456")
	require.Equal(t, http.StatusTooManyRequests, status)
	seconds, err := strconv.Atoi(retryAfter)
	require.NoError(t, err)
	require.Greater(t, seconds, 60*60-60)
	require.LessOrEqual(t, seconds, 60*60)

	status, _, _ = evaluate(t, instances[1].addr, "token-"+newUserID(), "123456")
	require.Equal(t, http.StatusOK, status)

	status, _, _ = evaluate(t, instances[1].addr, "not-a-token", "123456")
	require.Equal(t, http.StatusUnauthorized, status)
}
