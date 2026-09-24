package evaluator

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/unicode/norm"
)

var update = flag.Bool("update", false, "rewrite testdata/interop.json")

// interopFile holds fixed values of the whole exchange. interop/check.mjs recomputes the client side with
// @noble/curves, the library Natrium uses, and must arrive at the same values.
var interopFile = filepath.Join("testdata", "interop.json")

type interopVector struct {
	Name             string `json:"name"`
	Master           string `json:"master"`
	Domain           string `json:"domain"`
	UserID           string `json:"userId"`
	Epoch            uint64 `json:"epoch"`
	Info             string `json:"info"`
	SecretKey        string `json:"secretKey"`
	PIN              string `json:"pin"`
	Input            string `json:"input"`
	Blind            string `json:"blind"`
	BlindedElement   string `json:"blindedElement"`
	EvaluatedElement string `json:"evaluatedElement"`
	Output           string `json:"output"`
}

func interopVectors(t *testing.T) []interopVector {
	t.Helper()
	counting := make([]byte, MasterSize)
	for i := range counting {
		counting[i] = byte(i)
	}
	return []interopVector{
		makeVector(t, "digits", counting, "wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0", "123456",
			"3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"),
		// The PIN is given decomposed; the client normalizes it to NFC before it encodes it as UTF-8.
		makeVector(t, "unicode", counting[16:], "schwarz-dev-wire.runs.onstackit.cloud",
			"0f5c3a1e-7b2d-4c8e-9a6f-2d4b8e1c7a90", "Grüße 2026",
			"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"),
	}
}

func makeVector(t *testing.T, name string, masterPart []byte, domain, userID, pin, blindHex string) interopVector {
	t.Helper()
	master := append(append([]byte{}, masterPart...), masterPart...)[:MasterSize]
	info, err := Info(domain, userID, 0)
	require.NoError(t, err)
	key, err := deriveKey(master, info)
	require.NoError(t, err)
	secretKey, err := key.MarshalBinary()
	require.NoError(t, err)
	input := norm.NFC.Bytes([]byte(pin))

	blindBytes, err := hex.DecodeString(blindHex)
	require.NoError(t, err)
	var blinded, evaluated []byte
	output := clientOutput(t, blindBytes, input, func(b []byte) []byte {
		blinded = b
		element, err := ParseElement(b)
		require.NoError(t, err)
		evaluated, err = Evaluate(master, info, element)
		require.NoError(t, err)
		return evaluated
	})
	return interopVector{
		Name:             name,
		Master:           hex.EncodeToString(master),
		Domain:           domain,
		UserID:           userID,
		Epoch:            0,
		Info:             string(info),
		SecretKey:        hex.EncodeToString(secretKey),
		PIN:              pin,
		Input:            hex.EncodeToString(input),
		Blind:            blindHex,
		BlindedElement:   base64.StdEncoding.EncodeToString(blinded),
		EvaluatedElement: base64.StdEncoding.EncodeToString(evaluated),
		Output:           hex.EncodeToString(output),
	}
}

// The committed values must not change: key files depend on them. go test -run TestInteropVectors -update rewrites
// the file, after which interop/check.mjs must be run again.
func TestInteropVectors(t *testing.T) {
	got, err := json.MarshalIndent(interopVectors(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(interopFile, got, 0o644))
	}
	want, err := os.ReadFile(interopFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}

// The vectors also hold with a random blind: the output depends only on master, info and PIN.
func TestInteropOutputDoesNotDependOnTheBlind(t *testing.T) {
	for _, v := range interopVectors(t) {
		master, _ := hex.DecodeString(v.Master)
		input, _ := hex.DecodeString(v.Input)
		client := oprf.NewClient(suite)
		finalize, request, err := client.Blind([][]byte{input})
		require.NoError(t, err)
		blinded, err := request.Elements[0].MarshalBinaryCompress()
		require.NoError(t, err)
		element, err := ParseElement(blinded)
		require.NoError(t, err)
		evaluated, err := Evaluate(master, []byte(v.Info), element)
		require.NoError(t, err)
		e := suite.Group().NewElement()
		require.NoError(t, e.UnmarshalBinary(evaluated))
		outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
		require.NoError(t, err)
		require.Equal(t, v.Output, hex.EncodeToString(outputs[0]), v.Name)
	}
}
