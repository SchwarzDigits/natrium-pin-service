package evaluator

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/stretchr/testify/require"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func element(t *testing.T, s string) Element {
	t.Helper()
	e, err := ParseElement(unhex(t, s))
	require.NoError(t, err)
	return e
}

// RFC 9497, appendix A.3.1: P256-SHA256, mode OPRF.
const (
	rfcSeed    = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"
	rfcKeyInfo = "74657374206b6579"
	rfcSkSm    = "159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"
	rfcBlind   = "3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"
)

var rfcVectors = []struct {
	input, blindedElement, evaluationElement, output string
}{
	{
		input:             "00",
		blindedElement:    "03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d",
		evaluationElement: "030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832",
		output:            "a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd",
	},
	{
		input:             "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
		blindedElement:    "03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838",
		evaluationElement: "03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c",
		output:            "c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce",
	},
}

func TestDeriveKeyMatchesRFC9497(t *testing.T) {
	key, err := deriveKey(unhex(t, rfcSeed), unhex(t, rfcKeyInfo))
	require.NoError(t, err)
	sk, err := key.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, rfcSkSm, hex.EncodeToString(sk))
}

func TestEvaluateMatchesRFC9497(t *testing.T) {
	for _, v := range rfcVectors {
		t.Run(v.input, func(t *testing.T) {
			evaluated, err := Evaluate(unhex(t, rfcSeed), unhex(t, rfcKeyInfo), element(t, v.blindedElement))
			require.NoError(t, err)
			require.Equal(t, v.evaluationElement, hex.EncodeToString(evaluated))

			// The client side with the vector's blind gives the vector's blinded element and output.
			output := clientOutput(t, unhex(t, rfcBlind), unhex(t, v.input), func(blinded []byte) []byte {
				require.Equal(t, v.blindedElement, hex.EncodeToString(blinded))
				return evaluated
			})
			require.Equal(t, v.output, hex.EncodeToString(output))
		})
	}
}

// Fixed values for our info encoding. If this test fails, existing key files can no longer be decrypted.
// exampleRefundKey is the receipt key of the examples in docs/protocol.md.
const exampleRefundKey = "A7RAoFrwwW6LPWoswV51l5MYJ3IkumhNz2Wk3KgW8xku"

func refundKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(exampleRefundKey)
	require.NoError(t, err)
	return key
}

func TestInfoEncodingIsFixed(t *testing.T) {
	info, err := Info("wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0", 0, refundKey(t))
	require.NoError(t, err)
	require.Equal(t, "natrium-recovery-v2|wire.example|39b7f597-dfd1-4dff-86f5-fe1b79cb70a0|0|"+exampleRefundKey,
		string(info))

	info, err = Info("wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0", 12, refundKey(t))
	require.NoError(t, err)
	require.Equal(t, "natrium-recovery-v2|wire.example|39b7f597-dfd1-4dff-86f5-fe1b79cb70a0|12|"+exampleRefundKey,
		string(info))

	master := make([]byte, MasterSize)
	for i := range master {
		master[i] = byte(i)
	}
	info, err = Info("wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0", 0, refundKey(t))
	require.NoError(t, err)
	key, err := deriveKey(master, info)
	require.NoError(t, err)
	sk, err := key.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, "d3e29efe18859211267ca8afc6540d9afc9e4ca32b364a121e56cfd8e135a5e6", hex.EncodeToString(sk))

	blinded := "038685b582b12819611d877c17a39c29b460fb3a9e68a66799bcb97d6b05eefc4c"
	evaluated, err := Evaluate(master, info, element(t, blinded))
	require.NoError(t, err)
	require.Equal(t, "02c06abab8686496eee00103d8874d92c402771b79b9eba016fadf5586105cc369", hex.EncodeToString(evaluated))

	output := clientOutput(t, unhex(t, rfcBlind), []byte("123456"), func(b []byte) []byte {
		require.Equal(t, blinded, hex.EncodeToString(b))
		return evaluated
	})
	require.Equal(t, "cdb5a6c8ce1a0fa5ace124e069ab15e2f7802c768720108ca630db2f922344a9", hex.EncodeToString(output))
}

func TestInfoRejectsOtherForms(t *testing.T) {
	const id = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	for _, tc := range []struct{ domain, userID string }{
		{"", id},
		{"Wire.example", id},
		{"wire.example|x", id},
		{"wire example", id},
		{string(bytes.Repeat([]byte("a"), 254)), id},
		{"wire.example", "39B7F597-DFD1-4DFF-86F5-FE1B79CB70A0"},
		{"wire.example", "39b7f597dfd14dff86f5fe1b79cb70a0"},
		{"wire.example", "{39b7f597-dfd1-4dff-86f5-fe1b79cb70a0}"},
		{"wire.example", "39b7f597-dfd1-4dff-86f5-fe1b79cb70ag"},
		{"wire.example", "39b7f597-dfd1-4dff-86f5+fe1b79cb70a0"},
		{"wire.example", ""},
	} {
		_, err := Info(tc.domain, tc.userID, 0, refundKey(t))
		require.Error(t, err, "domain %q, user ID %q", tc.domain, tc.userID)
	}
	for _, key := range [][]byte{nil, refundKey(t)[:31], append(refundKey(t), 0)} {
		_, err := Info("wire.example", id, 0, key)
		require.Error(t, err, "refund key of %d bytes", len(key))
	}
}

func TestParseElementRejectsInvalidEncodings(t *testing.T) {
	valid := unhex(t, rfcVectors[0].blindedElement)
	g := suite.Group()
	uncompressed, err := g.NewElement().MulGen(g.RandomScalar(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))).MarshalBinary()
	require.NoError(t, err)
	require.Len(t, uncompressed, 65)

	for name, b := range map[string][]byte{
		"empty":        nil,
		"identity":     {0x00},
		"too short":    valid[:32],
		"too long":     append(append([]byte{}, valid...), 0),
		"uncompressed": uncompressed,
		"wrong prefix": append([]byte{0x04}, valid[1:]...),
		"not on curve": append([]byte{0x02}, bytes.Repeat([]byte{0xff}, 32)...),
	} {
		_, err := ParseElement(b)
		require.ErrorIs(t, err, ErrInvalidElement, name)
	}
}

func TestEvaluateRejectsBadInput(t *testing.T) {
	_, err := Evaluate(make([]byte, MasterSize), []byte("info"), Element{})
	require.ErrorIs(t, err, ErrInvalidElement)

	_, err = Evaluate(make([]byte, MasterSize-1), []byte("info"), element(t, rfcVectors[0].blindedElement))
	require.Error(t, err)
}

// A full run with the CIRCL client: the same PIN gives the same output with any blind, and another user or another
// master gives another output.
func TestRoundTripWithClient(t *testing.T) {
	master1 := bytes.Repeat([]byte{1}, MasterSize)
	master2 := bytes.Repeat([]byte{2}, MasterSize)
	alice, err := Info("wire.example", "11111111-1111-4111-8111-111111111111", 0, refundKey(t))
	require.NoError(t, err)
	bob, err := Info("wire.example", "22222222-2222-4222-8222-222222222222", 0, refundKey(t))
	require.NoError(t, err)
	otherKey := append([]byte{}, refundKey(t)...)
	otherKey[0] ^= 1
	aliceOtherFile, err := Info("wire.example", "11111111-1111-4111-8111-111111111111", 0, otherKey)
	require.NoError(t, err)
	pin := []byte("123456")

	run := func(master, info, input []byte) []byte {
		client := oprf.NewClient(suite)
		finalize, request, err := client.Blind([][]byte{input})
		require.NoError(t, err)
		blinded, err := request.Elements[0].MarshalBinaryCompress()
		require.NoError(t, err)
		parsed, err := ParseElement(blinded)
		require.NoError(t, err)
		evaluated, err := Evaluate(master, info, parsed)
		require.NoError(t, err)
		e := suite.Group().NewElement()
		require.NoError(t, e.UnmarshalBinary(evaluated))
		outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
		require.NoError(t, err)
		return outputs[0]
	}

	first := run(master1, alice, pin)
	require.Len(t, first, 32)
	require.Equal(t, first, run(master1, alice, pin), "same PIN, other blind")
	require.NotEqual(t, first, run(master1, alice, []byte("123457")), "other PIN")
	require.NotEqual(t, first, run(master1, bob, pin), "other user")
	require.NotEqual(t, first, run(master1, aliceOtherFile, pin), "other receipt key")
	require.NotEqual(t, first, run(master2, alice, pin), "other master")
}

// clientOutput runs the client side with a fixed blind. evaluate receives the serialized blinded element and returns
// the serialized evaluated element.
func clientOutput(t *testing.T, blind, input []byte, evaluate func(blinded []byte) []byte) []byte {
	t.Helper()
	scalar := suite.Group().NewScalar()
	require.NoError(t, scalar.UnmarshalBinary(blind))
	client := oprf.NewClient(suite)
	finalize, request, err := client.DeterministicBlind([][]byte{input}, []oprf.Blind{scalar})
	require.NoError(t, err)
	blinded, err := request.Elements[0].MarshalBinaryCompress()
	require.NoError(t, err)
	e := suite.Group().NewElement()
	require.NoError(t, e.UnmarshalBinary(evaluate(blinded)))
	outputs, err := client.Finalize(finalize, &oprf.Evaluation{Elements: []oprf.Evaluated{e}})
	require.NoError(t, err)
	return outputs[0]
}
