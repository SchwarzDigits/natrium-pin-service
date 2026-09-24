package masterkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey/masterkeytest"
)

func generate(t *testing.T, kms KMS, keyVersion uint32, kmsVersion int64) Entry {
	t.Helper()
	e, err := Generate(context.Background(), kms, keyVersion, kmsVersion)
	require.NoError(t, err)
	return e
}

func fastKeys(kms KMS, entries []Entry, current uint32, log *slog.Logger) *Keys {
	k := New(kms, entries, current, log)
	k.minBackoff, k.maxBackoff = time.Millisecond, 4*time.Millisecond
	return k
}

func discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestParseEntries(t *testing.T) {
	entries := []Entry{
		{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte("first")},
		{KeyVersion: 2, KMSVersion: 3, Ciphertext: []byte("second")},
	}
	s := entries[0].String() + " , " + entries[1].String() + ","
	require.Equal(t, "1:1:Zmlyc3Q=", entries[0].String())
	parsed, err := ParseEntries(s)
	require.NoError(t, err)
	require.Equal(t, entries, parsed)

	for _, bad := range []string{
		"",
		",",
		"1:1",
		"1:1:Zmlyc3Q=:x",
		"x:1:Zmlyc3Q=",
		"1:x:Zmlyc3Q=",
		"1:1:not base64",
		"1:1:Zmlyc3Q",
		"0:1:Zmlyc3Q=",
		"1:0:Zmlyc3Q=",
		"1:1:",
		"1:1:Zmlyc3Q=,1:2:Zmlyc3Q=",
		"4294967296:1:Zmlyc3Q=",
	} {
		_, err := ParseEntries(bad)
		require.Error(t, err, "%q", bad)
	}
}

func TestParseEntriesDoesNotRepeatTheCiphertext(t *testing.T) {
	_, err := ParseEntries("1:x:c2VjcmV0")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "c2VjcmV0")
}

func TestCheck(t *testing.T) {
	require.NoError(t, Check([]Entry{{KeyVersion: 1, KMSVersion: 1, Ciphertext: []byte{1}}}))
	require.Error(t, Check(nil))
}

func TestGenerateAndLoad(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	entries := []Entry{generate(t, kms, 1, 1), generate(t, kms, 2, 2)}
	keys := New(kms, entries, 2, discard())
	require.False(t, keys.Loaded())
	require.Error(t, keys.Ready(context.Background()))
	_, ok := keys.Get(1)
	require.False(t, ok, "nothing before Load")

	require.NoError(t, keys.Load(context.Background()))
	defer keys.Close()
	require.True(t, keys.Loaded())
	require.NoError(t, keys.Ready(context.Background()))
	require.Equal(t, uint32(2), keys.Current())
	require.Equal(t, 2, keys.Versions())

	first, ok := keys.Get(1)
	require.True(t, ok)
	second, ok := keys.Get(2)
	require.True(t, ok)
	require.Len(t, first, Size)
	require.Len(t, second, Size)
	require.NotEqual(t, first, second)
	require.NotEqual(t, make([]byte, Size), first)
	_, ok = keys.Get(3)
	require.False(t, ok)

	// Loading the same entries again gives the same keys.
	again := New(kms, entries, 2, discard())
	require.NoError(t, again.Load(context.Background()))
	defer again.Close()
	sameFirst, _ := again.Get(1)
	require.Equal(t, first, sameFirst)
}

func TestLoadRetriesFailedKMSCalls(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	entries := []Entry{generate(t, kms, 1, 1)}
	before := kms.DecryptCalls()
	kms.FailDecrypt(3)

	keys := fastKeys(kms, entries, 1, discard())
	require.NoError(t, keys.Load(context.Background()))
	defer keys.Close()
	require.True(t, keys.Loaded())
	require.Equal(t, 4, kms.DecryptCalls()-before)
}

func TestLoadStopsWithTheContext(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	entries := []Entry{generate(t, kms, 1, 1)}
	kms.FailDecrypt(1 << 30)

	keys := fastKeys(kms, entries, 1, discard())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, keys.Load(ctx), context.DeadlineExceeded)
	require.False(t, keys.Loaded())
}

func TestLoadDetectsSwappedEntries(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	one, two := generate(t, kms, 1, 1), generate(t, kms, 2, 1)
	one.Ciphertext, two.Ciphertext = two.Ciphertext, one.Ciphertext

	keys := New(kms, []Entry{one, two}, 1, discard())
	require.ErrorContains(t, keys.Load(context.Background()), "belongs to key version 2")
	require.False(t, keys.Loaded())
}

func TestLoadRejectsAPlainMasterKey(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	ciphertext, err := kms.Encrypt(context.Background(), 1, bytes.Repeat([]byte{7}, Size))
	require.NoError(t, err)

	keys := New(kms, []Entry{{KeyVersion: 1, KMSVersion: 1, Ciphertext: ciphertext}}, 1, discard())
	require.ErrorContains(t, keys.Load(context.Background()), "not a sealed master key")
}

func TestGenerateRejectsInvalidVersions(t *testing.T) {
	_, err := Generate(context.Background(), masterkeytest.NewFakeKMS(), 0, 1)
	require.Error(t, err)
	_, err = Generate(context.Background(), masterkeytest.NewFakeKMS(), 1, 0)
	require.Error(t, err)
}

// The master keys never appear in the logs, also not in the logs of failed attempts.
func TestMasterKeysNeverLogged(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kms := masterkeytest.NewFakeKMS()
	entries := []Entry{generate(t, kms, 1, 1), generate(t, kms, 2, 1)}
	kms.FailDecrypt(2)

	keys := fastKeys(kms, entries, 1, log)
	require.NoError(t, keys.Load(context.Background()))
	defer keys.Close()
	require.Contains(t, logs.String(), "retrying")
	require.Contains(t, logs.String(), "master keys loaded")

	for _, v := range []uint32{1, 2} {
		master, ok := keys.Get(v)
		require.True(t, ok)
		for _, form := range []string{
			string(master),
			hex.EncodeToString(master),
			base64.StdEncoding.EncodeToString(master),
			base64.RawStdEncoding.EncodeToString(master),
			base64.RawURLEncoding.EncodeToString(master),
		} {
			require.NotContains(t, logs.String(), form)
		}
	}
}

func TestCloseForgetsTheKeys(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	keys := New(kms, []Entry{generate(t, kms, 1, 1)}, 1, discard())
	require.NoError(t, keys.Load(context.Background()))
	keys.Close()
	require.False(t, keys.Loaded())
	_, ok := keys.Get(1)
	require.False(t, ok)
	keys.Close()
}

func TestSealAndOpen(t *testing.T) {
	master := bytes.Repeat([]byte{9}, Size)
	sealed := seal(7, master)
	require.Len(t, sealed, sealedSize)
	opened, err := open(sealed, 7)
	require.NoError(t, err)
	require.Equal(t, master, opened)

	_, err = open(sealed, 8)
	require.ErrorContains(t, err, "belongs to key version 7")
	_, err = open(sealed[:sealedSize-1], 7)
	require.Error(t, err)
	other := append([]byte("natrium-recovery-master-v2"), sealed[len(sealPrefix):]...)
	_, err = open(other, 7)
	require.Error(t, err)
}
