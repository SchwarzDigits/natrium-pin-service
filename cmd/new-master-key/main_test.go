package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey"
	"github.com/SchwarzDigits/natrium-recovery-server/internal/masterkey/masterkeytest"
	"github.com/SchwarzDigits/natrium-recovery-server/server"
)

func TestPrintsAnEntryTheServerLoads(t *testing.T) {
	kms := masterkeytest.NewFakeKMS()
	var out bytes.Buffer
	err := run(context.Background(), []string{"-key-version", "2", "-kms-version", "3"}, &out, io.Discard,
		func() (masterkey.KMS, error) { return kms, nil })
	require.NoError(t, err)

	line := strings.TrimSuffix(out.String(), "\n")
	require.NotContains(t, line, "\n", "only the entry is printed")
	entries, err := server.ParseMasterKeys(line)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, uint32(2), entries[0].KeyVersion)
	require.Equal(t, int64(3), entries[0].KMSVersion)

	keys := masterkey.New(kms, entries, 2, slog.New(slog.DiscardHandler))
	require.NoError(t, keys.Load(context.Background()))
	defer keys.Close()
	master, ok := keys.Get(2)
	require.True(t, ok)
	require.Len(t, master, masterkey.Size)
}

func TestNeedsBothVersions(t *testing.T) {
	noKMS := func() (masterkey.KMS, error) {
		t.Error("the KMS must not be created for invalid arguments")
		return nil, errors.New("no KMS")
	}
	for _, args := range [][]string{
		nil,
		{"-key-version", "1"},
		{"-kms-version", "1"},
		{"-key-version", "0", "-kms-version", "1"},
		{"-key-version", "1", "-kms-version", "0"},
		{"-key-version", "4294967296", "-kms-version", "1"},
		{"-key-version", "1", "-kms-version", "1", "extra"},
		{"-unknown"},
	} {
		var out bytes.Buffer
		require.Error(t, run(context.Background(), args, &out, io.Discard, noKMS), "%q", args)
		require.Empty(t, out.String())
	}
}

func TestReportsKMSErrors(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), []string{"-key-version", "1", "-kms-version", "1"}, &out, io.Discard,
		func() (masterkey.KMS, error) { return nil, errors.New("NATRIUM_RECOVERY_KMS_KEY_ID is required") })
	require.ErrorContains(t, err, "NATRIUM_RECOVERY_KMS_KEY_ID")
	require.Empty(t, out.String())
}
