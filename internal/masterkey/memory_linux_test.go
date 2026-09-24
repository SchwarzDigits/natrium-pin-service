package masterkey

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestAllocLockedMapsWholePages(t *testing.T) {
	m, err := allocLocked(3 * Size)
	require.NoError(t, err)
	defer m.free()
	require.Len(t, m.buf, 3*Size)
	require.Len(t, m.region, unix.Getpagesize())
	if !m.locked {
		t.Logf("not locked: %s", m.reason)
	}
	copy(m.buf, []byte("written"))
	require.Equal(t, []byte("written"), m.buf[:7])
}

func TestProtectProcess(t *testing.T) {
	require.NoError(t, ProtectProcess())
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	require.NoError(t, err)
	require.Zero(t, dumpable)
	var core unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_CORE, &core))
	require.Zero(t, core.Cur)
}
