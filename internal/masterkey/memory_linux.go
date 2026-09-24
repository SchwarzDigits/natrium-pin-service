package masterkey

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// lockedMemory is memory outside the Go heap. On Linux it is excluded from core dumps and, if the memory lock limit
// allows it, locked against swapping.
type lockedMemory struct {
	buf    []byte
	region []byte
	locked bool
	reason string
}

// allocLocked maps size bytes of anonymous memory, rounded up to whole pages.
func allocLocked(size int) (*lockedMemory, error) {
	pageSize := unix.Getpagesize()
	length := max((size+pageSize-1)/pageSize*pageSize, pageSize)
	region, err := unix.Mmap(-1, 0, length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	m := &lockedMemory{buf: region[:size:size], region: region}
	if err := unix.Madvise(region, unix.MADV_DONTDUMP); err != nil {
		_ = unix.Munmap(region)
		return nil, fmt.Errorf("madvise: %w", err)
	}
	if err := unix.Mlock(region); err != nil {
		m.reason = "mlock: " + err.Error()
	} else {
		m.locked = true
	}
	return m, nil
}

// free overwrites the memory and unmaps it.
func (m *lockedMemory) free() {
	clear(m.region)
	if m.locked {
		_ = unix.Munlock(m.region)
	}
	_ = unix.Munmap(m.region)
}

// ProtectProcess makes the process not dumpable and turns off core dumps: another process of the same user cannot
// attach a debugger or read its memory through /proc, and a crash writes no memory to disk.
func ProtectProcess() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl PR_SET_DUMPABLE: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("setrlimit RLIMIT_CORE: %w", err)
	}
	return nil
}
