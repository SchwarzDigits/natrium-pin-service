//go:build !linux

package masterkey

// lockedMemory is ordinary memory on platforms other than Linux, which the service is not deployed on. It is neither
// locked nor excluded from core dumps.
type lockedMemory struct {
	buf    []byte
	locked bool
	reason string
}

func allocLocked(size int) (*lockedMemory, error) {
	return &lockedMemory{buf: make([]byte, size), reason: "memory locking is only implemented on Linux"}, nil
}

// free overwrites the memory.
func (m *lockedMemory) free() {
	clear(m.buf)
}

// ProtectProcess does nothing on platforms other than Linux.
func ProtectProcess() error {
	return nil
}
