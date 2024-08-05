package ebpf

import "github.com/cilium/ebpf/internal"

func guessNonExistentKey(m *Map) ([]byte, error) {
	return nil, internal.ErrNotSupportedOnOS
}
