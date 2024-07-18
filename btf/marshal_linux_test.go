package btf

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
	"github.com/go-quicktest/qt"
)

func TestRoundtripVMlinux(t *testing.T) {
	types := typesFromSpec(vmlinuxSpec(t))

	// Randomize the order to force different permutations of walking the type
	// graph. Keep Void at index 0.
	testutils.Rand(t).Shuffle(len(types[1:]), func(i, j int) {
		types[i+1], types[j+1] = types[j+1], types[i+1]
	})

	visited := make(map[Type]struct{})
limitTypes:
	for i, typ := range types {
		visitInPostorder(typ, visited, func(t Type) bool { return true })
		if len(visited) >= math.MaxInt16 {
			// IDs exceeding math.MaxUint16 can trigger a bug when loading BTF.
			// This can be removed once the patch lands.
			// See https://lore.kernel.org/bpf/20220909092107.3035-1-oss@lmb.io/
			types = types[:i]
			break limitTypes
		}
	}

	b, err := NewBuilder(types)
	qt.Assert(t, qt.IsNil(err))
	buf, err := b.Marshal(nil, KernelMarshalOptions())
	qt.Assert(t, qt.IsNil(err))

	rebuilt, err := loadRawSpec(bytes.NewReader(buf), binary.LittleEndian, nil)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("round tripping BTF failed"))

	if n := len(rebuilt.imm.types); n > math.MaxUint16 {
		t.Logf("Rebuilt BTF contains %d types which exceeds uint16, test may fail on older kernels", n)
	}

	h, err := NewHandleFromRawBTF(buf)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}
