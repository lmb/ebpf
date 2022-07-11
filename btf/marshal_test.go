package btf

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"sort"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestBuild(t *testing.T) {
	typ := &Int{
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}

	b := newBuilder(internal.NativeEndian, 0, nil)

	id, err := b.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("First non-void type doesn't get id 1"))

	id, err = b.Add(typ)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, id, qt.Equals, TypeID(1), qt.Commentf("Adding a type twice returns different ids"))

	raw, err := b.Build()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Build returned an error"))

	spec, err := loadRawSpec(bytes.NewReader(raw), internal.NativeEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("Couldn't parse BTF"))

	have, err := spec.AnyTypeByName("foo")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, have, qt.DeepEquals, typ)
}

func TestBuildVmlinux(t *testing.T) {
	spec := parseVMLinuxTypes(t)

	noFloat := testutils.MustKernelVersion().Less(internal.Version{5, 13, 0})
	types := make([]Type, 0, len(spec.types))
	for _, typ := range spec.types {
		if noFloat {
			if _, ok := typ.(*Float); ok {
				// Skip floats on pre-5.13 kernels.
				continue
			}
		}

		types = append(types, typ)
	}

	// Randomize the order to force different permutations of walking the type
	// graph.
	rand.Shuffle(len(types), func(i, j int) {
		types[i], types[j] = types[j], types[i]
	})

	b := newBuilder(binary.LittleEndian, 0, nil)
	b.StripFuncLinkage = haveFuncLinkage() != nil

	for i, typ := range types {
		_, err := b.Add(typ)
		qt.Assert(t, err, qt.IsNil, qt.Commentf("add type #%d: %s", i, typ))
	}

	nStr := len(b.strings.strings)
	nTypes := len(types)
	t.Log(len(b.strings.strings), "strings", nTypes, "types")
	t.Log(float64(nStr)/float64(nTypes), "avg strings per type")

	raw, err := b.Build()
	qt.Assert(t, err, qt.IsNil, qt.Commentf("build BTF"))

	rebuilt, err := loadRawSpec(bytes.NewReader(raw), binary.LittleEndian, nil, nil)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("round tripping BTF failed"))
	qt.Assert(t, len(rebuilt.types), qt.Equals, nTypes)

	h, err := NewHandle(rebuilt)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil, qt.Commentf("loading rebuilt BTF failed"))
	h.Close()
}

func BenchmarkBuildVmlinux(b *testing.B) {
	spec := parseVMLinuxTypes(b)

	b.Run("builder", func(b *testing.B) {
		b.ReportAllocs()

		types := spec.types

		for i := 0; i < b.N; i++ {
			builder := newBuilder(binary.LittleEndian, len(types), nil)

			for _, typ := range types {
				if _, err := builder.Add(typ); err != nil {
					b.Fatal(err)
				}
			}

			_, err := builder.Build()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestKernelBug(t *testing.T) {
	// btf, err := os.ReadFile("testdata/struct-err.btf")
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// load(t, btf)
	// return

	f, err := os.Open("testdata/struct-err.btf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	spec, err := LoadSpecFromReader(f)
	if err != nil {
		t.Fatal(err)
	}

	// buildAndLoad(t, spec.types)
	// return

	typ, err := spec.AnyTypeByName("dma_fence_func_t")
	if err != nil {
		t.Fatal(err)
	}

	types := preorderTraversal(typ, func(t Type) bool {
		_, isVoid := t.(*Void)
		return isVoid
	})

	for _, id := range []TypeID{
		69612,
		69617,
		74829,
		74838,
		74841,
		77026,
		77408,
		77409,
		81077,
		81279,
		88718,
		88842,
	} {
		typ, err := spec.TypeByID(id)
		if err != nil {
			t.Fatal(err)
		}
		types = append(types, typ)
	}

	sort.Slice(types, func(i, j int) bool {
		iID, err := spec.TypeID(types[i])
		if err != nil {
			panic(err)
		}

		jID, err := spec.TypeID(types[j])
		if err != nil {
			panic(err)
		}

		return iID < jID
	})

	for _, typ := range types {
		id, _ := spec.TypeID(typ)
		t.Log(id, typ)
	}

	// buildAndLoad(t, types)
	// t.Error("should fail")

	for {
		rand.Shuffle(len(types), func(i, j int) {
			types[i], types[j] = types[j], types[i]
		})

		buildAndLoad(t, types)
	}
}

func buildAndLoad(t *testing.T, types types) {
	t.Helper()

	stb := newBuilder(internal.NativeEndian, 0, nil)
	stb.StripFuncLinkage = haveFuncLinkage() != nil

	for _, typ := range types {
		_, err := stb.Add(typ)
		if err != nil {
			t.Fatal(err)
		}
	}

	btf, err := stb.Build()
	if err != nil {
		t.Fatal(err)
	}

	// if err := os.WriteFile("testdata/struct-err.btf", btf, 0666); err != nil {
	// 	t.Fatal(err)
	// }
	load(t, btf)
}

func load(t *testing.T, btf []byte) {
	t.Helper()

	logBuf := make([]byte, 10*1024*1024)
	attr := &sys.BtfLoadAttr{
		Btf:         sys.NewSlicePointer(btf),
		BtfSize:     uint32(len(btf)),
		BtfLogBuf:   sys.NewSlicePointer(logBuf),
		BtfLogSize:  uint32(len(logBuf)),
		BtfLogLevel: 1,
	}

	fd, err := sys.BtfLoad(attr)
	if err != nil {
		t.Fatalf("%-20v", internal.ErrorWithLog(err, logBuf))
	}
	fd.Close()
}
