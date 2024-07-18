package btf

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/ebpf/internal"
)

func TestBuilderMarshal(t *testing.T) {
	typ := &Int{
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}

	want := []Type{
		(*Void)(nil),
		typ,
		&Pointer{typ},
		&Typedef{"baz", typ},
	}

	b, err := NewBuilder(want)
	qt.Assert(t, qt.IsNil(err))

	cpy := *b
	buf, err := b.Marshal(nil, &MarshalOptions{Order: internal.NativeEndian})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.CmpEquals(b, &cpy, cmp.AllowUnexported(*b)), qt.Commentf("Marshaling should not change Builder state"))

	have, err := loadRawSpec(bytes.NewReader(buf), internal.NativeEndian, nil)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("Couldn't parse BTF"))
	qt.Assert(t, qt.DeepEquals(have.imm.types, want))
}

func TestBuilderAdd(t *testing.T) {
	i := &Int{
		Name:     "foo",
		Size:     2,
		Encoding: Signed | Char,
	}
	pi := &Pointer{i}

	var b Builder
	id, err := b.Add(pi)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, TypeID(1)), qt.Commentf("First non-void type doesn't get id 1"))

	id, err = b.Add(pi)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, TypeID(1)))

	id, err = b.Add(i)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, TypeID(2)), qt.Commentf("Second type doesn't get id 2"))

	id, err = b.Add(i)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, TypeID(2)), qt.Commentf("Adding a type twice returns different ids"))

	id, err = b.Add(&Typedef{"baz", i})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(id, TypeID(3)))
}

func TestMarshalEnum64(t *testing.T) {
	enum := &Enum{
		Name:   "enum64",
		Size:   8,
		Signed: true,
		Values: []EnumValue{
			{"A", 0},
			{"B", 1},
		},
	}

	b, err := NewBuilder([]Type{enum})
	qt.Assert(t, qt.IsNil(err))
	buf, err := b.Marshal(nil, &MarshalOptions{
		Order:         internal.NativeEndian,
		ReplaceEnum64: true,
	})
	qt.Assert(t, qt.IsNil(err))

	spec, err := loadRawSpec(bytes.NewReader(buf), internal.NativeEndian, nil)
	qt.Assert(t, qt.IsNil(err))

	var have *Union
	err = spec.TypeByName("enum64", &have)
	qt.Assert(t, qt.IsNil(err))

	placeholder := &Int{Name: "enum64_placeholder", Size: 8, Encoding: Signed}
	qt.Assert(t, qt.DeepEquals(have, &Union{
		Name: "enum64",
		Size: 8,
		Members: []Member{
			{Name: "A", Type: placeholder},
			{Name: "B", Type: placeholder},
		},
	}))
}

func BenchmarkMarshaler(b *testing.B) {
	types := typesFromSpec(vmlinuxTestdataSpec(b))[:100]

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var b Builder
		for _, typ := range types {
			_, _ = b.Add(typ)
		}
		_, _ = b.Marshal(nil, nil)
	}
}

func BenchmarkBuildVmlinux(b *testing.B) {
	types := typesFromSpec(vmlinuxTestdataSpec(b))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var b Builder
		for _, typ := range types {
			_, _ = b.Add(typ)
		}
		_, _ = b.Marshal(nil, nil)
	}
}

func marshalNativeEndian(tb testing.TB, types []Type) []byte {
	tb.Helper()

	b, err := NewBuilder(types)
	qt.Assert(tb, qt.IsNil(err))
	buf, err := b.Marshal(nil, nil)
	qt.Assert(tb, qt.IsNil(err))
	return buf
}

func specFromTypes(tb testing.TB, types []Type) *Spec {
	tb.Helper()

	btf := marshalNativeEndian(tb, types)
	spec, err := loadRawSpec(bytes.NewReader(btf), internal.NativeEndian, nil)
	qt.Assert(tb, qt.IsNil(err))

	return spec
}

func typesFromSpec(spec *Spec) []Type {
	var types []Type
	iter := spec.Iterate()
	for iter.Next() {
		types = append(types, iter.Type)
	}

	return types
}
