package btf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"

	"golang.org/x/exp/slices"
)

// Mirrors MAX_RESOLVE_DEPTH in libbpf.
// https://github.com/libbpf/libbpf/blob/e26b84dc330c9644c07428c271ab491b0f01f4e1/src/btf.c#L761
const maxResolveDepth = 32

// TypeID identifies a type in a BTF section.
type TypeID = sys.TypeID

// Type represents a type described by BTF.
//
// Identity of Type follows the [Go specification]: two Types are considered
// equal if they have the same concrete type and the same dynamic value, aka
// they point at the same location in memory. This means that the following
// Types are considered distinct even though they have the same "shape".
//
//	a := &Int{Size: 1}
//	b := &Int{Size: 1}
//	a != b
//
// [Go specification]: https://go.dev/ref/spec#Comparison_operators
type Type interface {
	// Type can be formatted using the %s and %v verbs. %s outputs only the
	// identity of the type, without any detail. %v outputs additional detail.
	//
	// Use the '+' flag to include the address of the type.
	//
	// Use the width to specify how many levels of detail to output, for example
	// %1v will output detail for the root type and a short description of its
	// children. %2v would output details of the root type and its children
	// as well as a short description of the grandchildren.
	fmt.Formatter

	// Name of the type, empty for anonymous types and types that cannot
	// carry a name, like Void and Pointer.
	TypeName() string

	// Make a copy of the type, without copying Type members.
	copy() Type

	// New implementations must update walkType.
}

var (
	_ Type = (*Int)(nil)
	_ Type = (*Struct)(nil)
	_ Type = (*Union)(nil)
	_ Type = (*Enum)(nil)
	_ Type = (*Fwd)(nil)
	_ Type = (*Func)(nil)
	_ Type = (*Typedef)(nil)
	_ Type = (*Var)(nil)
	_ Type = (*Datasec)(nil)
	_ Type = (*Float)(nil)
	_ Type = (*declTag)(nil)
	_ Type = (*typeTag)(nil)
	_ Type = (*cycle)(nil)
)

// Void is the unit type of BTF.
type Void struct{}

func (v *Void) Format(fs fmt.State, verb rune) { formatType(fs, verb, v) }
func (v *Void) TypeName() string               { return "" }
func (v *Void) size() uint32                   { return 0 }
func (v *Void) copy() Type                     { return (*Void)(nil) }

type IntEncoding byte

// Valid IntEncodings.
//
// These may look like they are flags, but they aren't.
const (
	Unsigned IntEncoding = 0
	Signed   IntEncoding = 1
	Char     IntEncoding = 2
	Bool     IntEncoding = 4
)

func (ie IntEncoding) String() string {
	switch ie {
	case Char:
		// NB: There is no way to determine signedness for char.
		return "char"
	case Bool:
		return "bool"
	case Signed:
		return "signed"
	case Unsigned:
		return "unsigned"
	default:
		return fmt.Sprintf("IntEncoding(%d)", byte(ie))
	}
}

// Int is an integer of a given length.
//
// See https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-int
type Int struct {
	Name string

	// The size of the integer in bytes.
	Size     uint32
	Encoding IntEncoding
}

func (i *Int) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, i, i.Encoding, "size=", i.Size*8)
}

func (i *Int) TypeName() string { return i.Name }
func (i *Int) size() uint32     { return i.Size }
func (i *Int) copy() Type {
	cpy := *i
	return &cpy
}

// Pointer is a pointer to another type.
type Pointer struct {
	Target Type
}

func (p *Pointer) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, p, "target=", p.Target)
}

func (p *Pointer) TypeName() string { return "" }
func (p *Pointer) size() uint32     { return 8 }
func (p *Pointer) copy() Type {
	cpy := *p
	return &cpy
}

// Array is an array with a fixed number of elements.
type Array struct {
	Index  Type
	Type   Type
	Nelems uint32
}

func (arr *Array) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, arr, "index=", arr.Index, "type=", arr.Type, "n=", arr.Nelems)
}

func (arr *Array) TypeName() string { return "" }

func (arr *Array) copy() Type {
	cpy := *arr
	return &cpy
}

// Struct is a compound type of consecutive members.
type Struct struct {
	Name string
	// The size of the struct including padding, in bytes
	Size    uint32
	Members []Member
}

func (s *Struct) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, s, "fields=", len(s.Members))
}

func (s *Struct) TypeName() string { return s.Name }

func (s *Struct) size() uint32 { return s.Size }

func (s *Struct) copy() Type {
	cpy := *s
	cpy.Members = copyMembers(s.Members)
	return &cpy
}

func (s *Struct) members() []Member {
	return s.Members
}

// Union is a compound type where members occupy the same memory.
type Union struct {
	Name string
	// The size of the union including padding, in bytes.
	Size    uint32
	Members []Member
}

func (u *Union) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, u, "fields=", len(u.Members))
}

func (u *Union) TypeName() string { return u.Name }

func (u *Union) size() uint32 { return u.Size }

func (u *Union) copy() Type {
	cpy := *u
	cpy.Members = copyMembers(u.Members)
	return &cpy
}

func (u *Union) members() []Member {
	return u.Members
}

func copyMembers(orig []Member) []Member {
	cpy := make([]Member, len(orig))
	copy(cpy, orig)
	return cpy
}

type composite interface {
	Type
	members() []Member
}

var (
	_ composite = (*Struct)(nil)
	_ composite = (*Union)(nil)
)

// A value in bits.
type Bits uint32

// Bytes converts a bit value into bytes.
func (b Bits) Bytes() uint32 {
	return uint32(b / 8)
}

// Member is part of a Struct or Union.
//
// It is not a valid Type.
type Member struct {
	Name         string
	Type         Type
	Offset       Bits
	BitfieldSize Bits
}

// Enum lists possible values.
type Enum struct {
	Name string
	// Size of the enum value in bytes.
	Size uint32
	// True if the values should be interpreted as signed integers.
	Signed bool
	Values []EnumValue
}

func (e *Enum) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, e, "size=", e.Size, "values=", len(e.Values))
}

func (e *Enum) TypeName() string { return e.Name }

// EnumValue is part of an Enum
//
// Is is not a valid Type
type EnumValue struct {
	Name  string
	Value uint64
}

func (e *Enum) size() uint32 { return e.Size }
func (e *Enum) copy() Type {
	cpy := *e
	cpy.Values = make([]EnumValue, len(e.Values))
	copy(cpy.Values, e.Values)
	return &cpy
}

// FwdKind is the type of forward declaration.
type FwdKind int

// Valid types of forward declaration.
const (
	FwdStruct FwdKind = iota
	FwdUnion
)

func (fk FwdKind) String() string {
	switch fk {
	case FwdStruct:
		return "struct"
	case FwdUnion:
		return "union"
	default:
		return fmt.Sprintf("%T(%d)", fk, int(fk))
	}
}

// Fwd is a forward declaration of a Type.
type Fwd struct {
	Name string
	Kind FwdKind
}

func (f *Fwd) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, f.Kind)
}

func (f *Fwd) TypeName() string { return f.Name }

func (f *Fwd) copy() Type {
	cpy := *f
	return &cpy
}

// Typedef is an alias of a Type.
type Typedef struct {
	Name string
	Type Type
}

func (td *Typedef) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, td, td.Type)
}

func (td *Typedef) TypeName() string { return td.Name }

func (td *Typedef) copy() Type {
	cpy := *td
	return &cpy
}

// Volatile is a qualifier.
type Volatile struct {
	Type Type
}

func (v *Volatile) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, v, v.Type)
}

func (v *Volatile) TypeName() string { return "" }

func (v *Volatile) qualify() Type { return v.Type }
func (v *Volatile) copy() Type {
	cpy := *v
	return &cpy
}

// Const is a qualifier.
type Const struct {
	Type Type
}

func (c *Const) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, c, c.Type)
}

func (c *Const) TypeName() string { return "" }

func (c *Const) qualify() Type { return c.Type }
func (c *Const) copy() Type {
	cpy := *c
	return &cpy
}

// Restrict is a qualifier.
type Restrict struct {
	Type Type
}

func (r *Restrict) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, r, r.Type)
}

func (r *Restrict) TypeName() string { return "" }

func (r *Restrict) qualify() Type { return r.Type }
func (r *Restrict) copy() Type {
	cpy := *r
	return &cpy
}

// Func is a function definition.
type Func struct {
	Name    string
	Type    Type
	Linkage FuncLinkage
}

func FuncMetadata(ins *asm.Instruction) *Func {
	fn, _ := ins.Metadata.Get(funcInfoMeta{}).(*Func)
	return fn
}

// WithFuncMetadata adds a btf.Func to the Metadata of asm.Instruction.
func WithFuncMetadata(ins asm.Instruction, fn *Func) asm.Instruction {
	ins.Metadata.Set(funcInfoMeta{}, fn)
	return ins
}

func (f *Func) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, f.Linkage, "proto=", f.Type)
}

func (f *Func) TypeName() string { return f.Name }

func (f *Func) copy() Type {
	cpy := *f
	return &cpy
}

// FuncProto is a function declaration.
type FuncProto struct {
	Return Type
	Params []FuncParam
}

func (fp *FuncProto) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, fp, "args=", len(fp.Params), "return=", fp.Return)
}

func (fp *FuncProto) TypeName() string { return "" }

func (fp *FuncProto) copy() Type {
	cpy := *fp
	cpy.Params = make([]FuncParam, len(fp.Params))
	copy(cpy.Params, fp.Params)
	return &cpy
}

type FuncParam struct {
	Name string
	Type Type
}

// Var is a global variable.
type Var struct {
	Name    string
	Type    Type
	Linkage VarLinkage
}

func (v *Var) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, v, v.Linkage)
}

func (v *Var) TypeName() string { return v.Name }

func (v *Var) copy() Type {
	cpy := *v
	return &cpy
}

// Datasec is a global program section containing data.
type Datasec struct {
	Name string
	Size uint32
	Vars []VarSecinfo
}

func (ds *Datasec) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, ds)
}

func (ds *Datasec) TypeName() string { return ds.Name }

func (ds *Datasec) size() uint32 { return ds.Size }

func (ds *Datasec) copy() Type {
	cpy := *ds
	cpy.Vars = make([]VarSecinfo, len(ds.Vars))
	copy(cpy.Vars, ds.Vars)
	return &cpy
}

// VarSecinfo describes variable in a Datasec.
//
// It is not a valid Type.
type VarSecinfo struct {
	// Var or Func.
	Type   Type
	Offset uint32
	Size   uint32
}

// Float is a float of a given length.
type Float struct {
	Name string

	// The size of the float in bytes.
	Size uint32
}

func (f *Float) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, "size=", f.Size*8)
}

func (f *Float) TypeName() string { return f.Name }
func (f *Float) size() uint32     { return f.Size }
func (f *Float) copy() Type {
	cpy := *f
	return &cpy
}

// declTag associates metadata with a declaration.
type declTag struct {
	Type  Type
	Value string
	// The index this tag refers to in the target type. For composite types,
	// a value of -1 indicates that the tag refers to the whole type. Otherwise
	// it indicates which member or argument the tag applies to.
	Index int
}

func (dt *declTag) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, dt, "type=", dt.Type, "value=", dt.Value, "index=", dt.Index)
}

func (dt *declTag) TypeName() string { return "" }
func (dt *declTag) copy() Type {
	cpy := *dt
	return &cpy
}

// typeTag associates metadata with a type.
type typeTag struct {
	Type  Type
	Value string
}

func (tt *typeTag) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, tt, "type=", tt.Type, "value=", tt.Value)
}

func (tt *typeTag) TypeName() string { return "" }
func (tt *typeTag) qualify() Type    { return tt.Type }
func (tt *typeTag) copy() Type {
	cpy := *tt
	return &cpy
}

// cycle is a type which had to be elided since it exceeded maxTypeDepth.
type cycle struct {
	root Type
}

func (c *cycle) ID() TypeID                     { return math.MaxUint32 }
func (c *cycle) Format(fs fmt.State, verb rune) { formatType(fs, verb, c, "root=", c.root) }
func (c *cycle) TypeName() string               { return "" }
func (c *cycle) copy() Type {
	cpy := *c
	return &cpy
}

type sizer interface {
	size() uint32
}

var (
	_ sizer = (*Int)(nil)
	_ sizer = (*Pointer)(nil)
	_ sizer = (*Struct)(nil)
	_ sizer = (*Union)(nil)
	_ sizer = (*Enum)(nil)
	_ sizer = (*Datasec)(nil)
)

type qualifier interface {
	qualify() Type
}

var (
	_ qualifier = (*Const)(nil)
	_ qualifier = (*Restrict)(nil)
	_ qualifier = (*Volatile)(nil)
	_ qualifier = (*typeTag)(nil)
)

var errUnsizedType = errors.New("type is unsized")

// Sizeof returns the size of a type in bytes.
//
// Returns an error if the size can't be computed.
func Sizeof(typ Type) (int, error) {
	var (
		n    = int64(1)
		elem int64
	)

	for i := 0; i < maxResolveDepth; i++ {
		switch v := typ.(type) {
		case *Array:
			if n > 0 && int64(v.Nelems) > math.MaxInt64/n {
				return 0, fmt.Errorf("type %s: overflow", typ)
			}

			// Arrays may be of zero length, which allows
			// n to be zero as well.
			n *= int64(v.Nelems)
			typ = v.Type
			continue

		case sizer:
			elem = int64(v.size())

		case *Typedef:
			typ = v.Type
			continue

		case qualifier:
			typ = v.qualify()
			continue

		default:
			return 0, fmt.Errorf("type %T: %w", typ, errUnsizedType)
		}

		if n > 0 && elem > math.MaxInt64/n {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		size := n * elem
		if int64(int(size)) != size {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		return int(size), nil
	}

	return 0, fmt.Errorf("type %s: exceeded type depth", typ)
}

// alignof returns the alignment of a type.
//
// Returns an error if the Type can't be aligned, like an integer with an uneven
// size. Currently only supports the subset of types necessary for bitfield
// relocations.
func alignof(typ Type) (int, error) {
	var n int

	switch t := UnderlyingType(typ).(type) {
	case *Enum:
		n = int(t.size())
	case *Int:
		n = int(t.Size)
	case *Array:
		return alignof(t.Type)
	default:
		return 0, fmt.Errorf("can't calculate alignment of %T", t)
	}

	if !pow(n) {
		return 0, fmt.Errorf("alignment value %d is not a power of two", n)
	}

	return n, nil
}

// pow returns true if n is a power of two.
func pow(n int) bool {
	return n != 0 && (n&(n-1)) == 0
}

// Transformer modifies a given Type and returns the result.
//
// For example, UnderlyingType removes any qualifiers or typedefs from a type.
// See the example on Copy for how to use a transform.
type Transformer func(Type) Type

// Copy a Type recursively.
//
// typ may form a cycle. If transform is not nil, it is called with the
// to be copied type, and the returned value is copied instead.
func Copy(typ Type, transform Transformer) Type {
	copies := copier{copies: make(map[Type]Type)}
	copies.copy(&typ, transform)
	return typ
}

// copy a slice of Types recursively.
//
// See Copy for the semantics.
func copyTypes(types []Type, transform Transformer) []Type {
	result := make([]Type, len(types))
	copy(result, types)

	copies := copier{copies: make(map[Type]Type, len(types))}
	for i := range result {
		copies.copy(&result[i], transform)
	}

	return result
}

type copier struct {
	copies map[Type]Type
	work   typeDeque
}

func (c *copier) copy(typ *Type, transform Transformer) {
	for t := typ; t != nil; t = c.work.Pop() {
		// *t is the identity of the type.
		if cpy := c.copies[*t]; cpy != nil {
			*t = cpy
			continue
		}

		var cpy Type
		if transform != nil {
			cpy = transform(*t).copy()
		} else {
			cpy = (*t).copy()
		}

		c.copies[*t] = cpy
		*t = cpy

		// Mark any nested types for copying.
		walkType(cpy, c.work.Push)
	}
}

type typeDeque = internal.Deque[*Type]

type decoder struct {
	btf io.ReaderAt

	order binary.ByteOrder

	// The first logical type ID in the BTF blob. Non-zero when reading split BTF.
	firstTypeID TypeID

	// All types decoded so far.
	types map[TypeID]Type

	// Any types with an ID less than firstTypeID are looked up in base instead
	// of attempting to decode them.
	base *Spec

	typeOffsets []uint32

	rawStrings *stringTable

	datasecSizes   map[string]uint32
	datasecSymbols map[symbol]uint32

	// A list of legacy bitfields as encountered during decoding of the BTF.
	legacyBitfields map[TypeID][2]Bits // offset, size

	// Temporary storage used by decode().

	// A stack of pending types.
	pending []pendingType

	// Any newly decoded declTags.
	declTags []*declTag
	datasecs []*Datasec
}

// nextTypeID returns the next unallocated type ID or an error if there are no
// more type IDs.
func (d *decoder) nextTypeID() (TypeID, error) {
	id := d.firstTypeID + TypeID(len(d.typeOffsets))
	if id < d.firstTypeID {
		return 0, fmt.Errorf("no more type IDs")
	}
	return id, nil
}

func newDecoder(btf io.ReaderAt, bo binary.ByteOrder, base *Spec, datasecSizes map[string]uint32, datasecSymbols map[symbol]uint32) (*decoder, map[essentialName][]TypeID, error) {
	buf := internal.NewBufferedSectionReader(btf, 0, math.MaxInt64)
	header, err := parseBTFHeader(buf, bo)
	if err != nil {
		return nil, nil, fmt.Errorf("parse .BTF header: %w", err)
	}

	maxTypes := header.TypeLen / uint32(btfTypeLen)

	var (
		baseStrings *stringTable
		// Void is ID 0 and omitted from BTF.
		firstTypeID = TypeID(0)
		types       = map[sys.TypeID]Type{0: (*Void)(nil)}
	)

	if base != nil {
		if bo != base.decoder.order {
			return nil, nil, fmt.Errorf("base BTF has %s byte order, expected %s", base.decoder.order, bo)
		}

		if base.decoder.firstTypeID != 0 {
			return nil, nil, fmt.Errorf("can't use split BTF as base")
		}

		var err error
		firstTypeID, err = base.decoder.nextTypeID()
		if err != nil {
			return nil, nil, err
		}

		baseStrings = base.decoder.rawStrings
		delete(types, 0)
	}

	rawStrings, err := readStringTable(io.NewSectionReader(btf, header.stringStart(), int64(header.StringLen)),
		baseStrings)
	if err != nil {
		return nil, nil, fmt.Errorf("parse string table: %w", err)
	}

	btfTypes := io.NewSectionReader(btf, header.typeStart(), int64(header.TypeLen))
	buf.Reset(btfTypes)

	// Heuristic: current vmlinux has about one string per type.
	offsets := make([]uint32, 0, rawStrings.Num())
	// Heuristic: half of current vmlinux types have a name.
	namedTypes := make(map[essentialName][]TypeID, rawStrings.Num()/2)

	if firstTypeID == 0 {
		// Void doesn't really have an offset in BTF. Use MaxUint32 as a sentinel
		// which will cause an error should we ever attempt to decode it.
		offsets = append(make([]uint32, 0, maxTypes), math.MaxUint32)
	}

	var raw btfType
	var offset uint32
	for {
		id := firstTypeID + TypeID(len(offsets))

		if err := raw.Unmarshal(buf, bo); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("read type id %d: %w", id, err)
		}

		dataLen, err := raw.DataLen()
		if err != nil {
			return nil, nil, fmt.Errorf("type id %d: determine data length: %w", id, err)
		}

		_, err = buf.Discard(dataLen)
		if err != nil {
			return nil, nil, fmt.Errorf("type id %d: skip data: %w", id, err)
		}

		name, err := rawStrings.Lookup(raw.NameOff)
		if err != nil {
			return nil, nil, fmt.Errorf("read type %d: lookup name: %w", id, err)
		}

		offsets = append(offsets, uint32(offset))
		if name != "" {
			eName := newEssentialName(name)
			namedTypes[eName] = append(namedTypes[eName], id)
		}

		offset += uint32(btfTypeLen + dataLen)
	}

	btfTypes.Seek(0, io.SeekStart)

	d := &decoder{
		btfTypes,
		bo,
		TypeID(0),
		map[TypeID]Type{0: (*Void)(nil)},
		base,
		offsets,
		rawStrings,
		datasecSizes,
		datasecSymbols,
		make(map[TypeID][2]Bits),
		nil,
		nil,
		nil,
	}

	return d, namedTypes, nil
}

func (d *decoder) copy() *decoder {
	cpy := *d
	if cpy.firstTypeID == 0 {
		cpy.types = map[TypeID]Type{0: (*Void)(nil)}
	} else {
		cpy.types = make(map[TypeID]Type)
	}
	cpy.legacyBitfields = make(map[TypeID][2]Bits)
	return &cpy
}

func (d *decoder) convertMembers(raw []btfMember, kindFlag bool) []Member {
	// NB: The fixup below relies on pre-allocating this array to
	// work, since otherwise append might re-allocate members.
	members := make([]Member, 0, len(raw))
	for i, btfMember := range raw {
		name, err := d.rawStrings.Lookup(btfMember.NameOff)
		if err != nil {
			panic(fmt.Errorf("get name for member %d: %w", i, err))
		}

		members = append(members, Member{
			Name:   name,
			Offset: Bits(btfMember.Offset),
		})

		m := &members[i]
		d.decodeRecurse(raw[i].Type, &m.Type)

		if kindFlag {
			m.BitfieldSize = Bits(btfMember.Offset >> 24)
			m.Offset &= 0xffffff
			// We ignore legacy bitfield definitions if the current composite
			// is a new-style bitfield. This is kind of safe since offset and
			// size on the type of the member must be zero if kindFlat is set
			// according to spec.
			continue
		}

		// This may be an Int and carry a legacy bitfield, try to fix it up.
		// Since Int can't be cyclical we know that decodeRecurse() above must
		// have decoded raw[i].Type and therefore populated legacyBitfields.
		data, ok := d.legacyBitfields[raw[i].Type]
		if ok {
			// Bingo!
			m.Offset += data[0]
			m.BitfieldSize = data[1]
		}
	}
	return members
}

type pendingType struct {
	id     TypeID
	fixups []*Type
}

func (d *decoder) decodeRecurse(id TypeID, typ *Type) {
	if id < d.firstTypeID {
		baseType, err := d.base.TypeByID(id)
		if err != nil {
			panic(err)
		}

		*typ = baseType
		return
	}

	if decoded, ok := d.types[id]; ok {
		*typ = decoded
		return
	}

	index := int(id - d.firstTypeID)
	if index >= len(d.typeOffsets) {
		panic(os.ErrNotExist)
	}

	// Prevent infinite recursion in case of cyclic types.
	if i := slices.IndexFunc(d.pending, func(pt pendingType) bool { return pt.id == id }); i >= 0 {
		// There is already an instance of decodeRecurse for this type ID.
		d.pending[i].fixups = append(d.pending[i].fixups, typ)
		return
	}

	d.pending = append(d.pending, pendingType{id, nil})
	defer func() {
		d.pending = d.pending[:len(d.pending)-1]
	}()

	offset := d.typeOffsets[index]
	r := io.NewSectionReader(d.btf, int64(offset), math.MaxInt64)

	var raw rawType
	if err := raw.Unmarshal(r, d.order); err != nil {
		panic(err)
	}

	name, err := d.rawStrings.Lookup(raw.NameOff)
	if err != nil {
		panic(fmt.Errorf("get name from string table: %w", err))
	}

	switch raw.Kind() {
	case kindInt:
		size := raw.Size()
		bi := raw.data.(*btfInt)
		if bi.Offset() > 0 || bi.Bits().Bytes() != size {
			d.legacyBitfields[id] = [2]Bits{bi.Offset(), bi.Bits()}
		}
		*typ = &Int{name, raw.Size(), bi.Encoding()}

	case kindPointer:
		ptr := &Pointer{nil}
		d.decodeRecurse(raw.Type(), &ptr.Target)
		*typ = ptr

	case kindArray:
		btfArr := raw.data.(*btfArray)
		arr := &Array{nil, nil, btfArr.Nelems}
		d.decodeRecurse(btfArr.IndexType, &arr.Index)
		d.decodeRecurse(btfArr.Type, &arr.Type)
		*typ = arr

	case kindStruct:
		*typ = &Struct{
			name,
			raw.Size(),
			d.convertMembers(raw.data.([]btfMember), raw.Bitfield()),
		}

	case kindUnion:
		*typ = &Union{
			name,
			raw.Size(),
			d.convertMembers(raw.data.([]btfMember), raw.Bitfield()),
		}

	case kindEnum:
		rawvals := raw.data.([]btfEnum)
		vals := make([]EnumValue, 0, len(rawvals))
		signed := raw.Signed()
		for i, btfVal := range rawvals {
			name, err := d.rawStrings.Lookup(btfVal.NameOff)
			if err != nil {
				panic(fmt.Errorf("get name for enum value %d: %s", i, err))
			}
			value := uint64(btfVal.Val)
			if signed {
				// Sign extend values to 64 bit.
				value = uint64(int32(btfVal.Val))
			}
			vals = append(vals, EnumValue{name, value})
		}
		*typ = &Enum{name, raw.Size(), signed, vals}

	case kindForward:
		*typ = &Fwd{name, raw.FwdKind()}

	case kindTypedef:
		typedef := &Typedef{name, nil}
		d.decodeRecurse(raw.Type(), &typedef.Type)
		*typ = typedef

	case kindVolatile:
		volatile := &Volatile{nil}
		d.decodeRecurse(raw.Type(), &volatile.Type)
		*typ = volatile

	case kindConst:
		cnst := &Const{nil}
		d.decodeRecurse(raw.Type(), &cnst.Type)
		*typ = cnst

	case kindRestrict:
		restrict := &Restrict{nil}
		d.decodeRecurse(raw.Type(), &restrict.Type)
		*typ = restrict

	case kindFunc:
		fn := &Func{name, nil, raw.Linkage()}
		d.decodeRecurse(raw.Type(), &fn.Type)
		*typ = fn

	case kindFuncProto:
		rawparams := raw.data.([]btfParam)
		params := make([]FuncParam, 0, len(rawparams))
		for i, param := range rawparams {
			name, err := d.rawStrings.Lookup(param.NameOff)
			if err != nil {
				panic(fmt.Errorf("get name for func proto parameter %d: %s", i, err))
			}
			params = append(params, FuncParam{
				Name: name,
			})
		}
		for i := range params {
			d.decodeRecurse(rawparams[i].Type, &params[i].Type)
		}

		fp := &FuncProto{nil, params}
		d.decodeRecurse(raw.Type(), &fp.Return)
		*typ = fp

	case kindVar:
		variable := raw.data.(*btfVariable)
		v := &Var{name, nil, VarLinkage(variable.Linkage)}
		d.decodeRecurse(raw.Type(), &v.Type)
		*typ = v

	case kindDatasec:
		btfVars := raw.data.([]btfVarSecinfo)
		vars := make([]VarSecinfo, 0, len(btfVars))
		for _, btfVar := range btfVars {
			vars = append(vars, VarSecinfo{
				Offset: btfVar.Offset,
				Size:   btfVar.Size,
			})
		}
		for i := range vars {
			d.decodeRecurse(btfVars[i].Type, &vars[i].Type)
		}
		ds := &Datasec{name, raw.Size(), vars}
		*typ = ds
		d.datasecs = append(d.datasecs, ds)

	case kindFloat:
		*typ = &Float{name, raw.Size()}

	case kindDeclTag:
		btfIndex := raw.data.(*btfDeclTag).ComponentIdx
		if uint64(btfIndex) > math.MaxInt {
			panic(fmt.Errorf("declTag index exceeds int"))
		}

		dt := &declTag{nil, name, int(int32(btfIndex))}
		d.decodeRecurse(raw.Type(), &dt.Type)
		*typ = dt
		d.declTags = append(d.declTags, dt)

	case kindTypeTag:
		tt := &typeTag{nil, name}
		d.decodeRecurse(raw.Type(), &tt.Type)
		*typ = tt

	case kindEnum64:
		rawvals := raw.data.([]btfEnum64)
		vals := make([]EnumValue, 0, len(rawvals))
		for i, btfVal := range rawvals {
			name, err := d.rawStrings.Lookup(btfVal.NameOff)
			if err != nil {
				panic(fmt.Errorf("get name for enum64 value %d: %s", i, err))
			}
			value := (uint64(btfVal.ValHi32) << 32) | uint64(btfVal.ValLo32)
			vals = append(vals, EnumValue{name, value})
		}
		*typ = &Enum{name, raw.Size(), raw.Signed(), vals}

	default:
		panic(fmt.Errorf("unknown kind: %v", raw.Kind()))
	}

	// All non-Type fields are filled in. Most Type fields will be present, but
	// cyclical Types rely on the fixups below.
	d.types[id] = *typ

	// Fix up fields referencing cyclical Types.
	fixups := d.pending[len(d.pending)-1].fixups
	for _, fixup := range fixups {
		*fixup = *typ
	}
}

// decode a type given its ID.
//
// May recursively decode other necessary types as a side effect.
func (d *decoder) decode(id TypeID) (typ Type, err error) {
	if id < d.firstTypeID {
		return nil, fmt.Errorf("type with id %d: can't decode type from base (first ID is %d)", id, d.firstTypeID)
	}

	if d.types == nil {
		return nil, fmt.Errorf("decoding failed previously")
	}

	defer func() {
		r := recover()
		if r == nil {
			return
		}

		// Something went badly wrong and d.types may contain partially
		// decoded types. Clear out types and return an error from now on.
		d.types = nil

		if rerr, ok := r.(error); ok {
			err = fmt.Errorf("type with id %d: %w", id, rerr)
			return
		}

		panic(r)
	}()

	d.decodeRecurse(id, &typ)

	for _, dt := range d.declTags {
		switch t := dt.Type.(type) {
		case *Var, *Typedef:
			if dt.Index != -1 {
				return nil, fmt.Errorf("type %s: index %d is not -1", dt, dt.Index)
			}

		case composite:
			if dt.Index >= len(t.members()) {
				return nil, fmt.Errorf("type %s: index %d exceeds members of %s", dt, dt.Index, t)
			}

		case *Func:
			fp, ok := t.Type.(*FuncProto)
			if !ok {
				return nil, fmt.Errorf("type %s: %s is not a FuncProto", dt, t.Type)
			}

			if dt.Index >= len(fp.Params) {
				return nil, fmt.Errorf("type %s: index %d exceeds params of %s", dt, dt.Index, t)
			}

		default:
			return nil, fmt.Errorf("type %s: decl tag for type %s is not supported", dt, t)
		}
	}
	d.declTags = nil

	if err := fixupDatasec(d.datasecs, d.datasecSizes, d.datasecSymbols); err != nil {
		panic(err)
	}
	d.datasecs = nil

	return typ, nil
}

// essentialName represents the name of a BTF type stripped of any flavor
// suffixes after a ___ delimiter.
type essentialName string

// newEssentialName returns name without a ___ suffix.
//
// CO-RE has the concept of 'struct flavors', which are used to deal with
// changes in kernel data structures. Anything after three underscores
// in a type name is ignored for the purpose of finding a candidate type
// in the kernel's BTF.
func newEssentialName(name string) essentialName {
	if name == "" {
		return ""
	}
	lastIdx := strings.LastIndex(name, "___")
	if lastIdx > 0 {
		return essentialName(name[:lastIdx])
	}
	return essentialName(name)
}

// UnderlyingType skips qualifiers and Typedefs.
func UnderlyingType(typ Type) Type {
	result := typ
	for depth := 0; depth <= maxResolveDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result
		}
	}
	return &cycle{typ}
}

// as returns typ if is of type T. Otherwise it peels qualifiers and Typedefs
// until it finds a T.
//
// Returns the zero value and false if there is no T or if the type is nested
// too deeply.
func as[T Type](typ Type) (T, bool) {
	for depth := 0; depth <= maxResolveDepth; depth++ {
		switch v := (typ).(type) {
		case T:
			return v, true
		case qualifier:
			typ = v.qualify()
		case *Typedef:
			typ = v.Type
		default:
			goto notFound
		}
	}
notFound:
	var zero T
	return zero, false
}

type formatState struct {
	fmt.State
	depth int
}

// formattableType is a subset of Type, to ease unit testing of formatType.
type formattableType interface {
	fmt.Formatter
	TypeName() string
}

// formatType formats a type in a canonical form.
//
// Handles cyclical types by only printing cycles up to a certain depth. Elements
// in extra are separated by spaces unless the preceding element is a string
// ending in '='.
func formatType(f fmt.State, verb rune, t formattableType, extra ...interface{}) {
	if verb != 'v' && verb != 's' {
		fmt.Fprintf(f, "{UNRECOGNIZED: %c}", verb)
		return
	}

	_, _ = io.WriteString(f, internal.GoTypeName(t))

	if name := t.TypeName(); name != "" {
		// Output BTF type name if present.
		fmt.Fprintf(f, ":%q", name)
	}

	if f.Flag('+') {
		// Output address if requested.
		fmt.Fprintf(f, ":%#p", t)
	}

	if verb == 's' {
		// %s omits details.
		return
	}

	var depth int
	if ps, ok := f.(*formatState); ok {
		depth = ps.depth
		f = ps.State
	}

	maxDepth, ok := f.Width()
	if !ok {
		maxDepth = 0
	}

	if depth > maxDepth {
		// We've reached the maximum depth. This avoids infinite recursion even
		// for cyclical types.
		return
	}

	if len(extra) == 0 {
		return
	}

	wantSpace := false
	_, _ = io.WriteString(f, "[")
	for _, arg := range extra {
		if wantSpace {
			_, _ = io.WriteString(f, " ")
		}

		switch v := arg.(type) {
		case string:
			_, _ = io.WriteString(f, v)
			wantSpace = len(v) > 0 && v[len(v)-1] != '='
			continue

		case formattableType:
			v.Format(&formatState{f, depth + 1}, verb)

		default:
			fmt.Fprint(f, arg)
		}

		wantSpace = true
	}
	_, _ = io.WriteString(f, "]")
}
