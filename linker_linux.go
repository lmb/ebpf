package ebpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/kconfig"
)

// handles stores handle objects to avoid gc cleanup
type handles []*btf.Handle

func (hs *handles) add(h *btf.Handle) (int, error) {
	if h == nil {
		return 0, nil
	}

	if len(*hs) == math.MaxInt16 {
		return 0, fmt.Errorf("can't add more than %d module FDs to fdArray", math.MaxInt16)
	}

	*hs = append(*hs, h)

	// return length of slice so that indexes start at 1
	return len(*hs), nil
}

func (hs handles) fdArray() []int32 {
	// first element of fda is reserved as no module can be indexed with 0
	fda := []int32{0}
	for _, h := range hs {
		fda = append(fda, int32(h.FD()))
	}

	return fda
}

func (hs *handles) Close() error {
	var errs []error
	for _, h := range *hs {
		errs = append(errs, h.Close())
	}
	return errors.Join(errs...)
}

// fixupAndValidate is called by the ELF reader right before marshaling the
// instruction stream. It performs last-minute adjustments to the program and
// runs some sanity checks before sending it off to the kernel.
func fixupAndValidate(insns asm.Instructions) error {
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		// Map load was tagged with a Reference, but does not contain a Map pointer.
		needsMap := ins.Reference() != "" || ins.Metadata.Get(kconfigMetaKey{}) != nil
		if ins.IsLoadFromMap() && needsMap && ins.Map() == nil {
			return fmt.Errorf("instruction %d: %w", iter.Index, asm.ErrUnsatisfiedMapReference)
		}

		fixupProbeReadKernel(ins)
	}

	return nil
}

// POISON_CALL_KFUNC_BASE in libbpf.
// https://github.com/libbpf/libbpf/blob/2778cbce609aa1e2747a69349f7f46a2f94f0522/src/libbpf.c#L5767
const kfuncCallPoisonBase = 2002000000

// fixupKfuncs loops over all instructions in search for kfunc calls.
// If at least one is found, the current kernels BTF and module BTFis are searched to set Instruction.Constant
// and Instruction.Offset to the correct values.
func fixupKfuncs(insns asm.Instructions) (_ handles, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		if metadata := ins.Metadata.Get(kfuncMetaKey{}); metadata != nil {
			goto fixups
		}
	}

	return nil, nil

fixups:
	// only load the kernel spec if we found at least one kfunc call
	kernelSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	fdArray := make(handles, 0)
	defer closeOnError(&fdArray)

	for {
		ins := iter.Ins

		metadata := ins.Metadata.Get(kfuncMetaKey{})
		if metadata == nil {
			if !iter.Next() {
				// break loop if this was the last instruction in the stream.
				break
			}
			continue
		}

		// check meta, if no meta return err
		kfm, _ := metadata.(*kfuncMeta)
		if kfm == nil {
			return nil, fmt.Errorf("kfuncMetaKey doesn't contain kfuncMeta")
		}

		target := btf.Type((*btf.Func)(nil))
		spec, module, err := findTargetInKernel(kernelSpec, kfm.Func.Name, &target)
		if kfm.Binding == elf.STB_WEAK && errors.Is(err, btf.ErrNotFound) {
			if ins.IsKfuncCall() {
				// If the kfunc call is weak and not found, poison the call. Use a recognizable constant
				// to make it easier to debug. And set src to zero so the verifier doesn't complain
				// about the invalid imm/offset values before dead-code elimination.
				ins.Constant = kfuncCallPoisonBase
				ins.Src = 0
			} else if ins.OpCode.IsDWordLoad() {
				// If the kfunc DWordLoad is weak and not found, set its address to 0.
				ins.Constant = 0
				ins.Src = 0
			} else {
				return nil, fmt.Errorf("only kfunc calls and dword loads may have kfunc metadata")
			}

			iter.Next()
			continue
		}
		// Error on non-weak kfunc not found.
		if errors.Is(err, btf.ErrNotFound) {
			return nil, fmt.Errorf("kfunc %q: %w", kfm.Func.Name, ErrNotSupported)
		}
		if err != nil {
			return nil, err
		}

		idx, err := fdArray.add(module)
		if err != nil {
			return nil, err
		}

		if err := btf.CheckTypeCompatibility(kfm.Func.Type, target.(*btf.Func).Type); err != nil {
			return nil, &incompatibleKfuncError{kfm.Func.Name, err}
		}

		id, err := spec.TypeID(target)
		if err != nil {
			return nil, err
		}

		ins.Constant = int64(id)
		ins.Offset = int16(idx)

		if !iter.Next() {
			break
		}
	}

	return fdArray, nil
}

type incompatibleKfuncError struct {
	name string
	err  error
}

func (ike *incompatibleKfuncError) Error() string {
	return fmt.Sprintf("kfunc %q: %s", ike.name, ike.err)
}

// fixupProbeReadKernel replaces calls to bpf_probe_read_{kernel,user}(_str)
// with bpf_probe_read(_str) on kernels that don't support it yet.
func fixupProbeReadKernel(ins *asm.Instruction) {
	if !ins.IsBuiltinCall() {
		return
	}

	// Kernel supports bpf_probe_read_kernel, nothing to do.
	if haveProbeReadKernel() == nil {
		return
	}

	switch asm.BuiltinFunc(ins.Constant) {
	case asm.FnProbeReadKernel, asm.FnProbeReadUser:
		ins.Constant = int64(asm.FnProbeRead)
	case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
		ins.Constant = int64(asm.FnProbeReadStr)
	}
}

// resolveKconfigReferences creates and populates a .kconfig map if necessary.
//
// Returns a nil Map and no error if no references exist.
func resolveKconfigReferences(insns asm.Instructions) (_ *Map, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	var spec *MapSpec
	iter := insns.Iterate()
	for iter.Next() {
		meta, _ := iter.Ins.Metadata.Get(kconfigMetaKey{}).(*kconfigMeta)
		if meta != nil {
			spec = meta.Map
			break
		}
	}

	if spec == nil {
		return nil, nil
	}

	cpy := spec.Copy()
	if err := resolveKconfig(cpy); err != nil {
		return nil, err
	}

	kconfig, err := NewMap(cpy)
	if err != nil {
		return nil, err
	}
	defer closeOnError(kconfig)

	// Resolve all instructions which load from .kconfig map with actual map
	// and offset inside it.
	iter = insns.Iterate()
	for iter.Next() {
		meta, _ := iter.Ins.Metadata.Get(kconfigMetaKey{}).(*kconfigMeta)
		if meta == nil {
			continue
		}

		if meta.Map != spec {
			return nil, fmt.Errorf("instruction %d: reference to multiple .kconfig maps is not allowed", iter.Index)
		}

		if err := iter.Ins.AssociateMap(kconfig); err != nil {
			return nil, fmt.Errorf("instruction %d: %w", iter.Index, err)
		}

		// Encode a map read at the offset of the var in the datasec.
		iter.Ins.Constant = int64(uint64(meta.Offset) << 32)
		iter.Ins.Metadata.Set(kconfigMetaKey{}, nil)
	}

	return kconfig, nil
}

// resolveKconfig resolves all variables declared in .kconfig and populates
// m.Contents. Does nothing if the given m.Contents is non-empty.
func resolveKconfig(m *MapSpec) error {
	ds, ok := m.Value.(*btf.Datasec)
	if !ok {
		return errors.New("map value is not a Datasec")
	}

	type configInfo struct {
		offset uint32
		typ    btf.Type
	}

	configs := make(map[string]configInfo)

	data := make([]byte, ds.Size)
	for _, vsi := range ds.Vars {
		v := vsi.Type.(*btf.Var)
		n := v.TypeName()

		switch n {
		case "LINUX_KERNEL_VERSION":
			if integer, ok := v.Type.(*btf.Int); !ok || integer.Size != 4 {
				return fmt.Errorf("variable %s must be a 32 bits integer, got %s", n, v.Type)
			}

			kv, err := internal.KernelVersion()
			if err != nil {
				return fmt.Errorf("getting kernel version: %w", err)
			}
			internal.NativeEndian.PutUint32(data[vsi.Offset:], kv.Kernel())

		case "LINUX_HAS_SYSCALL_WRAPPER":
			integer, ok := v.Type.(*btf.Int)
			if !ok {
				return fmt.Errorf("variable %s must be an integer, got %s", n, v.Type)
			}
			var value uint64 = 1
			if err := haveSyscallWrapper(); errors.Is(err, ErrNotSupported) {
				value = 0
			} else if err != nil {
				return fmt.Errorf("unable to derive a value for LINUX_HAS_SYSCALL_WRAPPER: %w", err)
			}

			if err := kconfig.PutInteger(data[vsi.Offset:], integer, value); err != nil {
				return fmt.Errorf("set LINUX_HAS_SYSCALL_WRAPPER: %w", err)
			}

		default: // Catch CONFIG_*.
			configs[n] = configInfo{
				offset: vsi.Offset,
				typ:    v.Type,
			}
		}
	}

	// We only parse kconfig file if a CONFIG_* variable was found.
	if len(configs) > 0 {
		f, err := kconfig.Find()
		if err != nil {
			return fmt.Errorf("cannot find a kconfig file: %w", err)
		}
		defer f.Close()

		filter := make(map[string]struct{}, len(configs))
		for config := range configs {
			filter[config] = struct{}{}
		}

		kernelConfig, err := kconfig.Parse(f, filter)
		if err != nil {
			return fmt.Errorf("cannot parse kconfig file: %w", err)
		}

		for n, info := range configs {
			value, ok := kernelConfig[n]
			if !ok {
				return fmt.Errorf("config option %q does not exists for this kernel", n)
			}

			err := kconfig.PutValue(data[info.offset:], info.typ, value)
			if err != nil {
				return fmt.Errorf("problem adding value for %s: %w", n, err)
			}
		}
	}

	m.Contents = []MapKV{{uint32(0), data}}

	return nil
}

// findTargetInKernel attempts to find a named type in the current kernel.
//
// target will point at the found type after a successful call. Searches both
// vmlinux and any loaded modules.
//
// Returns a non-nil handle if the type was found in a module, or btf.ErrNotFound
// if the type wasn't found at all.
func findTargetInKernel(kernelSpec *btf.Spec, typeName string, target *btf.Type) (*btf.Spec, *btf.Handle, error) {
	err := kernelSpec.TypeByName(typeName, target)
	if errors.Is(err, btf.ErrNotFound) {
		spec, module, err := findTargetInModule(kernelSpec, typeName, target)
		if err != nil {
			return nil, nil, fmt.Errorf("find target in modules: %w", err)
		}
		return spec, module, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("find target in vmlinux: %w", err)
	}
	return kernelSpec, nil, err
}

// findTargetInModule attempts to find a named type in any loaded module.
//
// base must contain the kernel's types and is used to parse kmod BTF. Modules
// are searched in the order they were loaded.
//
// Returns btf.ErrNotFound if the target can't be found in any module.
func findTargetInModule(base *btf.Spec, typeName string, target *btf.Type) (*btf.Spec, *btf.Handle, error) {
	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	for it.Next() {
		info, err := it.Handle.Info()
		if err != nil {
			return nil, nil, fmt.Errorf("get info for BTF ID %d: %w", it.ID, err)
		}

		if !info.IsModule() {
			continue
		}

		spec, err := it.Handle.Spec(base)
		if err != nil {
			return nil, nil, fmt.Errorf("parse types for module %s: %w", info.Name, err)
		}

		err = spec.TypeByName(typeName, target)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("lookup type in module %s: %w", info.Name, err)
		}

		return spec, it.Take(), nil
	}
	if err := it.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate modules: %w", err)
	}

	return nil, nil, btf.ErrNotFound
}
