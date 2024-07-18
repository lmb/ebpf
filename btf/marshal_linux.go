package btf

import (
	"fmt"

	"github.com/cilium/ebpf/internal"
)

// KernelMarshalOptions will generate BTF suitable for the current kernel.
func KernelMarshalOptions() *MarshalOptions {
	return &MarshalOptions{
		Order:              internal.NativeEndian,
		StripFuncLinkage:   haveFuncLinkage() != nil,
		ReplaceEnum64:      haveEnum64() != nil,
		PreventNoTypeFound: true, // All current kernels require this.
	}
}

// MarshalMapKV creates a BTF object containing a map key and value.
//
// The function is intended for the use of the ebpf package and may be removed
// at any point in time.
func MarshalMapKV(key, value Type) (_ *Handle, keyID, valueID TypeID, err error) {
	var b Builder

	if key != nil {
		keyID, err = b.Add(key)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("add key type: %w", err)
		}
	}

	if value != nil {
		valueID, err = b.Add(value)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("add value type: %w", err)
		}
	}

	handle, err := NewHandle(&b)
	if err != nil {
		// Check for 'full' map BTF support, since kernels between 4.18 and 5.2
		// already support BTF blobs for maps without Var or Datasec just fine.
		if err := haveMapBTF(); err != nil {
			return nil, 0, 0, err
		}
	}
	return handle, keyID, valueID, err
}
