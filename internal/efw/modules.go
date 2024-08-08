//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Module is the global handle for the eBPF for Windows user-space API.
var Module = windows.NewLazyDLL("ebpfapi.dll")

// void ebpf_free_mem(_In_opt_ _Post_invalid_ const void* p)
var freeProc = Module.NewProc("ebpf_free_mem")

// Call a function which returns a C int.
//
//go:uintptrescapes
func CallInt(proc *windows.LazyProc, args ...uintptr) (int, windows.Errno, error) {
	if err := proc.Find(); err != nil {
		return 0, 0, fmt.Errorf("%s: %w", proc.Name, err)
	}

	res, _, err := proc.Call(args...)
	return int(int32(res)), err.(windows.Errno), nil
}

// Call a function which returns ebpf_result_t.
//
//go:uintptrescapes
func CallResult(proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}

	res, _, _ := proc.Call(args...)
	if err := ResultToError(Result(res)); err != nil {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}
	return nil
}

// Size is the equivalent of size_t.
// TODO: Is this really size_t?
type Size uint64

type Pointer[T any] struct {
	ptr uintptr
}

func (p Pointer[T]) Cast() *T {
	// TODO: Is this dodgy?
	return (*T)(unsafe.Pointer(p.ptr))
}

// Free memory allocated by the efW runtime.
func (p Pointer[T]) Free() {
	freeProc.Call(p.ptr)
}
