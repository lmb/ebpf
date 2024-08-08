//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Module is the global handle for the eBPF for Windows user-space API.
var Module = windows.NewLazyDLL("ebpfapi.dll")

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

