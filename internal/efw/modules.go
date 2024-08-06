//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Module is the global handle for the eBPF for Windows user-space API.
var Module = windows.NewLazyDLL("ebpfapi.dll")

func FindProcs(procs ...*windows.LazyProc) error {
	for _, proc := range procs {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%s: %w", proc.Name, err)
		}
	}
	return nil
}
