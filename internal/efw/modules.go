//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"golang.org/x/sys/windows"
)

// Module is the global handle for the eBPF for Windows user-space API.
var Module = windows.NewLazyDLL("ebpfapi.dll")
