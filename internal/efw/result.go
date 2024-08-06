//go:build windows

package efw

import "fmt"

// See https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_result.h
type Result int32

func ResultToError(res Result) error {
	switch res {
	case 0:
		return nil
	default:
		return fmt.Errorf("unknown result: %d", res)
	}
}
