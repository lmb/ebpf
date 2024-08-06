package sys

import "fmt"

// See https://github.com/microsoft/ebpf-for-windows/blob/main/include/ebpf_result.h
type winResult int // XXX: What type?

func winResultToError(res winResult) error {
	switch res {
	case 0:
		return nil
	default:
		return fmt.Errorf("unknown result: %d", res)
	}
}
