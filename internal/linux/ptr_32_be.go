//go:build armbe || mips || mips64p32

package linux

import (
	"unsafe"
)

// Pointer wraps an unsafe.Pointer to be 64bit to
// conform to the syscall specification.
type Pointer struct {
	pad uint32
	ptr unsafe.Pointer
}
