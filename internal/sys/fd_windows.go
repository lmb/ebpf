package sys

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf/internal/efw"
	"golang.org/x/sys/windows"
)

var ErrClosedFd syscall.Errno = windows.ERROR_INVALID_HANDLE

// https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L25
const invalidFd = RawFD(-1)

// The underlying type of a file descriptor.
//
// Has to match the size of the C type exactly since we
// sometimes pass a pointer to this.
//
// https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L24
type RawFD = int32

// FD wraps a handle which is managed by the eBPF for Windows runtime.
//
// It is not equivalent to a real file descriptor or handle.
type FD struct {
	raw RawFD
}

// NewFD wraps a raw fd with a finalizer.
//
// You must not use the raw fd after calling this function.
func NewFD(value RawFD) (*FD, error) {
	if value == invalidFd {
		return nil, fmt.Errorf("invalid fd %d", value)
	}

	if value == 0 {
		// The bpf() syscall API can't deal with zero fds but we can't dup because
		// the handle is managed by efW.
		return nil, fmt.Errorf("invalid zero fd")
	}

	return newFD(value), nil
}

// Universal C runtime base.
//
// Bad things happen if ebpfapi.dll is linked against the non-debug version
// and vice versa.
var ucrt = windows.NewLazyDLL("ucrtbased.dll")

// int _close(int fd)
var ucrtCloseProc = ucrt.NewProc("_close")

// int _dup(int fd)
var ucrtDupProc = ucrt.NewProc("_dup")

func (fd *FD) Close() error {
	if fd.raw == invalidFd {
		return nil
	}

	// efW uses _open_osfhandle() to turn a handle into a virtual fd.
	// We need to call into the C runtime to close it.
	// TODO: This should also go via ebpfapi.dll
	res, errNo, err := efw.CallInt(ucrtCloseProc, uintptr(fd.disown()))
	if err != nil {
		return err
	}
	if res == -1 {
		return fmt.Errorf("close: %w", errNo)
	}
	return nil
}

func (fd *FD) Dup() (*FD, error) {
	if fd.raw == invalidFd {
		return nil, ErrClosedFd
	}

	res, errNo, err := efw.CallInt(ucrtDupProc, uintptr(fd.raw))
	if err != nil {
		return nil, err
	}
	if res == -1 {
		return nil, fmt.Errorf("dup: %w", errNo)
	}

	return NewFD(int32(res))
}
