package sys

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

var ErrClosedFd syscall.Errno = windows.ERROR_INVALID_HANDLE

// https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L25
const invalidFd = raw(-1)

// Using int here isn't entirely correct since eBPF for Windows defines this
// to be int32. However Go guarantees that int is at least int32, and using int
// here is more ergonomic.
//
// https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L24
type raw = int

// FD wraps a handle which is managed by the eBPF for Windows runtime.
//
// It is not equivalent to a real file descriptor or handle.
type FD struct {
	raw raw
}

// NewFD wraps a raw fd with a finalizer.
//
// You must not use the raw fd after calling this function.
func NewFD(value raw) (*FD, error) {
	if value == invalidFd || value == 0 {
		// We also reject 0 since we
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

// ebpf_result_t ebpf_close_fd(fd_t fd)
var ucrtCloseProc = ucrt.NewProc("_close")

// int _dup(int fd)
var ucrtDupProc = ucrt.NewProc("_dup")

func (fd *FD) Close() error {
	if fd.raw == invalidFd {
		return nil
	}

	if err := ucrtCloseProc.Find(); err != nil {
		return err
	}

	// efW uses _open_osfhandle() to turn a handle into a virtual fd.
	// We need to call into the C runtime to close it.
	// TODO: This should also go via ebpfapi.dll
	res, _, _ := ucrtCloseProc.Call(uintptr(fd.disown()))
	return winResultToError(winResult(res))
}

func (fd *FD) Dup() (*FD, error) {
	if fd.raw == invalidFd {
		return nil, ErrClosedFd
	}

	if err := ucrtDupProc.Find(); err != nil {
		return nil, err
	}

	res, _, err := ucrtDupProc.Call(uintptr(fd.raw))
	if int32(res) == -1 {
		return nil, fmt.Errorf("dup: %w", err)
	}

	return NewFD(int(int32(res)))
}
