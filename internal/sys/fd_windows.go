package sys

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

const invalidFd = windows.InvalidHandle

var ErrClosedFd syscall.Errno = windows.ERROR_INVALID_HANDLE

type raw = windows.Handle

type FD struct {
	raw windows.Handle
}

// NewFD wraps a raw fd with a finalizer.
//
// You must not use the raw fd after calling this function, since the underlying
// file descriptor number may change. This is because the BPF UAPI assumes that
// zero is not a valid fd value.
func NewFD(value windows.Handle) (*FD, error) {
	if value == invalidFd {
		return nil, fmt.Errorf("invalid fd %d", value)
	}

	return newFD(value), nil
}

func (fd *FD) Close() error {
	if fd.raw == invalidFd {
		return nil
	}

	return windows.CloseHandle(fd.disown())
}
