package sys

import (
	"errors"
	"syscall"
	"testing"
)

func TestSyscallError(t *testing.T) {
	const E syscall.Errno = 1

	err := errors.New("foo")
	foo := Error(err, E)

	if !errors.Is(foo, E) {
		t.Error("SyscallError is not the wrapped errno")
	}

	if !errors.Is(foo, err) {
		t.Error("SyscallError is not the wrapped error")
	}

	if errors.Is(E, foo) {
		t.Error("Errno is the SyscallError")
	}

	if errors.Is(err, foo) {
		t.Error("Error is the SyscallError")
	}
}
