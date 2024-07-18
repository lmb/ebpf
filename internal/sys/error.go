package sys

import "syscall"

type syscallError struct {
	error
	errno syscall.Errno
}

func Error(err error, errno syscall.Errno) error {
	return &syscallError{err, errno}
}

func (se *syscallError) Is(target error) bool {
	return target == se.error
}

func (se *syscallError) Unwrap() error {
	return se.errno
}
