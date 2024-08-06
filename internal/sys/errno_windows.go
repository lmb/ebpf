package sys

// The code in this file is derived from syscall_unix.go in the Go source code,
// licensed under the MIT license.

import (
	"errors"
	"os"
)

// Errno is a portable version of unix.Errno.
//
// It's required because the Windows bpf() translation layer returns unix.Errno,
// but the type and constants aren't accessible on non-Unix OS.
type Errno uintptr

func (e Errno) Error() string {
	return e.String()
}

func (e Errno) Is(target error) bool {
	switch target {
	case os.ErrPermission:
		return e == EACCES || e == EPERM
	case os.ErrExist:
		return e == EEXIST /* || e == ENOTEMPTY */
	case os.ErrNotExist:
		return e == ENOENT
	case errors.ErrUnsupported:
		return /* e == ENOSYS || e == ENOTSUP || */ e == EOPNOTSUPP
	}
	return false
}

func (e Errno) Temporary() bool {
	return e == EINTR || /* e == EMFILE || e == ENFILE || */ e.Timeout()
}

func (e Errno) Timeout() bool {
	return e == EAGAIN /* || e == EWOULDBLOCK || e == ETIMEDOUT */
}
