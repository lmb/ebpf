package sys

import "runtime"

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=Errno -tags=windows -output=errno_string_windows.go

const (
	EPERM      Errno = 1
	ENOENT     Errno = 2
	ESRCH      Errno = 3
	EINTR      Errno = 4
	E2BIG      Errno = 7
	EBADF      Errno = 9
	EAGAIN     Errno = 11
	EACCES     Errno = 13
	EFAULT     Errno = 14
	EEXIST     Errno = 17
	ENODEV     Errno = 19
	EINVAL     Errno = 22
	ENOSPC     Errno = 28
	EILSEQ     Errno = 84
	EOPNOTSUPP Errno = 95
	ESTALE     Errno = 116
	// ENOTSUPP is a Linux internal error code that has leaked into UAPI.
	//
	// It is not the same as ENOTSUP or EOPNOTSUPP.
	ENOTSUPP Errno = 524
)

var (
	errEAGAIN error = wrappedErrno{EAGAIN}
	errEINVAL error = wrappedErrno{EINVAL}
	errENOENT error = wrappedErrno{ENOENT}
)

func errnoErr(e Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return wrappedErrno{e}
}

// wrappedErrno wraps Errno to prevent direct comparisons with
// syscall.E* or unix.E* constants.
//
// You should never export an error of this type.
type wrappedErrno struct {
	Errno
}

func (we wrappedErrno) Unwrap() error {
	return we.Errno
}

func (we wrappedErrno) Error() string {
	if runtime.GOOS == "linux" && we.Errno == ENOTSUPP {
		return "operation not supported"
	}
	return we.Errno.Error()
}
