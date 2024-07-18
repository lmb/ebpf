//go:build linux

package linux

import (
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// ENOTSUPP is a Linux internal error code that has leaked into UAPI.
//
// It is not the same as ENOTSUP or EOPNOTSUPP.
const ENOTSUPP = syscall.Errno(524)

// BPF wraps SYS_BPF.
//
// Any pointers contained in attr must use the Pointer type from this package.
func BPF(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	// Prevent the Go profiler from repeatedly interrupting the verifier,
	// which could otherwise lead to a livelock due to receiving EAGAIN.
	if cmd == BPF_PROG_LOAD || cmd == BPF_PROG_RUN {
		maskProfilerSignal()
		defer unmaskProfilerSignal()
	}

	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		// As of ~4.20 the verifier can be interrupted by a signal,
		// and returns EAGAIN in that case.
		if errNo == unix.EAGAIN && cmd == BPF_PROG_LOAD {
			continue
		}

		var err error
		if errNo != 0 {
			err = wrappedErrno{errNo}
		}

		return r1, err
	}
}

// Info is implemented by all structs that can be passed to the ObjInfo syscall.
//
//	MapInfo
//	ProgInfo
//	LinkInfo
//	BtfInfo
type Info interface {
	info() (unsafe.Pointer, uint32)
}

var _ Info = (*MapInfo)(nil)

func (i *MapInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

var _ Info = (*ProgInfo)(nil)

func (i *ProgInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

var _ Info = (*LinkInfo)(nil)

func (i *LinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *TracingLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *CgroupLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *NetNsLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *XDPLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *TcxLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *NetfilterLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *NetkitLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *KprobeMultiLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *KprobeLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

var _ Info = (*BtfInfo)(nil)

func (i *BtfInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

func (i *PerfEventLinkInfo) info() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(i), uint32(unsafe.Sizeof(*i))
}

// ObjInfo retrieves information about a BPF Fd.
//
// info may be one of MapInfo, ProgInfo, LinkInfo and BtfInfo.
func ObjInfo(fd *sys.FD, info Info) error {
	ptr, len := info.info()
	err := ObjGetInfoByFd(&ObjGetInfoByFdAttr{
		BpfFd:   fd.Uint(),
		InfoLen: len,
		Info:    NewPointer(ptr),
	})
	runtime.KeepAlive(fd)
	return err
}

// wrappedErrno wraps syscall.Errno to prevent direct comparisons with
// syscall.E* or unix.E* constants.
//
// You should never export an error of this type.
type wrappedErrno struct {
	syscall.Errno
}

func (we wrappedErrno) Unwrap() error {
	return we.Errno
}

func (we wrappedErrno) Error() string {
	if we.Errno == ENOTSUPP {
		return "operation not supported"
	}
	return we.Errno.Error()
}
