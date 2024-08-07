package sys

import (
	"math"
	"runtime"
	"strconv"

	"github.com/cilium/ebpf/internal/testutils/testmain"
)

// A value for an invalid fd.
//
// Luckily this is consistent across Linux and Windows.
//
// See https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L25
const invalidFd = -1

// The underlying type of a file descriptor.
//
// Has to match the size of the C type exactly since we
// sometimes pass a pointer to this.
//
// Checked against GCC on arm64, amd64 and MSVC on amd64.
//
// See https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L24
type RawFD int32

func newFD(value int) *FD {
	testmain.TraceFD(value, 1)

	fd := &FD{value}
	runtime.SetFinalizer(fd, (*FD).finalize)
	return fd
}

// finalize is set as the FD's runtime finalizer and
// sends a leak trace before calling FD.Close().
func (fd *FD) finalize() {
	if fd.raw == invalidFd {
		return
	}

	testmain.LeakFD(fd.raw)

	_ = fd.Close()
}

func (fd *FD) Int() int {
	return int(fd.raw)
}

func (fd *FD) Uint() uint32 {
	if fd.raw == invalidFd {
		// Best effort: this is the number most likely to be an invalid file
		// descriptor. It is equal to -1 (on two's complement arches).
		return math.MaxUint32
	}
	return uint32(fd.raw)
}

func (fd *FD) String() string {
	return strconv.FormatInt(int64(fd.raw), 10)
}

func (fd *FD) disown() int {
	value := fd.raw
	testmain.ForgetFD(value)
	fd.raw = invalidFd

	runtime.SetFinalizer(fd, nil)
	return value
}
