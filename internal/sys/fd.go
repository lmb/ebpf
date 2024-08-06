package sys

import (
	"math"
	"runtime"
	"strconv"

	"github.com/cilium/ebpf/internal/testutils/testmain"
)

func newFD(value raw) *FD {
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
	return fd.raw
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

func (fd *FD) disown() raw {
	value := fd.raw
	testmain.ForgetFD(value)
	fd.raw = invalidFd

	runtime.SetFinalizer(fd, nil)
	return value
}
