package sys

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
)

func newFD(value raw) *FD {
	if onLeakFD != nil {
		// Attempt to store the caller's stack for the given fd value.
		// Panic if fds contains an existing stack for the fd.
		old, exist := fds.LoadOrStore(value, callersFrames())
		if exist {
			f := old.(*runtime.Frames)
			panic(fmt.Sprintf("found existing stack for fd %d:\n%s", value, FormatFrames(f)))
		}
	}

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

	// Invoke the fd leak callback. Calls LoadAndDelete to guarantee the callback
	// is invoked at most once for one sys.FD allocation, runtime.Frames can only
	// be unwound once.
	f, ok := fds.LoadAndDelete(fd.raw)
	if ok && onLeakFD != nil {
		onLeakFD(f.(*runtime.Frames))
	}

	_ = fd.Close()
}

func (fd *FD) String() string {
	return strconv.FormatInt(int64(fd.raw), 10)
}

func (fd *FD) disown() raw {
	fds.Delete(fd.raw)

	value := fd.raw
	fd.raw = invalidFd

	runtime.SetFinalizer(fd, nil)
	return value
}

// File takes ownership of FD and turns it into an [*os.File].
//
// You must not use the FD after the call returns.
//
// Returns nil if the FD is not valid.
func (fd *FD) File(name string) *os.File {
	if fd.raw == invalidFd {
		return nil
	}

	return os.NewFile(uintptr(fd.disown()), name)
}
