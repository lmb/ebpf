package auxv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
	"golang.org/x/exp/constraints"
)

// See https://elixir.bootlin.com/linux/v6.5.5/source/include/uapi/linux/auxvec.h
const (
	AT_NULL         = 0  // End of vector
	AT_SYSINFO_EHDR = 33 // Offset to vDSO blob in process image
)

func parseAsUintptr[T constraints.Unsigned](r io.Reader, order binary.ByteOrder) ([]uintptr, error) {
	var auxv []uintptr
	var tmp T
	for {
		err := binary.Read(r, order, &tmp)
		if errors.Is(err, io.EOF) {
			return auxv, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read auxv: %w", err)
		}

		auxv = append(auxv, uintptr(tmp))
	}
}

func FromFile[T constraints.Unsigned](file string, order binary.ByteOrder) ([]uintptr, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseAsUintptr[T](f, order)
}

func Get() ([]uintptr, error) {
	if auxv := runtime_getAuxv(); auxv != nil {
		return auxv, nil
	}

	// Read data of the auxiliary vector through proc if we can't get it from
	// the runtime.
	// https://man7.org/linux/man-pages/man3/getauxval.3.html
	av, err := os.Open("/proc/self/auxv")
	if errors.Is(err, unix.EACCES) {
		return nil, fmt.Errorf("opening auxv: %w (process may not be dumpable due to file capabilities)", err)
	}
	if err != nil {
		return nil, fmt.Errorf("opening auxv: %w", err)
	}
	defer av.Close()

	if unsafe.Sizeof((uintptr)(0)) == 4 {
		return parseAsUintptr[uint32](av, internal.NativeEndian)
	}

	return parseAsUintptr[uint64](av, internal.NativeEndian)
}
