package vdso

import (
	"encoding/binary"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestParseAsUintptr(t *testing.T) {
	t.Run("uint64", func(t *testing.T) {
		f, err := os.Open("../testdata/auxv64le.bin")
		qt.Assert(t, err, qt.IsNil)
		defer f.Close()

		auxv, err := parseAsUintptr[uint64](f, binary.LittleEndian)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, auxv, qt.HasLen, 40)
	})

	t.Run("uint32", func(t *testing.T) {
		f, err := os.Open("../testdata/auxv32le.bin")
		qt.Assert(t, err, qt.IsNil)
		defer f.Close()

		auxv, err := parseAsUintptr[uint32](f, binary.LittleEndian)
		qt.Assert(t, err, qt.IsNil)
		qt.Assert(t, auxv, qt.HasLen, 44)
	})
}
