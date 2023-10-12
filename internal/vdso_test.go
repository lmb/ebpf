package internal

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/auxv"
	qt "github.com/frankban/quicktest"
)

func TestAuxvVDSOMemoryAddress(t *testing.T) {
	for _, testcase := range []struct {
		source  string
		parser  func(string, binary.ByteOrder) ([]uintptr, error)
		address uint64
	}{
		{"auxv64le.bin", auxv.FromFile[uint64], 0x7ffd377e5000},
		{"auxv32le.bin", auxv.FromFile[uint32], 0xb7fc3000},
	} {
		t.Run(testcase.source, func(t *testing.T) {
			auxv, err := testcase.parser("testdata/"+testcase.source, binary.LittleEndian)
			qt.Assert(t, err, qt.IsNil)

			addr, err := vdsoMemoryAddress(auxv)
			if err != nil {
				t.Fatal(err)
			}

			if uint64(addr) != testcase.address {
				t.Errorf("Expected vDSO memory address %x, got %x", testcase.address, addr)
			}
		})
	}
}

func TestAuxvNoVDSO(t *testing.T) {
	_, err := vdsoMemoryAddress([]uintptr{auxv.AT_NULL, 0})
	qt.Assert(t, err, qt.ErrorIs, errAuxvNoVDSO)
}

func TestVDSOVersion(t *testing.T) {
	_, err := vdsoVersion()
	qt.Assert(t, err, qt.IsNil)
}

func TestLinuxVersionCodeEmbedded(t *testing.T) {
	tests := []struct {
		file    string
		version uint32
	}{
		{
			"testdata/vdso.bin",
			uint32(328828), // 5.4.124
		},
		{
			"testdata/vdso_multiple_notes.bin",
			uint32(328875), // Container Optimized OS v85 with a 5.4.x kernel
		},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			vdso, err := os.Open(test.file)
			if err != nil {
				t.Fatal(err)
			}
			defer vdso.Close()

			vc, err := vdsoLinuxVersionCode(vdso)
			if err != nil {
				t.Fatal(err)
			}

			if vc != test.version {
				t.Errorf("Expected version code %d, got %d", test.version, vc)
			}
		})
	}
}
