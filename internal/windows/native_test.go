//go:build windows

package windows

import (
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"
)

func TestLoadProgram(t *testing.T) {
	for _, file := range []string{
		"testdata/empty.sys",
		"testdata/printk.sys",
	} {
		t.Run(file, func(t *testing.T) {
			maps, programs, err := LoadNativeImage(file)
			qt.Assert(t, qt.IsNil(err))

			for _, m := range maps {
				var info MapInfo
				qt.Assert(t, qt.IsNil(GetObjectInfo(m, &info)))
				name := windows.ByteSliceToString(unsafeSliceBytes(info.Name[:]))
				t.Logf("map %v: id %v name %v", m, info.Id, name)
			}

			for _, p := range programs {
				var info ProgramInfo
				qt.Assert(t, qt.IsNil(GetObjectInfo(p, &info)))
				name := windows.ByteSliceToString(unsafeSliceBytes(info.Name[:]))
				t.Logf("program %v: id %v name %v", p, info.Id, name)
			}

			for _, h := range append(maps, programs...) {
				qt.Check(t, qt.IsNil(windows.CloseHandle(h)))
			}
		})
	}
}
