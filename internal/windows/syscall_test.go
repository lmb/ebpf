//go:build windows

package windows

import (
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"
)

func TestMap(t *testing.T) {
	m := newMap(t)

	tmp := []byte{1, 2, 3, 5}
	out := make([]byte, len(tmp))

	qt.Assert(t, qt.ErrorIs(MapFindElement(m, tmp, out, false), windows.ERROR_PATH_NOT_FOUND))

	qt.Assert(t, qt.IsNil(MapUpdateElement(m, tmp, tmp, 0)))
	qt.Assert(t, qt.IsNotNil(MapUpdateElement(m, tmp, tmp, math.MaxUint32)))

	qt.Assert(t, qt.IsNil(MapGetNeyKey(m, nil, out)))
	qt.Assert(t, qt.DeepEquals(out, tmp))
	qt.Assert(t, qt.ErrorIs(MapGetNeyKey(m, out, out), windows.ERROR_NO_MORE_MATCHES))

	clear(out)
	qt.Assert(t, qt.IsNil(MapFindElement(m, tmp, out, false)))
	qt.Assert(t, qt.DeepEquals(out, tmp))

	qt.Assert(t, qt.IsNil(MapDeleteElement(m, tmp)))
	qt.Assert(t, qt.ErrorIs(MapDeleteElement(m, tmp), windows.ERROR_NOT_FOUND))
}

func TestMapId(t *testing.T) {
	m := newMap(t)

	id, err := GetNextMapId(0)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(id, 0)))

	m2, err := GetMapHandleById(id)
	qt.Assert(t, qt.IsNil(err))
	defer windows.CloseHandle(m2)
	qt.Assert(t, qt.Not(qt.Equals(m2, m)))
}

func TestMapHandle(t *testing.T) {
	inner := newMap(t)

	m, err := CreateMap("test", inner, &MapDefinition{
		Type:        7, // BPF_MAP_TYPE_ARRAY_OF_MAPS
		Key_size:    4,
		Value_size:  4,
		Max_entries: 1,
		Pinning:     0,
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() {
		qt.Assert(t, qt.IsNil(windows.CloseHandle(m)))
	})

	qt.Assert(t, qt.IsNil(MapUpdateElementWithHandle(m, []byte{0, 0, 0, 0}, inner, 0)))
	// TODO: Semantics.
	qt.Assert(t, qt.IsNil(MapUpdateElementWithHandle(m, []byte{0, 0, 0, 0}, windows.InvalidHandle, 0)))
}

func TestPinning(t *testing.T) {
	a := newMap(t)
	b := newMap(t)
	path := filepath.Join(t.TempDir(), "a")
	qt.Assert(t, qt.IsNil(UpdatePinning(a, path)))
	qt.Assert(t, qt.IsNotNil(UpdatePinning(b, path)))

	c, err := GetPinnedObject(path)
	qt.Assert(t, qt.IsNil(err))
	defer windows.CloseHandle(c)
	qt.Assert(t, qt.Not(qt.Equals(c, a)), qt.Commentf("pinned handles should be distinct"))

	// TODO: These semantics are wonky.
	qt.Assert(t, qt.IsNil(UpdatePinning(windows.InvalidHandle, path)))
	qt.Assert(t, qt.IsNil(UpdatePinning(b, path)))
}

func newMap(tb testing.TB) windows.Handle {
	m, err := CreateMap("test", windows.InvalidHandle, &MapDefinition{
		Type:         1,
		Key_size:     4,
		Value_size:   4,
		Max_entries:  1,
		Inner_map_id: 0, // ???
		Pinning:      0,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		qt.Assert(tb, qt.IsNil(windows.CloseHandle(m)))
	})
	return m
}

func TestMain(m *testing.M) {
	cleanup, err := startWPR()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Disabling trace logging:", err)
		cleanup = func(io.Writer) error { return nil }
	}

	code := m.Run()
	if code == 0 {
		cleanup(nil)
		os.Exit(code)
	}

	if err := cleanup(os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error while reading trace log:", err)
	}

	os.Exit(code)
}

// startWPR starts a trace log for eBPF for Windows related events.
//
// * https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#using-tracing
// * https://devblogs.microsoft.com/performance-diagnostics/controlling-the-event-session-name-with-the-instance-name/ and
func startWPR() (func(io.Writer) error, error) {
	def := filepath.Join(os.Getenv("ProgramFiles"), "ebpf-for-windows\\ebpfforwindows.wprp")
	if _, err := os.Stat(def); err != nil {
		return nil, err
	}

	path, err := os.MkdirTemp("", "ebpf-go-trace")
	if err != nil {
		return nil, err
	}

	session := fmt.Sprintf("epbf-go-%d", os.Getpid())
	wpr := exec.Command("wpr.exe", "-start", def, "-filemode", "-instancename", session)
	wpr.Stderr = os.Stderr
	if err := wpr.Run(); err != nil {
		_ = os.RemoveAll(path)
		return nil, err
	}

	return func(out io.Writer) error {
		defer os.RemoveAll(path)

		trace := filepath.Join(path, "trace.etl")
		wpr := exec.Command("wpr.exe", "-stop", trace, "-instancename", session)
		if err := wpr.Run(); err != nil {
			return err
		}

		if out == nil {
			return nil
		}

		netsh := exec.Command("netsh.exe", "trace", "convert", trace)
		if err := netsh.Run(); err != nil {
			return err
		}

		f, err := os.Open(filepath.Join(path, "trace.txt"))
		if err != nil {
			return err
		}
		defer f.Close()

		r := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Reader(f)
		_, err = io.Copy(os.Stderr, r)
		return err
	}, nil
}
