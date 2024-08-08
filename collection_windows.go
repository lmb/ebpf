package ebpf

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
	"golang.org/x/sys/windows"
)

/*
ebpf_result_t ebpf_program_load_native(

	_In_z_ const char* file_name,
	_Out_ ebpf_handle_t* native_module_handle,
	_Out_ size_t* count_of_maps,
	_Outptr_result_maybenull_ ebpf_handle_t** map_handles,
	_Out_ size_t* count_of_programs,
	_Outptr_result_maybenull_ ebpf_handle_t** program_handles)
*/
var ebpfProgramLoadNative = efw.Module.NewProc("ebpf_program_load_native")

func loadCollectionFromNativeImage(file string) (*Collection, error) {
	fileBytes, err := sys.ByteSliceFromString(file)
	if err != nil {
		return nil, err
	}

	var moduleHandle windows.Handle
	var numMaps, numPrograms efw.Size
	var mapHandles, programHandles efw.Pointer[windows.Handle]
	err = efw.CallResult(ebpfProgramLoadNative,
		uintptr(unsafe.Pointer(&fileBytes[0])),
		uintptr(unsafe.Pointer(&moduleHandle)),
		uintptr(unsafe.Pointer(&numMaps)),
		uintptr(unsafe.Pointer(&mapHandles)),
		uintptr(unsafe.Pointer(&numPrograms)),
		uintptr(unsafe.Pointer(&programHandles)),
	)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(moduleHandle)
	// TODO: Freeing the handles doesn't close them.
	defer mapHandles.Free()
	defer programHandles.Free()

	maps := unsafe.Slice(mapHandles.Cast(), numMaps)
	defer efw.CloseHandles(maps)

	programs := unsafe.Slice(programHandles.Cast(), numPrograms)
	defer efw.CloseHandles(programs)

}
