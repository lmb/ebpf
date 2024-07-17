//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	_SERVICE_PATH_PREFIX    = "\\Registry\\Machine"
	_PARAMETERS_PATH_PREFIX = "System\\CurrentControlSet\\Services"
	_SERVICE_PARAMETERS     = "Parameters"
	_NPI_MODULE_ID          = "NpiModuleId"
	_EBPF_DEVICE_WIN32_NAME = "\\\\.\\EbpfIoDevice"
)

// https://gitlab.winehq.org/wine/wine/-/blob/8070ed27bc4bb8c9c43c20734d340b62b379fcfc/include/winioctl.h
const (
	_FILE_DEVICE_NETWORK = 0x00000012
	_FILE_ANY_ACCESS     = 0
	_METHOD_BUFFERED     = 0
	_EBPF_IOCTL_TYPE     = _FILE_DEVICE_NETWORK
)

// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
const _IOCTL_EBPF_CTL_METHOD_BUFFERED = (_EBPF_IOCTL_TYPE << 16) | (_FILE_ANY_ACCESS << 14) | (0x900 << 2) | _METHOD_BUFFERED

// Derived from _ebpf_program_load_native().
func LoadNativeImage(path string) (maps, programs []windows.Handle, err error) {
	serviceHandle := windows.InvalidHandle
	defer func() {
		if err == nil || serviceHandle == windows.InvalidHandle {
			return
		}

		_ = windows.ControlService(serviceHandle, windows.SERVICE_STOP, nil)
		_ = queryAndDeleteService(serviceHandle)
	}()

	serviceId, err := windows.GenerateGUID()
	if err != nil {
		return nil, nil, fmt.Errorf("generate service id: %w", err)
	}

	moduleId, err := windows.GenerateGUID()
	if err != nil {
		return nil, nil, fmt.Errorf("generate module id: %w", err)
	}

	serviceHandle, err = createService(serviceId.String(), path)
	if err != nil {
		return nil, nil, fmt.Errorf("create service from %q: %w", path, err)
	}

	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, fmt.Sprintf("%s\\%s\\%s", _PARAMETERS_PATH_PREFIX, serviceId.String(), _SERVICE_PARAMETERS), registry.WRITE|registry.READ)
	if err != nil {
		return nil, nil, fmt.Errorf("create registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetBinaryValue(_NPI_MODULE_ID, unsafeBytes(&moduleId)); err != nil {
		return nil, nil, fmt.Errorf("update %q: %q", _NPI_MODULE_ID, err)
	}

	servicePath := fmt.Sprintf("%s\\%s\\%s", _SERVICE_PATH_PREFIX, _PARAMETERS_PATH_PREFIX, serviceId.String())
	moduleHandle, programCount, mapCount, err := loadNativeModule(servicePath, moduleId)
	if err != nil {
		return nil, nil, fmt.Errorf("load %q: %w", servicePath, err)
	}
	defer windows.CloseHandle(moduleHandle)

	programs, maps, err = loadNativePrograms(moduleId, programCount, mapCount)
	if err != nil {
		return nil, nil, fmt.Errorf("load programs for %q: %w", moduleId, err)
	}

	return maps, programs, queryAndDeleteService(serviceHandle)
}

// Derived from _create_service().
func createService(serviceName string, filePath string) (windows.Handle, error) {
	serviceNameW, err := windows.UTF16PtrFromString(serviceName)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("service name: %w", err)
	}

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("open SCM manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	filePathW, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return windows.InvalidHandle, err
	}

	fullPathW := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetFullPathName(filePathW, uint32(len(fullPathW)), &fullPathW[0], nil)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("get full path name: %w", err)
	}

	// n doesn't include the null char if filePathW is large enough,
	// but does include it if the buffer is too small.
	if n >= uint32(len(fullPathW)) {
		return windows.InvalidHandle, fmt.Errorf("full path name exceeds buffer")
	}
	fullPathW = fullPathW[:n+1]

	return windows.CreateService(
		scm,
		serviceNameW,
		serviceNameW,
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START,
		windows.SERVICE_ERROR_NORMAL,
		&fullPathW[0],
		nil,
		nil,
		nil,
		nil,
		nil,
	)
}

func queryAndDeleteService(service windows.Handle) error {
	// From libs/api/ebpf_api.cpp:
	//
	// Workaround: Querying service status hydrates service reference count in SCM.
	// This ensures that when _delete_service() is called, the service is marked
	// pending for delete, and a later call to ZwUnloadDriver() by ebpfcore does not
	// fail. One side effect of this approach still is that the stale service entries
	// in the registry will not be cleaned up till the next reboot.
	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(service, &status); err != nil {
		return fmt.Errorf("query service status: %w", err)
	}

	if err := windows.DeleteService(service); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	return nil
}

// Derived from _load_native_module().
func loadNativeModule(servicePath string, id windows.GUID) (_ windows.Handle, programCount, mapCount uint64, _ error) {
	req := LoadNativeModuleRequest{
		Header: header(OPERATION_LOAD_NATIVE_MODULE),
		Id:     id,
	}

	var buf []byte
	buf = append(buf, unsafeBytes(&req)...)
	buf = append(buf, unsafeSliceBytes(windows.StringToUTF16(servicePath))...)

	var rep LoadNativeModuleReply
	if err := ioctl(buf, unsafeBytes(&rep)); err != nil {
		return windows.InvalidHandle, 0, 0, fmt.Errorf("load native module: %w", err)
	}

	return windows.Handle(rep.Native_module_handle), rep.Count_of_programs, rep.Count_of_maps, nil
}

// Derived from _load_native_programs().
func loadNativePrograms(id windows.GUID, programCount, mapCount uint64) (programs, maps []windows.Handle, _ error) {
	req := LoadNativeProgramsRequest{
		Header: header(OPERATION_LOAD_NATIVE_PROGRAMS),
		Id:     id,
	}

	var rep LoadNativeProgramsReply
	buf := make([]byte, unsafe.Sizeof(rep)+uintptr(programCount+mapCount)*unsafe.Sizeof(windows.InvalidHandle))
	if err := ioctl(unsafeBytes(&req), buf); err != nil {
		return nil, nil, err
	}

	buf = lop(buf, unsafeBytes(&rep))

	maps = make([]windows.Handle, rep.Map_handle_count)
	programs = make([]windows.Handle, rep.Program_handle_count)

	buf = lop(buf, unsafeSliceBytes(maps))
	buf = lop(buf, unsafeSliceBytes(programs))

	if len(buf) != 0 {
		for _, h := range append(maps, programs...) {
			_ = windows.CloseHandle(h)
		}

		return nil, nil, fmt.Errorf("unexpected %d byte tail", len(buf))
	}

	return programs, maps, nil
}
