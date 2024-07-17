//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:generate go run github.com/cilium/ebpf/internal/cmd/godefs bindings.go -- -Iinclude template.go

type GUID = windows.GUID

func CreateMap(name string, innerMap windows.Handle, def *MapDefinition) (windows.Handle, error) {
	req := CreateMapRequest{
		Header:              header(OPERATION_CREATE_MAP),
		Ebpf_map_definition: *def,
		Inner_map_handle:    int64(innerMap),
	}

	var buf []byte
	buf = append(buf, unsafeBytes(&req)...)
	buf, err := appendString(buf, name)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("name: %w", err)
	}

	var rep CreateMapReply
	if err := ioctl(buf, unsafeBytes(&rep)); err != nil {
		return windows.InvalidHandle, fmt.Errorf("create map: %w", err)
	}

	return windows.Handle(rep.Handle), nil
}

var errMapLookupNotFound = fmt.Errorf("map lookup: %w", windows.ERROR_PATH_NOT_FOUND)

func MapFindElement(m windows.Handle, key, value []byte, delete bool) error {
	req := MapFindElementRequest{
		Header:     header(OPERATION_MAP_FIND_ELEMENT),
		Handle:     int64(m),
		And_delete: delete,
	}

	in := make([]byte, 0, unsafe.Sizeof(req)+uintptr(len(key)))
	in = append(in, unsafeBytes(&req, unsafe.Sizeof(req.Pad_cgo_0))...)
	in = append(in, key...)

	var rep MapFindElementReply
	out := make([]byte, unsafe.Sizeof(rep)+uintptr(len(value)))

	if err := ioctl(in, out); err == windows.ERROR_PATH_NOT_FOUND {
		return errMapLookupNotFound
	} else if err != nil {
		return fmt.Errorf("map find: %w", err)
	}

	out = out[unsafe.Sizeof(rep):]
	out = lop(out, value)

	if len(out) != 0 {
		return fmt.Errorf("unexpected %d byte tail", len(out))
	}

	return nil
}

func MapUpdateElement(m windows.Handle, key, value []byte, flags uint32) error {
	req := MapUpdateElementRequest{
		Header: header(OPERATION_MAP_UPDATE_ELEMENT),
		Handle: int64(m),
		Option: flags,
	}

	buf := make([]byte, 0, unsafe.Sizeof(req)+uintptr(len(key)+len(value)))
	buf = append(buf, unsafeBytes(&req, unsafe.Sizeof(req.Pad_cgo_0))...)
	buf = append(buf, key...)
	buf = append(buf, value...)

	if err := ioctl(buf, nil); err != nil {
		return fmt.Errorf("map update: %w", err)
	}

	return nil
}

func MapUpdateElementWithHandle(m windows.Handle, key []byte, value windows.Handle, flags uint32) error {
	req := MapUpdateElementWithHandleRequest{
		Header:       header(OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE),
		Map_handle:   int64(m),
		Value_handle: int64(value),
		Option:       flags,
	}

	buf := make([]byte, 0, unsafe.Sizeof(req)+uintptr(len(key)))
	buf = append(buf, unsafeBytes(&req, unsafe.Sizeof(req.Pad_cgo_0))...)
	buf = append(buf, key...)

	if err := ioctl(buf, nil); err != nil {
		return fmt.Errorf("map update with handle: %w", err)
	}

	return nil
}

var errMapDeleteNotFound = fmt.Errorf("map delete: %w", windows.ERROR_NOT_FOUND)

func MapDeleteElement(m windows.Handle, key []byte) error {
	req := MapDeleteElementRequest{
		Header: header(OPERATION_MAP_DELETE_ELEMENT),
		Handle: int64(m),
	}

	in := make([]byte, 0, unsafe.Sizeof(req)+uintptr(len(key)))
	in = append(in, unsafeBytes(&req)...)
	in = append(in, key...)

	if err := ioctl(in, nil); err == windows.ERROR_NOT_FOUND {
		return errMapDeleteNotFound
	} else if err != nil {
		return fmt.Errorf("map delete: %w", err)
	}

	return nil
}

func MapGetNeyKey(m windows.Handle, prevKey, key []byte) error {
	req := MapGetNextKeyRequest{
		Header: header(OPERATION_MAP_GET_NEXT_KEY),
		Handle: int64(m),
	}

	in := make([]byte, 0, unsafe.Sizeof(req)+uintptr(len(prevKey)))
	in = append(in, unsafeBytes(&req)...)
	// TODO: We don't make a difference between nil and zero length here.
	in = append(in, prevKey...)

	var rep MapGetNextKeyReply
	out := make([]byte, unsafe.Sizeof(rep)+uintptr(len(key)))

	if err := ioctl(in, out); err != nil {
		return fmt.Errorf("map next key: %w", err)
	}

	out = lop(out, unsafeBytes(&rep))
	out = lop(out, key)

	if len(out) != 0 {
		return fmt.Errorf("unexpected %d byte tail", len(out))
	}

	return nil
}

func BindMap(program, m windows.Handle) error {
	req := BindMapRequest{
		Header:         header(OPERATION_BIND_MAP),
		Program_handle: int64(program),
		Map_handle:     int64(m),
	}

	if err := ioctl(unsafeBytes(&req), nil); err != nil {
		return fmt.Errorf("bind map: %w", err)
	}

	return nil
}

func UpdatePinning(h windows.Handle, path string) error {
	req := UpdatePinningRequest{
		Header: header(OPERATION_UPDATE_PINNING),
		Handle: int64(h),
	}

	var in []byte
	in = append(in, unsafeBytes(&req)...)
	in = append(in, []byte(path)...)

	if err := ioctl(in, nil); err != nil {
		return fmt.Errorf("update pinning: %w", err)
	}

	return nil
}

func GetPinnedObject(path string) (windows.Handle, error) {
	req := GetPinnedObjectRequest{
		Header: header(OPERATION_GET_PINNED_OBJECT),
	}

	var in []byte
	in = append(in, unsafeBytes(&req)...)
	in = append(in, path...)

	var res GetPinnedObjectReply
	if err := ioctl(in, unsafeBytes(&res)); err != nil {
		return windows.InvalidHandle, fmt.Errorf("get pinned object: %w", err)
	}

	return windows.Handle(res.Handle), nil
}

func LinkProgram(program windows.Handle, attachType windows.GUID, params []byte) (windows.Handle, error) {
	req := LinkProgramRequest{
		Header:         header(OPERATION_LINK_PROGRAM),
		Program_handle: int64(program),
		Attach_type:    attachType,
	}

	var in []byte
	in = append(in, unsafeBytes(&req)...)
	in = append(in, params...)

	var res LinkProgramReply
	if err := ioctl(in, unsafeBytes(&res)); err != nil {
		return windows.InvalidHandle, fmt.Errorf("link program: %w", err)
	}

	return windows.Handle(res.Handle), nil
}

func GetMapHandleById(id uint32) (windows.Handle, error) {
	return getHandleById(OPERATION_GET_MAP_HANDLE_BY_ID, id)
}

func GetProgramHandleById(id uint32) (windows.Handle, error) {
	return getHandleById(OPERATION_GET_PROGRAM_HANDLE_BY_ID, id)
}

func GetLinkHandleById(id uint32) (windows.Handle, error) {
	return getHandleById(OPERATION_GET_LINK_HANDLE_BY_ID, id)
}

func getHandleById(op OperationID, id uint32) (windows.Handle, error) {
	req := GetHandleByIdRequest{
		Header: header(op),
		Id:     id,
	}

	var res GetHandleByIdReply
	if err := ioctl(unsafeBytes(&req), unsafeBytes(&res)); err != nil {
		return windows.InvalidHandle, fmt.Errorf("get handle by id: %w", err)
	}

	return windows.Handle(res.Handle), nil
}

func GetObjectInfo[T any](handle windows.Handle, info *T) error {
	req := GetObjectInfoRequest{
		Header: header(OPERATION_GET_OBJECT_INFO),
		Handle: int64(handle),
	}

	var rep GetObjectInfoReply
	buf := make([]byte, unsafe.Sizeof(rep)+unsafe.Sizeof(*info))
	if err := ioctl(unsafeBytes(&req), buf); err != nil {
		return fmt.Errorf("get object info: %w", err)
	}

	buf = lop(buf, unsafeBytes(&rep))
	buf = lop(buf, unsafeBytes(info))

	if len(buf) != 0 {
		return fmt.Errorf("unexpected %d byte tail", len(buf))
	}

	return nil
}

func GetNextMapId(id uint32) (uint32, error) {
	return getNextId(OPERATION_GET_NEXT_MAP_ID, id)
}

func GetNextProgramId(id uint32) (uint32, error) {
	return getNextId(OPERATION_GET_NEXT_PROGRAM_ID, id)
}

func GetNextLinkId(id uint32) (uint32, error) {
	return getNextId(OPERATION_GET_NEXT_LINK_ID, id)
}

func getNextId(op OperationID, id uint32) (uint32, error) {
	req := GetNextIdRequest{
		Header: header(op),
		Id:     id,
	}

	var res GetNextIdReply
	if err := ioctl(unsafeBytes(&req), unsafeBytes(&res)); err != nil {
		return 0, fmt.Errorf("get next id: %w", err)
	}

	return res.Id, nil
}

// TODO: Should dataIn, dataOut be single buffer with different cap?
// TODO: Untested.
func ProgramTestRun(program windows.Handle, repeat uint64, flags, cpu uint32, batchSize uint64, dataIn, dataOut, ctxIn, ctxOut []byte) (ret uint64, duration time.Duration, dataOutRet, ctxOutRet []byte, _ error) {
	req := ProgramTestRunRequest{
		Header:         header(OPERATION_PROGRAM_TEST_RUN),
		Program_handle: int64(program),
		Repeat_count:   repeat,
		Flags:          flags,
		Cpu:            cpu,
		Batch_size:     batchSize,
	}

	if len(dataIn) > math.MaxUint16 {
		return 0, 0, nil, nil, fmt.Errorf("program run: data length exceeds uint16")
	}
	req.Context_offset = uint16(len(dataIn))

	var in []byte
	in = append(in, unsafeBytes(&req, unsafe.Sizeof(req.Pad_cgo_0))...)
	in = append(in, dataIn...)
	in = append(in, ctxIn...)

	var rep ProgramTestRunReply
	out := make([]byte, unsafe.Sizeof(rep)+uintptr(len(dataOut)+len(ctxOut)))

	if err := ioctl(in, out); err != nil {
		return 0, 0, nil, nil, fmt.Errorf("program run: %w", err)
	}

	out = lop(out, unsafeBytes(&rep))

	// TODO: This is a weird way of encoding things.
	dataOutLen := rep.Context_offset
	if dataOutLen > uint64(len(dataOut)) {
		return 0, 0, nil, nil, fmt.Errorf("program run: output data length %d exceeds buffer size %d", dataOutLen, len(dataOut))
	}
	dataOut = dataOut[dataOutLen:]
	out = lop(out, dataOut)

	if len(out) > len(ctxOut) {
		return 0, 0, nil, nil, fmt.Errorf("program run: output context length %d exceeds buffer size %d", len(out), len(ctxOut))
	}
	ctxOut = ctxOut[len(out):]
	out = lop(out, ctxOut)

	if len(out) != 0 {
		return 0, 0, nil, nil, fmt.Errorf("unexpected %d byte tail", len(out))
	}

	// TODO: ms? uint64?
	// TODO:
	return rep.Return_value, time.Duration(rep.Duration), dataOut, ctxOut, nil
}

var deviceHandle = sync.OnceValues(func() (windows.Handle, error) {
	name := windows.StringToUTF16Ptr(_EBPF_DEVICE_WIN32_NAME)
	return windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_ALWAYS, 0, 0)
})

func header(op OperationID) OperationHeader {
	return OperationHeader{Id: uint32(op)}
}

// lop off the first len(dst) bytes from src.
//
// Copies the lopped bytes into dst.
func lop(src, dst []byte) []byte {
	return src[copy(dst, src):]
}

// in must start with OperationHeader. The buffer is modified so that
// OperationHeader.Length is equal to len(in).
//
// out must be large enough to contain the response, and may be nil.
func ioctl(in, out []byte) error {
	// Problems with the syscall bindings:
	// - Padding is handled inconsistently. Interior padding is ignored / set to
	//   zero. Trailing padding is truncated and must not be passed to the syscall.
	// - Strings are handled inconsistently. Map creation expects null termination,
	//   other things do not allow null termination.
	// - Some variable fields have their length encoded as offsets which is
	//   cumbersome.

	if len(in) < int(unsafe.Sizeof(OperationHeader{})) {
		return fmt.Errorf("ioctl: request is too short")
	} else if len(in) > math.MaxUint16 {
		return fmt.Errorf("request size exceeds uint16")
	}

	// Update length in the header.
	hdr := OperationHeader{Length: uint16(len(in))}
	binary.NativeEndian.PutUint16(in[unsafe.Offsetof(hdr.Length):], hdr.Length)

	h, err := deviceHandle()
	if err != nil {
		return fmt.Errorf("get device handle: %w", err)
	}

	var outp *byte
	if out != nil {
		outp = &out[0]
	}

	outLen := uint32(len(out))
	var replySize uint32
	err = windows.DeviceIoControl(h, _IOCTL_EBPF_CTL_METHOD_BUFFERED, &in[0], uint32(len(in)), outp, outLen, &replySize, nil)
	if err != nil {
		// Do not wrap to avoid allocation on the hot path.
		// TODO: Add a test.
		return err
	}

	if replySize != outLen {
		return fmt.Errorf("ioctl: unexpected reply size (%d != %d)", replySize, len(out))
	}

	return nil
}

func unsafeBytes[T any](t *T, paddings ...uintptr) []byte {
	size := unsafe.Sizeof(*t)
	for _, padding := range paddings {
		size -= padding
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(t)), size)
}

func unsafeSliceBytes[T any](s []T) []byte {
	if len(s) == 0 {
		return nil
	}

	size := len(s) * int(unsafe.Sizeof(s[0]))
	return unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), size)
}

func appendString(buf []byte, s string) ([]byte, error) {
	if strings.ContainsRune(s, 0) {
		return nil, fmt.Errorf("string %q contains NUL byte", s)
	}

	buf = slices.Grow(buf, len(s)+1)
	buf = append(buf, s...)
	buf = append(buf, 0)
	return buf, nil
}
