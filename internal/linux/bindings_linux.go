// Code generated by internal/cmd/gentypes; DO NOT EDIT.

//go:build linux

package linux

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

func BtfGetFdById(attr *BtfGetFdByIdAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_BTF_GET_FD_BY_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func BtfGetNextId(attr *BtfGetNextIdAttr) error {
	_, err := BPF(BPF_BTF_GET_NEXT_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func BtfLoad(attr *BtfLoadAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_BTF_LOAD, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func EnableStats(attr *EnableStatsAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_ENABLE_STATS, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func IterCreate(attr *IterCreateAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_ITER_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreate(attr *LinkCreateAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateIter(attr *LinkCreateIterAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateKprobeMulti(attr *LinkCreateKprobeMultiAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateNetfilter(attr *LinkCreateNetfilterAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateNetkit(attr *LinkCreateNetkitAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreatePerfEvent(attr *LinkCreatePerfEventAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateTcx(attr *LinkCreateTcxAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateTracing(attr *LinkCreateTracingAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkCreateUprobeMulti(attr *LinkCreateUprobeMultiAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkGetFdById(attr *LinkGetFdByIdAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_LINK_GET_FD_BY_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func LinkGetNextId(attr *LinkGetNextIdAttr) error {
	_, err := BPF(BPF_LINK_GET_NEXT_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func LinkUpdate(attr *LinkUpdateAttr) error {
	_, err := BPF(BPF_LINK_UPDATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapCreate(attr *MapCreateAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_MAP_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func MapDeleteBatch(attr *MapDeleteBatchAttr) error {
	_, err := BPF(BPF_MAP_DELETE_BATCH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapDeleteElem(attr *MapDeleteElemAttr) error {
	_, err := BPF(BPF_MAP_DELETE_ELEM, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapFreeze(attr *MapFreezeAttr) error {
	_, err := BPF(BPF_MAP_FREEZE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapGetFdById(attr *MapGetFdByIdAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_MAP_GET_FD_BY_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func MapGetNextId(attr *MapGetNextIdAttr) error {
	_, err := BPF(BPF_MAP_GET_NEXT_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapGetNextKey(attr *MapGetNextKeyAttr) error {
	_, err := BPF(BPF_MAP_GET_NEXT_KEY, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapLookupAndDeleteBatch(attr *MapLookupAndDeleteBatchAttr) error {
	_, err := BPF(BPF_MAP_LOOKUP_AND_DELETE_BATCH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapLookupAndDeleteElem(attr *MapLookupAndDeleteElemAttr) error {
	_, err := BPF(BPF_MAP_LOOKUP_AND_DELETE_ELEM, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapLookupBatch(attr *MapLookupBatchAttr) error {
	_, err := BPF(BPF_MAP_LOOKUP_BATCH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapLookupElem(attr *MapLookupElemAttr) error {
	_, err := BPF(BPF_MAP_LOOKUP_ELEM, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapUpdateBatch(attr *MapUpdateBatchAttr) error {
	_, err := BPF(BPF_MAP_UPDATE_BATCH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func MapUpdateElem(attr *MapUpdateElemAttr) error {
	_, err := BPF(BPF_MAP_UPDATE_ELEM, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ObjGet(attr *ObjGetAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_OBJ_GET, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func ObjGetInfoByFd(attr *ObjGetInfoByFdAttr) error {
	_, err := BPF(BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ObjPin(attr *ObjPinAttr) error {
	_, err := BPF(BPF_OBJ_PIN, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgAttach(attr *ProgAttachAttr) error {
	_, err := BPF(BPF_PROG_ATTACH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgBindMap(attr *ProgBindMapAttr) error {
	_, err := BPF(BPF_PROG_BIND_MAP, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgDetach(attr *ProgDetachAttr) error {
	_, err := BPF(BPF_PROG_DETACH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgGetFdById(attr *ProgGetFdByIdAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_PROG_GET_FD_BY_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func ProgGetNextId(attr *ProgGetNextIdAttr) error {
	_, err := BPF(BPF_PROG_GET_NEXT_ID, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgLoad(attr *ProgLoadAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_PROG_LOAD, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}

func ProgQuery(attr *ProgQueryAttr) error {
	_, err := BPF(BPF_PROG_QUERY, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgRun(attr *ProgRunAttr) error {
	_, err := BPF(BPF_PROG_TEST_RUN, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func RawTracepointOpen(attr *RawTracepointOpenAttr) (*sys.FD, error) {
	fd, err := BPF(BPF_RAW_TRACEPOINT_OPEN, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return sys.NewFD(int(fd))
}
