package ebpf

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

type bpfCgroupStorageKey struct {
	CgroupInodeId uint64
	AttachType    AttachType
	_             [4]byte // Padding
}

func TestCgroupPerCPUStorageMarshaling(t *testing.T) {
	numCPU := MustPossibleCPU()
	if numCPU < 2 {
		t.Skip("Test requires at least two CPUs")
	}
	testutils.SkipOnOldKernel(t, "5.9", "per-CPU CGoup storage with write from user space support")

	cgroup := testutils.CreateCgroup(t)

	arr, err := NewMap(&MapSpec{
		Type:      PerCPUCGroupStorage,
		KeySize:   uint32(unsafe.Sizeof(bpfCgroupStorageKey{})),
		ValueSize: uint32(unsafe.Sizeof(uint64(0))),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		arr.Close()
	})

	prog, err := NewProgram(&ProgramSpec{
		Type:       CGroupSKB,
		AttachType: AttachCGroupInetEgress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, arr.FD()),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnGetLocalStorage.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	progAttachAttrs := sys.ProgAttachAttr{
		TargetFdOrIfindex: uint32(cgroup.Fd()),
		AttachBpfFd:       uint32(prog.FD()),
		AttachType:        uint32(AttachCGroupInetEgress),
		AttachFlags:       0,
		ReplaceBpfFd:      0,
	}
	err = sys.ProgAttach(&progAttachAttrs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		attr := sys.ProgDetachAttr{
			TargetFdOrIfindex: uint32(cgroup.Fd()),
			AttachBpfFd:       uint32(prog.FD()),
			AttachType:        uint32(AttachCGroupInetEgress),
		}
		if err := sys.ProgDetach(&attr); err != nil {
			t.Fatal(err)
		}
	}()

	var mapKey = &bpfCgroupStorageKey{
		CgroupInodeId: testutils.GetCgroupIno(t, cgroup),
		AttachType:    AttachCGroupInetEgress,
	}

	values := []uint64{1, 2}
	if err := arr.Put(mapKey, values); err != nil {
		t.Fatalf("Can't set cgroup %s storage: %s", cgroup.Name(), err)
	}

	var retrieved []uint64
	if err := arr.Lookup(mapKey, &retrieved); err != nil {
		t.Fatalf("Can't retrieve cgroup %s storage: %s", cgroup.Name(), err)
	}

	for i, want := range []uint64{1, 2} {
		if retrieved[i] == 0 {
			t.Errorf("Item %d is 0", i)
		} else if have := retrieved[i]; have != want {
			t.Errorf("PerCPUCGroupStorage map is not correctly unmarshaled, expected %d but got %d", want, have)
		}
	}
}
