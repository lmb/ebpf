package linux

// Types in this file are references by gentypes and must therefore be available
// on all platforms.

import "github.com/cilium/ebpf/internal/unix"

// BPFObjName is a null-terminated string made up of
// 'A-Za-z0-9_' characters.
type ObjName [unix.BPF_OBJ_NAME_LEN]byte

// NewObjName truncates the result if it is too long.
func NewObjName(name string) ObjName {
	var result ObjName
	copy(result[:unix.BPF_OBJ_NAME_LEN-1], name)
	return result
}

// LogLevel controls the verbosity of the kernel's eBPF program verifier.
type LogLevel uint32

const (
	BPF_LOG_LEVEL1 LogLevel = 1 << iota
	BPF_LOG_LEVEL2
	BPF_LOG_STATS
)

// LinkID uniquely identifies a bpf_link.
type LinkID uint32

// BTFID uniquely identifies a BTF blob loaded into the kernel.
type BTFID uint32

// TypeID identifies a type in a BTF blob.
type TypeID uint32

// MapFlags control map behaviour.
type MapFlags uint32

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type MapFlags

const (
	BPF_F_NO_PREALLOC MapFlags = 1 << iota
	BPF_F_NO_COMMON_LRU
	BPF_F_NUMA_NODE
	BPF_F_RDONLY
	BPF_F_WRONLY
	BPF_F_STACK_BUILD_ID
	BPF_F_ZERO_SEED
	BPF_F_RDONLY_PROG
	BPF_F_WRONLY_PROG
	BPF_F_CLONE
	BPF_F_MMAPABLE
	BPF_F_PRESERVE_ELEMS
	BPF_F_INNER_MAP
	BPF_F_LINK
	BPF_F_PATH_FD
)

// Flags used by bpf_mprog.
const (
	BPF_F_REPLACE = 1 << (iota + 2)
	BPF_F_BEFORE
	BPF_F_AFTER
	BPF_F_ID
	BPF_F_LINK_MPROG = 1 << 13 // aka BPF_F_LINK
)
