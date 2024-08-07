package link

import (
	"fmt"

	"github.com/cilium/ebpf/internal/sys"
)

// Valid link types.
const (
	UnspecifiedType   = sys.BPF_LINK_TYPE_UNSPEC
	RawTracepointType = sys.BPF_LINK_TYPE_RAW_TRACEPOINT
	TracingType       = sys.BPF_LINK_TYPE_TRACING
	CgroupType        = sys.BPF_LINK_TYPE_CGROUP
	IterType          = sys.BPF_LINK_TYPE_ITER
	NetNsType         = sys.BPF_LINK_TYPE_NETNS
	XDPType           = sys.BPF_LINK_TYPE_XDP
	PerfEventType     = sys.BPF_LINK_TYPE_PERF_EVENT
	KprobeMultiType   = sys.BPF_LINK_TYPE_KPROBE_MULTI
	TCXType           = sys.BPF_LINK_TYPE_TCX
	UprobeMultiType   = sys.BPF_LINK_TYPE_UPROBE_MULTI
	NetfilterType     = sys.BPF_LINK_TYPE_NETFILTER
	NetkitType        = sys.BPF_LINK_TYPE_NETKIT
)

// NewLinkFromFD creates a link from a raw fd.
//
// Deprecated: use [NewFromFD] instead.
func NewLinkFromFD(fd int) (Link, error) {
	return NewFromFD(fd)
}

// NewFromFD creates a link from a raw fd.
//
// You should not use fd after calling this function.
func NewFromFD(fd int) (Link, error) {
	sysFD, err := sys.NewFD(fd)
	if err != nil {
		return nil, err
	}

	return wrapRawLink(&RawLink{fd: sysFD})
}

// AttachRawLink creates a raw link.
func AttachRawLink(opts RawLinkOptions) (*RawLink, error) {
	if err := haveBPFLink(); err != nil {
		return nil, err
	}

	if opts.Target < 0 {
		return nil, fmt.Errorf("invalid target: %s", sys.ErrClosedFd)
	}

	progFd := opts.Program.FD()
	if progFd < 0 {
		return nil, fmt.Errorf("invalid program: %s", sys.ErrClosedFd)
	}

	attr := sys.LinkCreateAttr{
		TargetFd:    uint32(opts.Target),
		ProgFd:      uint32(progFd),
		AttachType:  sys.AttachType(opts.Attach),
		TargetBtfId: opts.BTF,
		Flags:       opts.Flags,
	}
	fd, err := sys.LinkCreate(&attr)
	if err != nil {
		return nil, fmt.Errorf("create link: %w", err)
	}

	return &RawLink{fd, ""}, nil
}

// FD returns the raw file descriptor.
func (l *RawLink) FD() int {
	return l.fd.Int()
}

// wrap a RawLink in a more specific type if possible.
//
// The function takes ownership of raw and closes it on error.
func wrapRawLink(raw *RawLink) (_ Link, err error) {
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()

	info, err := raw.Info()
	if err != nil {
		return nil, err
	}

	switch info.Type {
	case RawTracepointType:
		return &rawTracepoint{*raw}, nil
	case TracingType:
		return &tracing{*raw}, nil
	case CgroupType:
		return &linkCgroup{*raw}, nil
	case IterType:
		return &Iter{*raw}, nil
	case NetNsType:
		return &NetNsLink{*raw}, nil
	case KprobeMultiType:
		return &kprobeMultiLink{*raw}, nil
	case UprobeMultiType:
		return &uprobeMultiLink{*raw}, nil
	case PerfEventType:
		return &perfEventLink{*raw, nil}, nil
	case TCXType:
		return &tcxLink{*raw}, nil
	case NetfilterType:
		return &netfilterLink{*raw}, nil
	case NetkitType:
		return &netkitLink{*raw}, nil
	case XDPType:
		return &xdpLink{*raw}, nil
	default:
		return raw, nil
	}
}

type TracingInfo struct {
	AttachType  sys.AttachType
	TargetObjId uint32
	TargetBtfId sys.TypeID
}

type CgroupInfo struct {
	CgroupId   uint64
	AttachType sys.AttachType
	_          [4]byte
}

type NetNsInfo struct {
	NetnsIno   uint32
	AttachType sys.AttachType
}

type TCXInfo struct {
	Ifindex    uint32
	AttachType sys.AttachType
}

type XDPInfo struct {
	Ifindex uint32
}

type NetfilterInfo struct {
	Pf       uint32
	Hooknum  uint32
	Priority int32
	Flags    uint32
}

type NetkitInfo struct {
	Ifindex    uint32
	AttachType sys.AttachType
}

type KprobeMultiInfo struct {
	count  uint32
	flags  uint32
	missed uint64
}

// AddressCount is the number of addresses hooked by the kprobe.
func (kpm *KprobeMultiInfo) AddressCount() (uint32, bool) {
	return kpm.count, kpm.count > 0
}

func (kpm *KprobeMultiInfo) Flags() (uint32, bool) {
	return kpm.flags, kpm.count > 0
}

func (kpm *KprobeMultiInfo) Missed() (uint64, bool) {
	return kpm.missed, kpm.count > 0
}

type PerfEventInfo struct {
	Type  sys.PerfEventType
	extra interface{}
}

func (r *PerfEventInfo) Kprobe() *KprobeInfo {
	e, _ := r.extra.(*KprobeInfo)
	return e
}

type KprobeInfo struct {
	address uint64
	missed  uint64
}

func (kp *KprobeInfo) Address() (uint64, bool) {
	return kp.address, kp.address > 0
}

func (kp *KprobeInfo) Missed() (uint64, bool) {
	return kp.missed, kp.address > 0
}

// Tracing returns tracing type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) Tracing() *TracingInfo {
	e, _ := r.extra.(*TracingInfo)
	return e
}

// Cgroup returns cgroup type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) Cgroup() *CgroupInfo {
	e, _ := r.extra.(*CgroupInfo)
	return e
}

// NetNs returns netns type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) NetNs() *NetNsInfo {
	e, _ := r.extra.(*NetNsInfo)
	return e
}

// XDP returns XDP type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) XDP() *XDPInfo {
	e, _ := r.extra.(*XDPInfo)
	return e
}

// TCX returns TCX type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) TCX() *TCXInfo {
	e, _ := r.extra.(*TCXInfo)
	return e
}

// Netfilter returns netfilter type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) Netfilter() *NetfilterInfo {
	e, _ := r.extra.(*NetfilterInfo)
	return e
}

// Netkit returns netkit type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) Netkit() *NetkitInfo {
	e, _ := r.extra.(*NetkitInfo)
	return e
}

// KprobeMulti returns kprobe-multi type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) KprobeMulti() *KprobeMultiInfo {
	e, _ := r.extra.(*KprobeMultiInfo)
	return e
}

// PerfEvent returns perf-event type-specific link info.
//
// Returns nil if the type-specific link info isn't available.
func (r Info) PerfEvent() *PerfEventInfo {
	e, _ := r.extra.(*PerfEventInfo)
	return e
}
