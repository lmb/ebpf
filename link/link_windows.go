package link

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
)

// ebpf_result_t ebpf_program_attach_by_fd(
// fd_t program_fd,
// _In_opt_ const ebpf_attach_type_t* attach_type,
// _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
// size_t attach_parameters_size,
// _Outptr_ struct bpf_link** link)
var procProgramAttachByFd = efw.Module.NewProc("ebpf_program_attach_by_fd")

// void ebpf_link_fd(_Frees_ptr_ struct bpf_link* link, _Out_ fd_t* fd)
var procLinkFd = efw.Module.NewProc("ebpf_link_fd")

func AttachRawLink(opts RawLinkOptions) (*RawLink, error) {
	if opts.Attach != 0 {
		// TODO: Attach type is a GUID on Windows.
		return nil, errors.New("not supported")
	}

	if err := efw.FindProcs(procProgramAttachByFd, procLinkFd); err != nil {
		return nil, err
	}

	if err := procProgramAttachByFd.Find(); err != nil {
		return nil, fmt.Errorf("%s: %w", err)
	}

	if err := procLinkFd.Find(); err != nil {
		return nil, fmt.Errorf("ebpf_program_attach_by_fd: %w", err)

	}

	var link uintptr
	ret, _, _ := procProgramAttachByFd.Call(uintptr(opts.Program.FD()), 0, 0, 0, uintptr(unsafe.Pointer(&link)))
	err := efw.ResultToError(efw.Result(ret))
	if err != nil {
		return nil, fmt.Errorf("attach link: %w", err)
	}
}

func wrapRawLink(raw *RawLink) (Link, error) {
	return raw, nil
}
