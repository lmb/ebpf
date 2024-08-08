package link

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
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
	if opts != (RawLinkOptions{}) {
		// TODO: Attach type is a GUID on Windows.
		return nil, errors.New("not supported")
	}

	var link uintptr
	err := efw.CallResult(procProgramAttachByFd, uintptr(opts.Program.FD()), 0, 0, 0, uintptr(unsafe.Pointer(&link)))
	runtime.KeepAlive(opts.Program)
	if err != nil {
		return nil, fmt.Errorf("attach link: %w", err)
	}

	var raw sys.RawFD
	err = efw.CallResult(procLinkFd, link, uintptr(unsafe.Pointer(&raw)))
	if err != nil {
		return nil, fmt.Errorf("link fd: %w", err)
	}

	fd, err := sys.NewFD(int(raw))
	if err != nil {
		return nil, err
	}

	return &RawLink{fd: fd}, nil
}

func wrapRawLink(raw *RawLink) (Link, error) {
	return raw, nil
}
