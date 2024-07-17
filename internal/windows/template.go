//go:build ignore

package windows

// This file is used as a template to feed into cgo -godefs, which ends up
// generating Go equivalents of the necessary C types.

/*
#include <stdint.h>
#include "ebpf_protocol.h"
*/
import "C"

// Kernel handlers are in https://github.com/microsoft/ebpf-for-windows/blob/main/libs/execution_context/ebpf_core.c#L2601
const (
	OPERATION_RESOLVE_HELPER                 OperationID = C.EBPF_OPERATION_RESOLVE_HELPER
	OPERATION_RESOLVE_MAP                    OperationID = C.EBPF_OPERATION_RESOLVE_MAP
	OPERATION_CREATE_PROGRAM                 OperationID = C.EBPF_OPERATION_CREATE_PROGRAM
	OPERATION_CREATE_MAP                     OperationID = C.EBPF_OPERATION_CREATE_MAP
	OPERATION_LOAD_CODE                      OperationID = C.EBPF_OPERATION_LOAD_CODE
	OPERATION_MAP_FIND_ELEMENT               OperationID = C.EBPF_OPERATION_MAP_FIND_ELEMENT
	OPERATION_MAP_UPDATE_ELEMENT             OperationID = C.EBPF_OPERATION_MAP_UPDATE_ELEMENT
	OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE OperationID = C.EBPF_OPERATION_MAP_UPDATE_ELEMENT_WITH_HANDLE
	OPERATION_MAP_DELETE_ELEMENT             OperationID = C.EBPF_OPERATION_MAP_DELETE_ELEMENT
	OPERATION_MAP_GET_NEXT_KEY               OperationID = C.EBPF_OPERATION_MAP_GET_NEXT_KEY
	OPERATION_QUERY_PROGRAM_INFO             OperationID = C.EBPF_OPERATION_QUERY_PROGRAM_INFO
	OPERATION_UPDATE_PINNING                 OperationID = C.EBPF_OPERATION_UPDATE_PINNING
	OPERATION_GET_PINNED_OBJECT              OperationID = C.EBPF_OPERATION_GET_PINNED_OBJECT
	OPERATION_LINK_PROGRAM                   OperationID = C.EBPF_OPERATION_LINK_PROGRAM
	OPERATION_UNLINK_PROGRAM                 OperationID = C.EBPF_OPERATION_UNLINK_PROGRAM
	OPERATION_CLOSE_HANDLE                   OperationID = C.EBPF_OPERATION_CLOSE_HANDLE
	OPERATION_GET_EC_FUNCTION                OperationID = C.EBPF_OPERATION_GET_EC_FUNCTION
	OPERATION_GET_PROGRAM_INFO               OperationID = C.EBPF_OPERATION_GET_PROGRAM_INFO
	OPERATION_GET_PINNED_MAP_INFO            OperationID = C.EBPF_OPERATION_GET_PINNED_MAP_INFO
	OPERATION_GET_LINK_HANDLE_BY_ID          OperationID = C.EBPF_OPERATION_GET_LINK_HANDLE_BY_ID
	OPERATION_GET_MAP_HANDLE_BY_ID           OperationID = C.EBPF_OPERATION_GET_MAP_HANDLE_BY_ID
	OPERATION_GET_PROGRAM_HANDLE_BY_ID       OperationID = C.EBPF_OPERATION_GET_PROGRAM_HANDLE_BY_ID
	OPERATION_GET_NEXT_LINK_ID               OperationID = C.EBPF_OPERATION_GET_NEXT_LINK_ID
	OPERATION_GET_NEXT_MAP_ID                OperationID = C.EBPF_OPERATION_GET_NEXT_MAP_ID
	OPERATION_GET_NEXT_PROGRAM_ID            OperationID = C.EBPF_OPERATION_GET_NEXT_PROGRAM_ID
	OPERATION_GET_OBJECT_INFO                OperationID = C.EBPF_OPERATION_GET_OBJECT_INFO
	OPERATION_GET_NEXT_PINNED_PROGRAM_PATH   OperationID = C.EBPF_OPERATION_GET_NEXT_PINNED_PROGRAM_PATH
	OPERATION_BIND_MAP                       OperationID = C.EBPF_OPERATION_BIND_MAP
	OPERATION_RING_BUFFER_MAP_QUERY_BUFFER   OperationID = C.EBPF_OPERATION_RING_BUFFER_MAP_QUERY_BUFFER
	OPERATION_RING_BUFFER_MAP_ASYNC_QUERY    OperationID = C.EBPF_OPERATION_RING_BUFFER_MAP_ASYNC_QUERY
	OPERATION_LOAD_NATIVE_MODULE             OperationID = C.EBPF_OPERATION_LOAD_NATIVE_MODULE
	OPERATION_LOAD_NATIVE_PROGRAMS           OperationID = C.EBPF_OPERATION_LOAD_NATIVE_PROGRAMS
	OPERATION_PROGRAM_TEST_RUN               OperationID = C.EBPF_OPERATION_PROGRAM_TEST_RUN
	OPERATION_MAP_UPDATE_ELEMENT_BATCH       OperationID = C.EBPF_OPERATION_MAP_UPDATE_ELEMENT_BATCH
	OPERATION_MAP_DELETE_ELEMENT_BATCH       OperationID = C.EBPF_OPERATION_MAP_DELETE_ELEMENT_BATCH
	OPERATION_MAP_GET_NEXT_KEY_VALUE_BATCH   OperationID = C.EBPF_OPERATION_MAP_GET_NEXT_KEY_VALUE_BATCH
)

// +godefs map struct_my_guid GUID

type OperationID C.ebpf_operation_id_t

type OperationHeader C.ebpf_operation_header_t

type MapDefinition C.ebpf_map_definition_in_memory_t

type CreateMapRequest C.ebpf_operation_create_map_request_t

type CreateMapReply C.ebpf_operation_create_map_reply_t

type MapFindElementRequest C.ebpf_operation_map_find_element_request_t

type MapFindElementReply C.ebpf_operation_map_find_element_reply_t

type MapUpdateElementRequest C.ebpf_operation_map_update_element_request_t

type MapUpdateElementWithHandleRequest C.ebpf_operation_map_update_element_with_handle_request_t

type MapDeleteElementRequest C.ebpf_operation_map_delete_element_request_t

type MapGetNextKeyRequest C.ebpf_operation_map_get_next_key_request_t

type MapGetNextKeyReply C.ebpf_operation_map_get_next_key_reply_t

type UpdatePinningRequest C.ebpf_operation_update_pinning_request_t

type GetPinnedObjectRequest C.ebpf_operation_get_pinned_object_request_t

type GetPinnedObjectReply C.ebpf_operation_get_pinned_object_reply_t

type LinkProgramRequest C.ebpf_operation_link_program_request_t

type LinkProgramReply C.ebpf_operation_link_program_reply_t

type GetHandleByIdRequest C.ebpf_operation_get_handle_by_id_request_t

type GetHandleByIdReply C.ebpf_operation_get_handle_by_id_reply_t

type LoadNativeModuleRequest C.ebpf_operation_load_native_module_request_t

type LoadNativeModuleReply C.ebpf_operation_load_native_module_reply_t

type LoadNativeProgramsRequest C.ebpf_operation_load_native_programs_request_t

type LoadNativeProgramsReply C.ebpf_operation_load_native_programs_reply_t

type GetObjectInfoRequest C.ebpf_operation_get_object_info_request_t

type GetObjectInfoReply C.ebpf_operation_get_object_info_reply_t

type GetNextIdRequest C.ebpf_operation_get_next_id_request_t

type GetNextIdReply C.ebpf_operation_get_next_id_reply_t

type BindMapRequest C.ebpf_operation_bind_map_request_t

type ProgramTestRunRequest C.ebpf_operation_program_test_run_request_t

type ProgramTestRunReply C.ebpf_operation_program_test_run_reply_t

type MapInfo C.struct_bpf_map_info

type ProgramInfo C.struct_bpf_prog_info
