#pragma once

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

typedef struct __attribute__((__packed__))  _list_entry {
    uint32_t entry_length;
    char data[];
} list_entry;


TEE_Result store_data(char* key, size_t key_size, char* value, size_t value_size, uint32_t flags, uint32_t meta_permissions);
TEE_Result store_transient_object(char* key, size_t key_size, TEE_ObjectHandle transient, uint32_t flags, uint32_t meta_permissions);
TEE_Result fetch_transient_object(TEE_ObjectHandle targetObject, char* key, size_t key_size, uint32_t meta_permissions);
TEE_Result update_data(char* key, size_t key_size, char* value, size_t value_size, uint32_t meta_permissions);
TEE_Result delete_data(char* key, size_t key_size, uint32_t meta_permissions);
int32_t fetch_data(char* key, uint32_t key_size, char* buffer, uint32_t buf_size, uint32_t *read_bytes_ptr, uint32_t meta_permissions);
int32_t fetch_data_allocate(char* key, uint32_t key_size, char** buffer, uint32_t* buf_size, uint32_t meta_permissions);
uint32_t fetch_all_data(list_entry** data_ptr_out, uint32_t* buffer_size_out, uint32_t required_permissions);


static void print_TEE_ret(int32_t ret) {
    // https://github.com/OP-TEE/optee_os/blob/master/lib/libutee/include/tee_api_defines.h#L99
    switch (ret) {
    case TEE_SUCCESS:               InfoMSG("   > res=0x%08x (TEE_SUCCESS)",              ret); break;
    case TEE_ERROR_NOT_SUPPORTED:   ErrorMSG("  > res=0x%08x (TEE_ERROR_NOT_SUPPORTED)",  ret); break;
    case TEE_ERROR_ITEM_NOT_FOUND:  ErrorMSG("  > res=0x%08x (TEE_ERROR_ITEM_NOT_FOUND: data key not in ADP store)", ret); break;
    case TEE_ERROR_SHORT_BUFFER:    ErrorMSG("  > res=0x%08x (TEE_ERROR_SHORT_BUFFER: try again with larger buffer)",   ret); break;
    case TEE_ERROR_ACCESS_CONFLICT: ErrorMSG("  > res=0x%08x (TEE_ERROR_ACCESS_CONFLICT: data key already exists, use update instead or delete first)",   ret); break;
    default: ErrorMSG("other ERROR: 0x%08x", ret);
    }
    
}
