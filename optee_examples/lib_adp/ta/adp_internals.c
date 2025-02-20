#include <string.h>
#include "relic.h"
#include <adp1_ta.h>
#include "adp_internals.h"
#include "adp_metadata.h"
#include <assert.h>
#define FILE_META_NAME "files.meta"

uint32_t init_file_metadata(meta_ctx *ctx);
uint32_t save_file_metadata(meta_ctx *ctx);

TEE_Result store_data(char *key, size_t key_size, char *value, size_t value_size, uint32_t flags, uint32_t meta_permissions)
{
    TEE_ObjectHandle object;
    TEE_Result res;
    meta_ctx ctx;

    // Recreating this context for every store makes the restore function a bit slow...
    // Shouldn't really matter though, since it's only ran once

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry != 0)
    {
        // entry already exists
        res = TEE_ERROR_ACCESS_CONFLICT;
        goto end;
    }

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     key, key_size,
                                     flags,
                                     TEE_HANDLE_NULL,
                                     NULL, 0, /* we may not fill it right now */
                                     &object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("TEE_CreatePersistentObject failed 0x%08x", res);

        meta_destroy(&ctx);
        return res;
    }

    res = TEE_WriteObjectData(object, value, value_size);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> TEE_WriteObjectData failed 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object);
    }
    else
    {
        TEE_CloseObject(object);
        meta_insert(&ctx, key, key_size, meta_permissions);
        res = save_file_metadata(&ctx);
    }

end:
    InfoMSG("store_data result:");
    print_TEE_ret(res);
    meta_destroy(&ctx);

    return res;
}

TEE_Result store_transient_object(char *key, size_t key_size, TEE_ObjectHandle transient, uint32_t flags, uint32_t meta_permissions)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    meta_ctx ctx;

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry != 0)
    {
        res = TEE_ERROR_ACCESS_CONFLICT;
        goto end;
    }

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     key, key_size,
                                     0,
                                     transient,
                                     NULL, 0, /* we may not fill it right now */
                                     &object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("TEE_CreatePersistentObject failed 0x%08x", res);
        meta_destroy(&ctx);
        return res;
    }
    if (flags != 0)
    {
        res = TEE_RestrictObjectUsage1(object, flags);
        if (res != TEE_SUCCESS)
        {
            ErrorMSG("TEE_RestrictObjectUsage1 failed 0x%08x", res);
            meta_destroy(&ctx);
            TEE_CloseAndDeletePersistentObject1(object);
            return res;
        }
    }
    meta_insert(&ctx, key, key_size, meta_permissions);
    save_file_metadata(&ctx);
    TEE_CloseObject(object);

end:
    InfoMSG("store_transient_object result:");
    print_TEE_ret(res);
    meta_destroy(&ctx);

    return res;
}

TEE_Result fetch_transient_object(TEE_ObjectHandle targetObject, char *key, size_t key_size, uint32_t wanted_permissions)
{

    uint32_t read_bytes;
    TEE_ObjectHandle object;

    int32_t res = -1;

    meta_ctx ctx;

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry == 0)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        meta_destroy(&ctx);
        return res;
    }

    if ((entry->attributes & wanted_permissions) != wanted_permissions) // Found item has incorrect permissions
    {
        res = TEE_ERROR_ACCESS_CONFLICT;
        meta_destroy(&ctx);
        return res;
    }

    meta_destroy(&ctx);

    /*
     * Check the object exist and can be dumped into output buffer
     * then dump it.
     */
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_READ |
                                       TEE_DATA_FLAG_SHARE_READ,
                                   &object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to open persistent object, res=0x%08x", res);
        print_TEE_ret(res);
        return res;
    }

    res = TEE_CopyObjectAttributes1(targetObject, object);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> CopyObjectAttributes failed with code 0x%08x", res);
        goto exit;
    }

exit:
    InfoMSG("fetch_transient_object result:");
    print_TEE_ret(res);
    TEE_CloseObject(object);
    return res;
}

TEE_Result update_data(char *key, size_t key_size, char *value, size_t value_size, uint32_t wanted_permissions)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    meta_ctx ctx;

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry == 0)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        meta_destroy(&ctx);
        return res;
    }

    if ((entry->attributes & wanted_permissions) != wanted_permissions)
    {
        res = TEE_ERROR_ACCESS_CONFLICT;
        meta_destroy(&ctx);
        return res;
    }
    meta_destroy(&ctx);
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_READ |
                                       TEE_DATA_FLAG_SHARE_READ |
                                       TEE_DATA_FLAG_ACCESS_WRITE, /* we can later write into the object */
                                   &object);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> update_data: Failed to open persistent object, res=0x%08x", res);
        print_TEE_ret(res);
        return res;
    }

    res = TEE_WriteObjectData(object, value, value_size);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> update_data: TEE_WriteObjectData failed 0x%08x", res);
        print_TEE_ret(res);
        TEE_CloseObject(object); // Don't wanna delete the data here
        return res;
    }


    res = TEE_TruncateObjectData(object, value_size);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("update_data: Truncating failed");
        print_TEE_ret(res);
        return res;
    }

    TEE_CloseObject(object);

    InfoMSG("update_data result: TEE_SUCCESS");
    return TEE_SUCCESS;
}

uint32_t fetch_data_internal(char *key, uint32_t key_size, char **buf_ptr, uint32_t *buf_size)
{
    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    int32_t ret;
    char * tmp_buf;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_READ,
                                   &object);

    if (ret != TEE_SUCCESS)
        return ret;

    ret = TEE_GetObjectInfo1(object, &object_info);
    if (ret != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to get object info, res=0x%08x", ret);
        print_TEE_ret(ret);
        goto exit;
    }
    size_t data_sz = object_info.dataSize;
    *buf_ptr = TEE_Malloc(data_sz, 0);
    tmp_buf = TEE_Malloc(data_sz, 0);
    InfoMSG("Nuestro querido buff tiene un tamaño de: %d", object_info.dataSize);
    InfoMSG("Y este si que me deja tocarlo! 0x%x", (tmp_buf)[0]);
    if (*buf_ptr == 0)
    {
        ret = TEE_ERROR_OUT_OF_MEMORY;
        print_TEE_ret(ret);
        goto exit;
    }

    tmp_buf = TEE_Malloc(object_info.dataSize, 0);
    ret = TEE_ReadObjectData(object, tmp_buf, object_info.dataSize, buf_size);
    *buf_ptr = TEE_Malloc(data_sz, 0);
    if (ret != TEE_SUCCESS || *buf_size != object_info.dataSize)
    {
        ErrorMSG("> Failed to read object data, res=0x%08x", ret);
        print_TEE_ret(ret);
        TEE_Free(*buf_ptr);
    }
    TEE_MemMove(*buf_ptr, tmp_buf, object_info.dataSize);

exit:
    TEE_CloseObject(object);
    return ret;
}

uint32_t init_file_metadata(meta_ctx *ctx)
{
    char *data;
    uint32_t buf_size;
    uint32_t ret;

    ret = fetch_data_internal(FILE_META_NAME, strlen(FILE_META_NAME), &data, &buf_size);
    if (ret != TEE_SUCCESS && ret != TEE_ERROR_ITEM_NOT_FOUND)
        return ret;

    if (ret == TEE_SUCCESS)
    {
        meta_init(ctx, data, buf_size);
    }
    else
    {
        InfoMSG("creating new metadata structure");
        meta_init(ctx, 0, 0);
    }

    return ret;
}

uint32_t save_file_metadata(meta_ctx *ctx)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
                                     FILE_META_NAME, strlen(FILE_META_NAME),
                                     TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_OVERWRITE,
                                     TEE_HANDLE_NULL,
                                     NULL, 0, /* we may not fill it right now */
                                     &object);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("saving metadata failed");
        print_TEE_ret(res);
        return res;
    }

    size_t length = (size_t)ctx->end_ptr - (size_t)ctx->data_start;
    res = TEE_WriteObjectData(object, ctx->data_start, length);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to save metadata file, res=0x%08x", res);
        print_TEE_ret(res);
    }
    TEE_CloseObject(object);
    return res;
}

// Deprecated - use allocate variant
int32_t fetch_data(char *key, uint32_t key_size, char *buffer, uint32_t buf_size, uint32_t *read_bytes_ptr, uint32_t wanted_permissions)
{
    ErrorMSG("Deprecated function called: fetch_data");

    uint32_t read_bytes;
    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    uint32_t res;
    meta_ctx ctx;

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry == 0)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        meta_destroy(&ctx);
        return res;
    }

    if ((entry->attributes & wanted_permissions) != wanted_permissions)
    {
        res = TEE_ERROR_ACCESS_CONFLICT;
        meta_destroy(&ctx);
        return res;
    }
    meta_destroy(&ctx);

    /*
     * Check the object exist and can be dumped into output buffer
     * then dump it.
     */
    int32_t ret = -1;
    ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_READ |
                                       TEE_DATA_FLAG_SHARE_READ,
                                   &object);

    if (ret != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to open persistent object, res=0x%08x", ret);
        return ret;
    }

    ret = TEE_GetObjectInfo1(object, &object_info);
    if (ret != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to create persistent object, res=0x%08x", ret);
        goto exit;
    }

    if (object_info.dataSize > buf_size)
    {
        /*
         * Provided buffer is too short.
         * Return the expected size together with status "short buffer"
         */

        ret = object_info.dataSize; // todo: this is very meh, even though OPTEE error values are negative... Think about a better way to do this
        goto exit;
    }

    ret = TEE_ReadObjectData(object, buffer, object_info.dataSize, &read_bytes);

    *read_bytes_ptr = object_info.dataSize;
    if (ret == TEE_SUCCESS)
    {
        *read_bytes_ptr = read_bytes;
    }
    else if (ret != TEE_SUCCESS || read_bytes != object_info.dataSize)
    {
        ErrorMSG("> TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
                 ret, read_bytes, object_info.dataSize);
        goto exit;
    }

exit:
    InfoMSG("fetch_data result:");
    print_TEE_ret(ret);
    TEE_CloseObject(object);
    return ret;
}

//
int32_t fetch_data_allocate(char *key, uint32_t key_size, char **buffer, uint32_t *buf_size, uint32_t meta_permissions)
{
    uint32_t read_bytes;
    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    uint32_t res;
    meta_ctx ctx;

    init_file_metadata(&ctx);

    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry == 0)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        meta_destroy(&ctx);
        return res;
    }

    if ((entry->attributes & meta_permissions) != meta_permissions)
    {
        ErrorMSG("> Access Control Error while reading %s", key);
        res = TEE_ERROR_ACCESS_CONFLICT;
        meta_destroy(&ctx);
        return res;
    }

    meta_destroy(&ctx);

    /*
     * Check the object exist and can be dumped into output buffer
     * then dump it.
     */

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_READ |
                                       TEE_DATA_FLAG_SHARE_READ,
                                   &object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to open persistent object, res=0x%08x", res);
        return res;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to create persistent object, res=0x%08x", res);
        goto exit;
    }

    char *output_buffer = TEE_Malloc(object_info.dataSize, 0);
    if (output_buffer == 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    res = TEE_ReadObjectData(object, output_buffer, object_info.dataSize, &read_bytes);
    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to read object data, res=0x%08x", res);

        TEE_Free(output_buffer);
        goto exit;
    }

    *buf_size = object_info.dataSize;
    *buffer = output_buffer;

    // Should never happen...
    if (read_bytes != object_info.dataSize)
    {
        ErrorMSG("> TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
                 res, read_bytes, object_info.dataSize);
        assert(false);
        res = -1;
        goto exit;
    }

exit:
    InfoMSG("fetch_data_allocate result:");
    print_TEE_ret(res);
    TEE_CloseObject(object);
    return res;
}

TEE_Result delete_data(char *key, size_t key_size, uint32_t wanted_permissions)
{

    TEE_ObjectHandle object;
    TEE_Result res;

    meta_ctx ctx;

    init_file_metadata(&ctx);
    meta_entry *entry = meta_find(&ctx, key, key_size);
    if (entry == 0)
    {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        ErrorMSG("> Failed to init storage metadata:");
        print_TEE_ret(res);
        meta_destroy(&ctx);
        return res;
    }

    if ((entry->attributes & wanted_permissions) != wanted_permissions)
    {
        res = TEE_ERROR_ACCESS_CONFLICT;
        ErrorMSG("> Failed to init storage metadata:");
        print_TEE_ret(res);
        meta_destroy(&ctx);
        return res;
    }

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                   key, key_size,
                                   TEE_DATA_FLAG_ACCESS_WRITE_META, // We can delete the file
                                   &object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> Failed to open persistent object, res=0x%08x", res);
        print_TEE_ret(res);
        meta_destroy(&ctx);
        return res;
    }
    res = TEE_CloseAndDeletePersistentObject1(object);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> TEE_CloseAndDeletePersistentObject1 failed 0x%08x", res);
        print_TEE_ret(res);
    }
    else
    {
        meta_delete(&ctx, entry);
        save_file_metadata(&ctx);
    }
    meta_destroy(&ctx);
    return res;
}

uint32_t fetch_all_data(list_entry **data_ptr, uint32_t *data_length, uint32_t required_permissions)
{
    InfoMSG("fetch_all_data ...");

    meta_ctx ctx;

    meta_entry *entry = 0;
    uint32_t counter = 0;
    uint32_t buffer_size = 100;
    uint32_t ret;

    init_file_metadata(&ctx);
    list_entry *start_ptr = TEE_Malloc(buffer_size, 0);
    list_entry *local_data_ptr = start_ptr;

    // data format:
    //
    //  [uint32_t filename_length]
    //  [char filename[filename_length]]
    //  [uint32_t data_lenght]
    //  [char data[data_length]]
    //  [uint32_t attributes]
    // (repeat)
    // ...

    while ((entry = meta_next(&ctx)) != 0)
    {

        if ((entry->attributes & required_permissions) != required_permissions)
        {
            InfoMSG("Skipping data with wrong permissions.");
            continue;
        }

        while (strlen(entry->filename) >= (int64_t)buffer_size - (counter + 4))
        {
            list_entry *temp = TEE_Realloc(start_ptr, buffer_size + 100);
            if (temp == 0)
            {
                TEE_Free(start_ptr);
                InfoMSG("fetch_all_data: TEE_ERROR_OUT_OF_MEMORY 1");
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            start_ptr = temp;
            buffer_size += 100;
            local_data_ptr = (list_entry *)(((char *)start_ptr) + counter);
        }
        InfoMSG("Fetching: %s", entry->filename);
        // Copy ID
        local_data_ptr->entry_length = strlen(entry->filename);
        memcpy(local_data_ptr->data, entry->filename, strlen(entry->filename));

        // Advance ptr to end of current entry and track length
        local_data_ptr = local_data_ptr->data + local_data_ptr->entry_length;
        counter += strlen(entry->filename) + 4;

        // Get file content
        TEE_ObjectHandle object;
        TEE_ObjectInfo info;
        ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE_REE,
                                       entry->filename, strlen(entry->filename),
                                       TEE_DATA_FLAG_ACCESS_READ |
                                           TEE_DATA_FLAG_SHARE_READ,
                                       &object);
        if (ret != TEE_SUCCESS)
        {
            // This should never happen, file has to exist
            ErrorMSG("> Failed to open persistent object, res=0x%08x", ret);
            goto error;
        }

        ret = TEE_GetObjectInfo1(object, &info);
        if (ret != TEE_SUCCESS)
        {
            TEE_CloseObject(object);

            ErrorMSG("> Failed to get objectinfo, res=0x%08x", ret);
            goto error;
        }

        while (info.dataSize >= (int64_t)buffer_size - (counter + 4))
        {
            list_entry *temp = TEE_Realloc(start_ptr, buffer_size + 100);
            if (temp == 0)
            {
                TEE_Free(start_ptr);
                InfoMSG("fetch_all_data: TEE_ERROR_OUT_OF_MEMORY 2");
                return TEE_ERROR_OUT_OF_MEMORY;
            }
            start_ptr = temp;
            buffer_size += 100;
            local_data_ptr = (list_entry *)(((char *)start_ptr) + counter);
        }

        uint32_t read_bytes;

        ret = TEE_ReadObjectData(object, local_data_ptr->data, info.dataSize, &read_bytes);
        if (ret != TEE_SUCCESS || read_bytes != info.dataSize)
        {
            ErrorMSG("> TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
                     ret, read_bytes, info.dataSize);
            TEE_CloseObject(object);
            goto error;
        }
        local_data_ptr->entry_length = info.dataSize;
        local_data_ptr = local_data_ptr->data + local_data_ptr->entry_length;

        TEE_CloseObject(object);
        counter += info.dataSize + 4; // \0 already included
        while (4 >= (int64_t)buffer_size - (counter + 4))
        {
            list_entry *temp = TEE_Realloc(start_ptr, buffer_size + 100);
            if (temp == 0)
            {
                TEE_Free(start_ptr);
                InfoMSG("fetch_all_data: TEE_ERROR_OUT_OF_MEMORY 3");
                return TEE_ERROR_OUT_OF_MEMORY;
            }
            start_ptr = temp;
            buffer_size += 100;

            local_data_ptr = (list_entry *)(((char *)start_ptr) + counter);
        }

        // Add attributes
        *(uint32_t *)local_data_ptr = entry->attributes;
        local_data_ptr = (list_entry *)((char *)local_data_ptr + 4);

        counter += sizeof(uint32_t);
    }
    meta_destroy(&ctx);
    *data_ptr = start_ptr;
    *data_length = counter;
    InfoMSG("fetch_all_data: TEE_SUCCESS");
    return TEE_SUCCESS;

error:
    InfoMSG("fetch_all_data result:");
    print_TEE_ret(ret);
    meta_destroy(&ctx);
    TEE_Free(start_ptr);
    return (uint32_t)-1;
}
