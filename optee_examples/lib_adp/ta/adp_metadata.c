#include <adp1_ta.h>
#include "adp_metadata.h"
#include <assert.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


void meta_init(meta_ctx* ctx, char* data, uint32_t length);
meta_entry* meta_next(meta_ctx* ctx);
meta_entry* meta_find(meta_ctx* ctx, char* needle, uint32_t length);
void meta_rewind(meta_ctx* ctx);
void meta_delete(meta_ctx* ctx, meta_entry* entry);
void meta_insert(meta_ctx* ctx, char* filename, uint32_t length, uint32_t attributes);
void meta_destroy(meta_ctx* ctx);

#define MAGIC_BYTES 0x32345844
#define CURRENT_VERSION 1

#define STATUS_INVALID 0xff
#define STATUS_VALID 0x42


void meta_open(meta_ctx* ctx)
{

}


void meta_init(meta_ctx* ctx, char* data, uint32_t length)
{
    if(data == 0 && length == 0) // create new metadata structure
    {
        length = sizeof(meta_header);
        data = TEE_Malloc(length, 0);
        ((meta_header*)data)->magic = MAGIC_BYTES;
        ((meta_header*)data)->version = CURRENT_VERSION;
    }
    meta_header* header = ((meta_header*)data);
    assert(header->magic == MAGIC_BYTES);
    assert(header->version == CURRENT_VERSION);
    ctx->data_start = data;
    ctx->current_entry = 0;
    ctx->end_ptr = data + length;
    ctx->status = STATUS_VALID;
}

meta_entry* meta_next_internal(meta_ctx* ctx)
{
    assert(ctx->status == STATUS_VALID);
    meta_entry* entry = ctx->current_entry; 

    if(entry == 0)
    {
        ctx->current_entry = (char*)ctx->data_start + sizeof(meta_header);
        entry = ctx->current_entry; 
    }
    else
    {
        if(entry >=  ctx->end_ptr) return 0;
        
        entry = (meta_entry*) (entry->filename + entry->length);
        ctx->current_entry = entry;
    }

    if(entry >= ctx->end_ptr) return 0;

    return entry;
}

meta_entry* meta_next(meta_ctx* ctx)
{
    assert(ctx->status == STATUS_VALID);

    meta_entry* entry;
    while((entry = meta_next_internal(ctx)))
    {
        if(entry->attributes & META_PRESENT)
        {
            return entry;
        }
    }
    return 0;
}

void meta_rewind(meta_ctx* ctx)
{
    assert(ctx->status == STATUS_VALID);
    // reset iterator
    ctx->current_entry = 0;
}

void meta_delete(meta_ctx* ctx, meta_entry* entry)
{
    assert(ctx->status == STATUS_VALID);

    assert(entry > ctx->data_start && entry < ctx->end_ptr);

    entry->attributes = 0; // just set to not present - we don't want to update the whole file
}

void meta_insert(meta_ctx* ctx, char* filename, uint32_t length, uint32_t attributes)
{
    assert(ctx->status == STATUS_VALID); // context is initialized
    assert(filename[length] == 0); // nullbyte at the end of filename

    // TODO: Maybe allow insert without rewind to speed up restore
    meta_rewind(ctx);
    meta_entry* entry;

    while((entry = meta_next_internal(ctx)))
    {
        if((entry->attributes & META_PRESENT) == 0 && entry->length > length)
        {
            break; // found element that can fit the data
        }
    }

    if(entry == 0)
    {
        size_t current_size = ctx->end_ptr - ((char*)ctx->data_start);
        meta_header* temp = 0;
        temp = TEE_Realloc(ctx->data_start, current_size + length + 1 + sizeof(meta_entry));
        assert(temp); // if we run out of memory here, we have a problem

        if(temp != ctx->data_start) {
            // memory has moved, update pointers
            ctx->data_start = temp;
            ctx->current_entry = ((char*)ctx->data_start) + current_size;
            
        }
        entry = ctx->current_entry;
        ctx->end_ptr = ((char*)ctx->data_start) + current_size + length + 1 + sizeof(meta_entry);
        entry->length = length + 1;
        entry->attributes = 0;
    }

    TEE_MemFill(entry->filename, 0, entry->length); // overwrite full entry, since entry can be bigger
    TEE_MemMove(entry->filename, filename, length); // copy data
    entry->attributes = (attributes | META_PRESENT);

}

meta_entry* meta_find(meta_ctx* ctx, char* needle, uint32_t length)
{
    assert(ctx->status == STATUS_VALID);
    meta_entry* entry;
    meta_rewind(ctx);
    while(entry = meta_next(ctx))
    {
        if(entry->length <= length)
            continue;
        
        if(TEE_MemCompare(needle, entry->filename, length + 1) == 0)
        {
            return entry;
        }
    }
    return 0;
}

void meta_destroy(meta_ctx* ctx)
{
    assert(ctx->status == STATUS_VALID);

    TEE_Free(ctx->data_start);
    ctx->data_start = 0;
    ctx->end_ptr = 0;
    ctx->current_entry = 0;
    ctx->status = STATUS_INVALID;
}
