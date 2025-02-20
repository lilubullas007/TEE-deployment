#pragma once

#include <inttypes.h>

typedef struct __attribute__((__packed__)) meta_entry_ {
    uint32_t attributes;
    uint32_t length;
    char filename[];

} meta_entry;

typedef struct __attribute__((__packed__)) meta_header_ {
    uint32_t magic;
    uint32_t version;
    meta_entry data[];
} meta_header;



typedef struct __attribute__((__packed__)) meta_ctx {
    meta_header* data_start;
    meta_entry* current_entry;
    char* end_ptr;
    uint8_t status;
} meta_ctx;

#define META_PRESENT (1<<31)
#define META_EXTERNAL_READABLE 1
#define META_EDITABLE 2
#define META_DELETABLE 4
#define META_EXPORTABLE 8
#define META_PUBLIC (META_EXTERNAL_READABLE | META_EDITABLE | META_DELETABLE | META_EXPORTABLE)


// After init, data belongs to this code and will be managed by it.
// Any direct access to that memory might cause undefined behavior
void meta_init(meta_ctx* ctx, char* data, uint32_t length);
meta_entry* meta_next(meta_ctx* ctx);
meta_entry* meta_find(meta_ctx* ctx, char* needle, uint32_t length);
void meta_delete(meta_ctx* ctx, meta_entry* entry);
void meta_insert(meta_ctx* ctx, char* filename, uint32_t length, uint32_t attributes);
void meta_rewind(meta_ctx* ctx);
void meta_destroy(meta_ctx* ctx);
