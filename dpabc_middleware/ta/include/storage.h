#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <adp_interface.h>

TEE_Result st_store(char * id, size_t id_sz, char * data, size_t data_sz);
TEE_Result st_read(char * id, size_t id_sz, char ** data, size_t * data_sz);

#endif //STORAGE_H
