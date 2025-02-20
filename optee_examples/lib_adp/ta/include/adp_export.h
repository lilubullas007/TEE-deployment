#pragma once
#include <stdint.h>





uint32_t backup_data(char** data, uint32_t* data_length, char** key, uint32_t* key_length, char** signature, uint32_t* signature_length);
uint32_t restore_data(char* data, uint32_t data_length, char* key, uint32_t key_length);