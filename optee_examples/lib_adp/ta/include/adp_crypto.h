#pragma once

#include <inttypes.h>


#define ADP_RSA512 7
#define ADP_ED25519 8




#define ADP_ASYMMMETRIC_ALGO ADP_ED25519


typedef struct __attribute__((__packed__)) encrypted_backup_data_ {
    char nonce[16];
    char tag[16];
    char data[];
} encrypted_backup;

TEE_Result encrypt_data_with_pre(char* pk, size_t pk_length, char* data, size_t data_length, char* params, size_t params_length, char** ret_ptr, int *ret_length);
TEE_Result decrypt_data_with_pre(char* sk, size_t sk_length, char* data, size_t data_length, char* params, size_t params_length, char** ret_ptr, int* ret_length);
char* apply_token_pre(char* src_data, size_t src_data_sz, char* token, size_t token_sz, int *ret_len);
uint32_t init_pre_keys(char* params, size_t params_len, char** pubkey, size_t* pubkey_len);
uint32_t generate_plaintext_pre(char** plaintext, size_t* plaintext_length);

TEE_Result init_keys();
TEE_Result clear_pre_keys();
TEE_Result get_public_key(char** buffer1, size_t* length1, char** buffer2, size_t* length2, char** buffer3, size_t* length3);
TEE_Result hash_message(char* buffer, size_t length, char** digest_out, size_t *digest_length);

TEE_Result sign_digest(char* digest, size_t digest_len, char** signature_out, size_t* out_len);
TEE_Result sign_message(char* message, size_t length, char** signature, size_t* siglen_out);
TEE_Result encrypt_backup(char* data, size_t length, char* key, uint32_t key_length, encrypted_backup** encrypted_out, uint32_t* encrypted_out_len);
TEE_Result decrypt_backup(encrypted_backup* data, size_t length, char* recv_key, uint32_t key_length, char** decrypted_out, uint32_t* decrypted_out_len);

