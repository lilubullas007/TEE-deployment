#include <adp1_ta.h>
#include "adp_export.h"
#include "adp_internals.h"
#include "adp_crypto.h"
#include "adp_metadata.h"




uint32_t get_backupped_data(char** data, uint32_t* data_length, char** signature, uint32_t signature_length, char* key, uint32_t key_length)
{
    InfoMSG("get_backupped_data called");

    list_entry* internal_data;
    uint32_t internal_data_length;
    
    uint32_t res = fetch_all_data(&internal_data, &internal_data_length, META_EXPORTABLE);
    if(res != TEE_SUCCESS)
    {
        return res;
    }


    InfoMSG("Encrypting Backup");

    char* encrypted_data;
    uint32_t enc_len;
    res = encrypt_backup((char*)internal_data, internal_data_length, key, key_length, &encrypted_data, &enc_len);
    TEE_Free(internal_data); // Free this in any case
    *signature = 0;
    if(res != TEE_SUCCESS)
    {
        return res;
    }

    res = sign_message(encrypted_data, enc_len, signature, signature_length);
    if(res != TEE_SUCCESS)
    {
        TEE_Free(encrypted_data);
        return res;
    }
    InfoMSG("Signature: %s", *signature);

    *data_length = enc_len;
    *data = encrypted_data;
    return TEE_SUCCESS;

    
}


uint32_t backup_data(char** data, uint32_t* data_length, char** key, uint32_t* key_length, char** signature, uint32_t* signature_length)
{
    InfoMSG("backup_data called");

    char* pre_pt = 0;
    uint32_t pre_pt_length;

    char* temp_key = 0;
    uint32_t temp_key_length;

    char* pre_params = 0;
    uint32_t pre_params_length;

    char* pre_server_pk = 0;
    uint32_t pre_server_pk_length;

    char* pre_enc_key = 0;
    uint32_t pre_enc_key_length;



    uint32_t res = fetch_data_allocate("pre_params", 10, &pre_params, &pre_params_length, 0);
    if(res != TEE_SUCCESS)
    {
        InfoMSG("Failed to get PRE params");
        return res;
    }
    res = fetch_data_allocate("server_pk", 9, &pre_server_pk, &pre_server_pk_length, 0);
    if(res != TEE_SUCCESS)
    {
        InfoMSG("Failed to get server PK");

        goto end;
    }

    InfoMSG("Generating key");
    res = generate_plaintext_pre(&pre_pt, &pre_pt_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }

    res = hash_message(pre_pt, pre_pt_length, &temp_key, &temp_key_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }
    
    InfoMSG("Backing up data");
    InfoMSG("This can take a while");
    res = get_backupped_data(data, data_length, signature, signature_length, temp_key, temp_key_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }

    InfoMSG("Encrypting backup key");
    res = encrypt_data_with_pre(pre_server_pk, pre_server_pk_length, pre_pt, pre_pt_length, 
                                pre_params, pre_params_length, &pre_enc_key, &pre_enc_key_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }
    *key = pre_enc_key;
    *key_length = pre_enc_key_length;
    InfoMSG("Done!");

end: 
    TEE_Free(temp_key);
    TEE_Free(pre_params);
    TEE_Free(pre_pt);
    TEE_Free(pre_server_pk);
    return res;
    
}

uint32_t import_decrypted_data(char* data, uint32_t data_length)
{
    InfoMSG("import_decrypted_data called");

    char* end_ptr = (data + data_length);
    uint32_t ret = 0;
    while(data != end_ptr)
    {
        list_entry* entry = data;
        char* filename = entry->data;
        uint32_t filename_length = entry->entry_length;

        entry = (list_entry*) &entry->data[entry->entry_length];
        char* file_data = entry->data;
        uint32_t data_length = entry->entry_length;


        char* intermediate = &file_data[data_length];
        uint32_t permissions = *((uint32_t*)intermediate);

        char* temp_filename = TEE_Malloc(filename_length + 1, 0);
        TEE_MemMove(temp_filename, filename, filename_length);
        temp_filename[filename_length] = 0;
        InfoMSG("Importing %s", temp_filename);
        ret = store_data(temp_filename, filename_length, file_data, data_length, TEE_DATA_FLAG_ACCESS_WRITE, permissions);
        TEE_Free(temp_filename);
        if(ret != TEE_SUCCESS)
        {
            ErrorMSG("Importing backup failed for entry! name: %s, data: %s", filename, file_data);
            // continuing...
        }
        data = &intermediate[sizeof(uint32_t)];
    }
    return ret;

}


uint32_t restore_data(char* data, uint32_t data_length, char* key, uint32_t key_length)
{
    InfoMSG("restore_data called");

    char* dec_plaintext = 0;
    uint32_t dec_plaintext_length;

    char* sk = 0;
    uint32_t sk_length;

    char* temp_key = 0;
    uint32_t temp_key_length;

    char* dec_data = 0;
    uint32_t dec_data_length;

    char* pre_params = 0;
    uint32_t pre_params_length;

    uint32_t res = fetch_data_allocate("pre_params", 10, &pre_params, &pre_params_length, 0);
    if(res != TEE_SUCCESS)
    {
        InfoMSG("Failed to get PRE params");

        return res;
    }
    res = fetch_data_allocate("pre_sk", 6, &sk, &sk_length, 0);
    if(res != TEE_SUCCESS)
    {
        InfoMSG("Failed to get PRE secret");

        goto end;
    }

    InfoMSG("Decrypting backup key");
    res = decrypt_data_with_pre(sk, sk_length, key, key_length, 
                                pre_params, pre_params_length, &dec_plaintext, &dec_plaintext_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }



    TEE_Free(pre_params);
    TEE_Free(sk);


    res = hash_message(dec_plaintext, dec_plaintext_length, &temp_key, &temp_key_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }

    InfoMSG("Decrypting backup");
    res = decrypt_backup(data, data_length, temp_key, temp_key_length, &dec_data, &dec_data_length);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }

    InfoMSG("Importing data");
    res = import_decrypted_data(dec_data, dec_data_length);
    InfoMSG("Done!");

    // delete PRE data for replay attack protection


end:

    clear_pre_keys();
    TEE_Free(dec_data);
    TEE_Free(dec_plaintext);
    TEE_Free(temp_key);

    return res; 
}
