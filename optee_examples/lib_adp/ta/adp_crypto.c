#include "pre-afgh-relic.h"
#include <adp1_ta.h>
#include "adp_crypto.h"
#include "adp_internals.h"
#include "adp_metadata.h"
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>


#define keyname "internalKeyPair"

#define HASH_SIZE 32


#if ADP_ASYMMMETRIC_ALGO == ADP_RSA512

#define ASYMMETRIC_KEY_SIZE 512
#define PRIVATE_KEY_TYPE TEE_TYPE_RSA_KEYPAIR
#define PUBLIC_KEY_TYPE TEE_TYPE_RSA_PUBLIC_KEY
#define SIGNATURE_ALGORITHM TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
#define KEY_GETTER get_rsa_public_key
#define SIGNATURE_SIZE (ASYMMETRIC_KEY_SIZE/8)

#elif ADP_ASYMMMETRIC_ALGO == ADP_ED25519

#define ASYMMETRIC_KEY_SIZE 256
#define PRIVATE_KEY_TYPE TEE_TYPE_ED25519_KEYPAIR
#define PUBLIC_KEY_TYPE TEE_TYPE_ED25519_PUBLIC_KEY
#define SIGNATURE_ALGORITHM TEE_ALG_ED25519
#define KEY_GETTER get_ec_public_key
#define SIGNATURE_SIZE (512/8)

#else
    No valid signature algorithm selected, so this should not compile.
#endif


// Since the PRE keys are not used anymore after restoring anyways
uint32_t clear_pre_keys()
{
    uint32_t res = delete_data("pre_sk", 6, 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Deleting pre_sk failed");
    }
    return res;
}

// TODO: Bring return values of PRE code in line with TEE conventions
uint32_t init_pre_keys(char* params, size_t params_len, char** pubkey, size_t* pubkey_len)
{
    InfoMSG("Generating PRE keys");
    pre_sk_t pre_secret_key;
    pre_pk_t pre_public_key;
    uint32_t res;
    TEE_Result ;
    pre_params_t params_decoded;
    pre_init();

    res = decode_params(params_decoded, params, params_len);
    if(res != RLC_OK)
    {
        return 0;
    }

    
    res = pre_generate_sk(pre_secret_key, params_decoded);
    if(res != RLC_OK){
        ErrorMSG("Generating PRE secret failed. Error code: %u / %x", res, res);
        free_params(params_decoded);
        pre_cleanup();
        return 0;
    }
    // save SK
    int sk_len = get_encoded_sk_size(pre_secret_key);
    char* encoded_sk = TEE_Malloc(sk_len, 0);
    if(!encoded_sk)
    {
        free_params(params_decoded);
        free_sk(pre_secret_key);
        pre_cleanup();
        return 0;
    }
    res = encode_sk(encoded_sk, sk_len, pre_secret_key);
    if(res != RLC_OK)
    {
        goto end;
    }
    res = store_data("pre_sk", 6, encoded_sk, sk_len, TEE_DATA_FLAG_ACCESS_WRITE, 0);
    TEE_Free(encoded_sk);
    if(res != TEE_SUCCESS)
    {
        goto end;
    }
    res = pre_derive_pk(pre_public_key, params_decoded, pre_secret_key);
    if(res != RLC_OK)
    {
        goto end;
    }
    
    int pk_len = get_encoded_pk_size(pre_public_key);
    char* encoded_pk = TEE_Malloc(pk_len, 0);
    if(!encoded_pk)
    {
        goto end;
    }
    res = encode_pk(encoded_pk, pk_len, pre_public_key);
    if(res != RLC_OK)
    {
        TEE_Free(encoded_pk);
        goto end;
    }
    // We don't store the public key, only return it
    *pubkey_len = pk_len;
    *pubkey = encoded_pk;
end:
    pre_cleanup();
    free_sk(pre_secret_key);
    free_params(params_decoded);
    free_pk(pre_public_key);
    return res;

}
uint32_t generate_plaintext_pre(char** plaintext, size_t* plaintext_length)
{
    InfoMSG("generate_plaintext_pre called");

    uint32_t res = TEE_SUCCESS;
    pre_init();
    pre_plaintext_t plaintext_generated;
    pre_rand_plaintext(plaintext_generated);
    int plain_len = get_encoded_plaintext_size(plaintext_generated);
    char* encoded = TEE_Malloc(plain_len, 0);
    if(encoded == 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    encode_plaintext(encoded, plain_len, plaintext_generated);
    *plaintext = encoded;
    *plaintext_length = plain_len;

    exit:
    pre_clean_plaintext(plaintext_generated);
    pre_cleanup();
    return res;
}

TEE_Result encrypt_data_with_pre(char* pk, size_t pk_length, char* data, size_t data_length, char* params, size_t params_length, char** ret_ptr, int *ret_length)
{
    InfoMSG("encrypt_data_with_pre called");

    pre_init();
    pre_params_t pre_params;
    pre_pk_t pk_decoded;
    pre_plaintext_t plaintext_decoded;
    pre_ciphertext_t ciphertext;
    decode_params(pre_params, params, params_length);
    uint32_t res = TEE_SUCCESS;
    decode_plaintext(plaintext_decoded, data, data_length);
    decode_pk(pk_decoded, pk, pk_length);
    pre_encrypt(ciphertext, pre_params, pk_decoded, plaintext_decoded);

    int len = get_encoded_ciphertext_size(ciphertext);
    char* retval = TEE_Malloc(len, 0);
    if(retval == 0)
    {
        
        res = TEE_ERROR_OUT_OF_MEMORY;
    }
    
    encode_ciphertext(retval, len, ciphertext);
    free_params(pre_params);
    free_pk(pk_decoded);
    free_plaintext(plaintext_decoded);
    free_ciphertext(ciphertext);
    pre_cleanup();
    *ret_length = len;
    *ret_ptr = retval;
    return res;
}

TEE_Result decrypt_data_with_pre(char* sk, size_t sk_length, char* data, size_t data_length, char* params, size_t params_length, char** ret_ptr, int* ret_length)
{
    InfoMSG("decrypt_data_with_pre called");

    pre_init();
    pre_params_t pre_params;
    pre_sk_t sk_decoded;
    pre_re_ciphertext_t ciphertext_decoded;
    pre_plaintext_t plaintext;
    uint32_t res = TEE_SUCCESS;


    decode_params(pre_params, params, params_length);
    decode_re_ciphertext(ciphertext_decoded, data, data_length);
    decode_sk(sk_decoded, sk, sk_length);

    // Decrypt data
    pre_decrypt_re(plaintext, pre_params, sk_decoded, ciphertext_decoded);

    int len = get_encoded_plaintext_size(plaintext);
    char* retval = TEE_Malloc(len, 0);
    if(retval == 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        return res;
    }
    
    encode_plaintext(retval, len, plaintext);

    free_params(pre_params);
    free_sk(sk_decoded);
    free_plaintext(plaintext);
    free_re_ciphertext(ciphertext_decoded);
    pre_cleanup();
    *ret_length = len;
    *ret_ptr = retval;
    return res;
}

// Not needed in TEE
char* apply_token_pre(char* src_data, size_t src_data_sz, char* token, size_t token_sz, int *ret_len)
{
    InfoMSG("apply_token_pre called");

    pre_init();
    pre_token_t token_decoded;
    pre_ciphertext_t ciphertext;
    pre_re_ciphertext_t reenc_ciphertext;

    decode_ciphertext(ciphertext, src_data, src_data_sz);

    decode_token(token_decoded, token, token_sz);
    

    pre_apply_token(reenc_ciphertext, token_decoded, ciphertext);
    int len = get_encoded_re_ciphertext_size(reenc_ciphertext);
    char* retval = TEE_Malloc(len, 0);
    
    encode_re_ciphertext(retval, len, reenc_ciphertext);
    *ret_len = len;
    free_ciphertext(ciphertext);
    free_token(token_decoded);
    free_re_ciphertext(reenc_ciphertext);
    pre_cleanup();
    
    return retval;
}

TEE_Result init_keys()
{
    InfoMSG("init_keys called");

    TEE_ObjectHandle generatedKeyPair;
    TEE_Result res;
    
    InfoMSG("Allocating keypair");
    res = TEE_AllocateTransientObject(PRIVATE_KEY_TYPE, ASYMMETRIC_KEY_SIZE, &generatedKeyPair);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Allocating transient object failed");
        return res;
    }

    // no parameters, e defaults to 65537
    InfoMSG("Generating key");

    res = TEE_GenerateKey(generatedKeyPair, ASYMMETRIC_KEY_SIZE, 0, 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Generating key failed...");
        goto cleanup;
    }

    InfoMSG("Storing key");
    InfoMSG("key name is %s", keyname);
    res = store_transient_object(keyname, strlen(keyname), generatedKeyPair, 
            TEE_USAGE_ENCRYPT | 
            TEE_USAGE_DECRYPT | 
            TEE_USAGE_SIGN | 
            TEE_USAGE_VERIFY, 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Storing transient key failed");
        goto cleanup;
    }
    

cleanup:
    TEE_FreeTransientObject(generatedKeyPair);
    return res;
}

TEE_Result get_ec_public_key(char** buffer1, size_t* length1, char** buffer2, size_t* length2, char** buffer3, size_t* length3)
{
    InfoMSG("Getting EC Public key");

    TEE_ObjectHandle generatedKeyPair;
    TEE_Result res;
    res = TEE_AllocateTransientObject(PUBLIC_KEY_TYPE, ASYMMETRIC_KEY_SIZE, &generatedKeyPair);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Allocating transient object failed");
        return res;
    }

    res = fetch_transient_object(generatedKeyPair, keyname, strlen(keyname), 0);

    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Fetching key failed...");
        goto cleanup;
    }
    size_t size;
    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_ED25519_PUBLIC_VALUE, 0, &size);
    if(res != TEE_ERROR_SHORT_BUFFER)
    {

        InfoMSG("GetObjectBufferAttribute failed");
        goto cleanup;
    }
    char* value = TEE_Malloc(size, 0);
    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_ED25519_PUBLIC_VALUE, value, &size);
    InfoMSG("Size is %zd", size);
    if(res != TEE_SUCCESS)
    {
        TEE_Free(value);
        goto cleanup;
    }

    *buffer1 = value;
    *length1 = size;
    *buffer2 = 0;
    *length2 = 0;
    *buffer3 = 0;
    *length3 = 0;



cleanup:
    TEE_FreeTransientObject(generatedKeyPair);
    return res;
}

TEE_Result get_rsa_public_key(char** buffer1, size_t* length1, char** buffer2, size_t* length2, char** buffer3, size_t* length3)
{
    InfoMSG("Getting RSA Public key");

    TEE_ObjectHandle generatedKeyPair;
    TEE_Result res;
    res = TEE_AllocateTransientObject(PUBLIC_KEY_TYPE, ASYMMETRIC_KEY_SIZE, &generatedKeyPair);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Allocating transient object failed");
        return res;
    }
    res = fetch_transient_object(generatedKeyPair, keyname, strlen(keyname), 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Fetching key failed...");
        goto cleanup;
    }
    size_t size;
    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_RSA_MODULUS, 0, &size);
    if(res != TEE_ERROR_SHORT_BUFFER)
    {

        InfoMSG("GetObjectBufferAttribute failed");
        goto cleanup;
    }
    char* modulus = TEE_Malloc(size, 0);
    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_RSA_MODULUS, modulus, &size);
    InfoMSG("Size is %zd", size);
    if(res != TEE_SUCCESS)
    {
        TEE_Free(modulus);
        goto cleanup;
    }

    size_t exp_size;

    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_RSA_PUBLIC_EXPONENT, 0, &exp_size);
    if(res != TEE_ERROR_SHORT_BUFFER)
    {
        TEE_Free(modulus);
        InfoMSG("GetObjectBufferAttribute failed");
        goto cleanup;
    }
    char* exponent = TEE_Malloc(exp_size, 0);
    res = TEE_GetObjectBufferAttribute(generatedKeyPair, TEE_ATTR_RSA_PUBLIC_EXPONENT, modulus, &exp_size);
    InfoMSG("Size is %zd", exp_size);
    if(res != TEE_SUCCESS)
    {
        TEE_Free(modulus);
        TEE_Free(exponent);
        goto cleanup;
    }

    *buffer1 = modulus;
    *length1 = size;
    *buffer2 = exponent;
    *length2 = exp_size;
    *buffer3 = 0;
    *length3 = 0;
    



cleanup:
    TEE_FreeTransientObject(generatedKeyPair);
    return res;
}

TEE_Result get_public_key(char** buffer1, size_t* length1, char** buffer2, size_t* length2, char** buffer3, size_t* length3)
{
    InfoMSG("Getting TEE Public key");

    return KEY_GETTER(buffer1, length1, buffer2, length2, buffer3, length3);
}


TEE_Result hash_message(char* buffer, size_t length, char** digest_out, size_t *digest_length)
{

    InfoMSG("hash_message called");
    
    TEE_OperationHandle handle;
    TEE_Result res;
    char* digest = 0;
    size_t diglen;
    res = TEE_AllocateOperation(&handle, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if(res != TEE_SUCCESS)
    {

        ErrorMSG("AllocateOperation failed");
        return res;
    }

    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Setting key failed...");
        goto cleanup;
    }

    digest = TEE_Malloc(HASH_SIZE, 0);
    if(digest == 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    diglen = HASH_SIZE;
    res = TEE_DigestDoFinal(handle, buffer, length, digest, &diglen);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("DigestDoFinal failed");
        TEE_Free(digest);
        goto cleanup;
    }

    *digest_out = digest;
    *digest_length = diglen;

cleanup:
    TEE_FreeOperation(handle);
    return res;
}


TEE_Result sign_digest(char* digest, size_t digest_len, char** signature_out, size_t* out_len)
{
    InfoMSG("sign_digest called");
    TEE_ObjectHandle generatedKeyPair;
    TEE_OperationHandle handle;
    TEE_Result res;
    size_t siglen;
    char* signature = 0;

    res = TEE_AllocateTransientObject(PRIVATE_KEY_TYPE, ASYMMETRIC_KEY_SIZE, &generatedKeyPair);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Allocating transient object failed");
        TEE_FreeOperation(handle);
        return res;
    }
    res = fetch_transient_object(generatedKeyPair, keyname, strlen(keyname), 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Fetching key failed...");
        goto cleanup;
    }

    res = TEE_AllocateOperation(&handle, SIGNATURE_ALGORITHM, TEE_MODE_SIGN, ASYMMETRIC_KEY_SIZE);
    if(res != TEE_SUCCESS)
    {

        ErrorMSG("AllocateOperation failed");
        return res;
    }

    res = TEE_SetOperationKey(handle, generatedKeyPair);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Setting key failed!");
        goto cleanup;
    }
    signature = TEE_Malloc(SIGNATURE_SIZE, 0);
    if(signature == 0)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    siglen = SIGNATURE_SIZE;
    InfoMSG("Digest len %d, ptr %p", digest_len, digest);
    InfoMSG("signature len: %d, ptr %p", siglen, signature);




    res = TEE_AsymmetricSignDigest(handle, 0, 0, digest, digest_len, signature, &siglen);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("Sign failed!");
        goto cleanup;
    }

    InfoMSG("signature: %s", signature);


    *signature_out = signature;
    *out_len = siglen;

cleanup:
    TEE_FreeOperation(handle);
    TEE_FreeTransientObject(generatedKeyPair);
    return res;



}


TEE_Result sign_message(char* message, size_t length, char** signature, size_t* siglen_out)
{
    InfoMSG("sign_message called");

    char* digest;
    char* sig_out;
    size_t siglen;
    size_t diglen;
    TEE_Result res;
    
#if ADP_ASYMMMETRIC_ALGO == ADP_ED25519
   res = TEE_SUCCESS;  // Full message is the digest here
   digest = message;
   diglen = length;
#else
    res = hash_message(message, length, &digest, &diglen);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("hash_message failed");
        return res;
    }
    InfoMSG("hash success, %s, %zd", digest, diglen);

#endif



    res = sign_digest(digest, diglen, &sig_out, &siglen);
#if ADP_ASYMMMETRIC_ALGO == ADP_ED25519
   digest = 0;         // We don't want to free this
#endif

    if(res != TEE_SUCCESS)
    {
        ErrorMSG("sign_digest failed");
        TEE_Free(digest);
        return res;
    }

    *signature = sig_out;
    *siglen_out = siglen;
    TEE_Free(digest);
    return res;

}

TEE_Result encrypt_backup(char* data, size_t length, char* key, uint32_t key_length, encrypted_backup** encrypted_out, uint32_t* encrypted_out_len)
{
    InfoMSG("encrypt_backup called");

    TEE_ObjectHandle key_obj;
    TEE_Result res;
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_obj);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AllocateTransientObject failed: %d", res);
        return res;
    }


    TEE_Attribute secret_key[1];
    TEE_InitRefAttribute(secret_key, TEE_ATTR_SECRET_VALUE, key, key_length);
    res = TEE_PopulateTransientObject(key_obj, secret_key, 1);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("PopulateTransientObject failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    TEE_OperationHandle operation;
    res = TEE_AllocateOperation(&operation, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, 256);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AllocateOperation failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    TEE_SetOperationKey(operation, key_obj);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("SetOperationKey failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }
    char nonce[16];
    TEE_GenerateRandom(nonce, 16);


    res = TEE_AEInit(operation, nonce, 16, 128, 0, 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AEInit failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }


    encrypted_backup* out = TEE_Malloc(length + sizeof(encrypted_backup) + 32, 0); // 32 bytes for tag and nonce, then some buffer for padding purposes
    char* enc_out = out->data; // first 16 bytes for tag

    char* tag = out->tag;
    uint32_t out_len = length + 32;
    size_t tag_len = 16;
    
    if(out == 0)
    {
        TEE_CloseObject(key_obj);
        TEE_FreeOperation(operation);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    res = TEE_AEEncryptFinal(operation, data, length, enc_out, &out_len, tag, &tag_len);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AEEncryptFinal failed: %d", res);
        TEE_CloseObject(key_obj);
        TEE_FreeOperation(operation);
        TEE_Free(out);
        return res;
    }
    TEE_MemMove(out->nonce, nonce, 16);

    // layout: [nonce (16b)][tag (16b)][enc_data (n b)]

    *encrypted_out = out;
    *encrypted_out_len = out_len + sizeof(encrypted_backup);
    TEE_CloseObject(key_obj);
    TEE_FreeOperation(operation);
    return TEE_SUCCESS;

}

TEE_Result decrypt_backup(encrypted_backup* data, size_t length, char* recv_key, uint32_t key_length, char** decrypted_out, uint32_t* decrypted_out_len)
{
    InfoMSG("decrypt_backup called");

    TEE_ObjectHandle key_obj;
    TEE_Result res;
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 256, &key_obj);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AllocateTransientObject failed: %d", res);
        return res;
    }

    char* nonce = data->nonce;

    TEE_Attribute secret_key[1];
    TEE_InitRefAttribute(secret_key, TEE_ATTR_SECRET_VALUE, recv_key, key_length);
    res = TEE_PopulateTransientObject(key_obj, secret_key, 1);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("PopulateTransientObject failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    TEE_OperationHandle operation;
    res = TEE_AllocateOperation(&operation, TEE_ALG_AES_GCM, TEE_MODE_DECRYPT, 256);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AllocateOperation failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    TEE_SetOperationKey(operation, key_obj);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("SetOperationKey failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    res = TEE_AEInit(operation, nonce, 16, 128, 0, 0);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AEInit failed: %d", res);
        TEE_CloseObject(key_obj);
        return res;
    }

    char* enc_in = data->data;
    size_t out_len = length;
    char* tag = data->tag;
    size_t tag_len = 16;

    char* out = TEE_Malloc(length, 0); // data is smaller than encrypted data anyways
    if(out == 0)
    {
        ErrorMSG("Malloc failed");
        TEE_CloseObject(key_obj);
        TEE_FreeOperation(operation);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    res = TEE_AEDecryptFinal(operation, enc_in, length - sizeof(encrypted_backup), out, &out_len, tag, tag_len);
    if(res != TEE_SUCCESS)
    {
        ErrorMSG("AEDecryptFinal failed: %d", res);
        TEE_CloseObject(key_obj);
        TEE_FreeOperation(operation);
        TEE_Free(out);
        return res;
    }
    *decrypted_out = out;
    *decrypted_out_len = out_len;
    TEE_CloseObject(key_obj);
    TEE_FreeOperation(operation);
    return TEE_SUCCESS;

}

