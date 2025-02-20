#include <inttypes.h>
#include <adp1_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "relic.h"
// #include "mupre_test.h"
#include "pre-afgh-relic.h"
#include "adp_internals.h"
#include "adp_crypto.h"
#include "adp_metadata.h"
#include "adp_export.h"
// TEE meta-commands: /////////////////////////////////////////////////////////////////////////////

TEE_Result TA_CreateEntryPoint(void)
{
    InfoMSG("(1) CreateEntryPoint called. Initializing Eratosthenes ADP!");
    InfoMSG("Build date:   %s", ADP_BUILD_DATE);
    // InfoMSG("Build commit: %s", ADP_BUILD_COMMIT);
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types, TEE_Param __unused params[4], void __unused **session)
{
    InfoMSG("(2) OpenSessionEntryPoint called.");
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
    InfoMSG("(3) CloseSessionEntryPoint called.");
}

void TA_DestroyEntryPoint(void)
{
    InfoMSG("(4) DestroyEntryPoint called.");
}

// ADP Secure Storage Demo: //////////////////////////////////////////////////////////////////////

// TODO: Pass permissions integer instead of just boolean
static TEE_Result adp_store(uint32_t param_types, TEE_Param params[4], bool private)
{
    InfoMSG("adp_store called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    char *obj_id;
    size_t obj_id_sz;
    char *data;
    size_t data_sz;
    TEE_Result res;

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_sz = params[0].memref.size;
    if(obj_id_sz > TEE_OBJECT_ID_MAX_LEN) {
        ErrorMSG("Key too long. Key is %d bytes, limit from TEE is %d bytes.", obj_id_sz, TEE_OBJECT_ID_MAX_LEN);
        return TEE_ERROR_BAD_PARAMETERS;
    } else if (obj_id_sz == 0) {
        ErrorMSG("Key can not be an empty string.");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    InfoMSG("Storing to: %s", obj_id);

    data_sz = params[1].memref.size;
    if (data_sz == 0) 
    {
        ErrorMSG("Data length should not be zero.");
        TEE_Free(obj_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    data = TEE_Malloc(data_sz, 0);
    if (!data)
    {
        TEE_Free(obj_id);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(data, params[1].memref.buffer, data_sz);

    InfoMSG("Storing %zd bytes of data", data_sz);

    /*
     * Create object in secure storage and fill with data
     */
    uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |      /* we can later read the oject */
                             TEE_DATA_FLAG_ACCESS_WRITE |     /* we can later write into the object */
                             TEE_DATA_FLAG_ACCESS_WRITE_META; /* we can later destroy or rename the object */

    if (private)
        res = store_data(obj_id, obj_id_sz, data, data_sz, obj_data_flag, 0);
    else
        res = store_data(obj_id, obj_id_sz, data, data_sz, obj_data_flag, META_PUBLIC);

    TEE_Free(obj_id);
    TEE_Free(data);
    return res;
}

static TEE_Result adp_update(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("update called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    TEE_Result res;
    char *obj_id;
    size_t obj_id_sz;
    char *data;
    size_t data_sz;

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");

        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    InfoMSG("Updating at: %s", obj_id);

    data_sz = params[1].memref.size;
    data = TEE_Malloc(data_sz, 0);
    if (!data)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(data, params[1].memref.buffer, data_sz);

    InfoMSG("Updating to: %s", data);

    /*
     * Check the object exist and can be dumped into output buffer
     * then dump it.
     */
    res = update_data(obj_id, obj_id_sz, data, data_sz, false);

    TEE_Free(obj_id);
    TEE_Free(data);
    return res;
}

static TEE_Result adp_delete(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("delete called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    TEE_Result res;
    char *obj_id;
    size_t obj_id_sz;

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    InfoMSG("Deleting at: %s", obj_id);

    /*
     * Check the object exist and can be dumped into output buffer
     * then dump it.
     */
    res = delete_data(obj_id, obj_id_sz, false);

    InfoMSG("delete_data returned:");
    print_TEE_ret(res);

    TEE_Free(obj_id);
    return res;
}

static TEE_Result adp_read(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("adp_read called with buffer size %d ...", params[1].memref.size);

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    TEE_Result res;
    uint32_t read_bytes;
    char *obj_id;
    size_t obj_id_sz;
    char *data = 0;
    size_t data_sz;

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    obj_id_sz = params[0].memref.size;
    obj_id = TEE_Malloc(obj_id_sz, 0);
    if (!obj_id)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

    InfoMSG("Retrieving from: %s", obj_id);
    InfoMSG("Mi paciencia tiene un limite");

    data_sz = params[1].memref.size;

    InfoMSG("Pablito clavo un clavito");

    res = fetch_data_allocate(obj_id, obj_id_sz, &data, &data_sz, META_EXTERNAL_READABLE);

    InfoMSG("Que clavito clavo pablito?");

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> adp_read error from fetch_all_data:");
        print_TEE_ret(res);
        // memory leak? → fetch_data_allocate cleans up
        return res;
    }

    if (data_sz > params[1].memref.size)
    {
        ErrorMSG("> adp_list: buffer not large enough (yet).", res);
        ErrorMSG("Required: %d   Allocated in REE: %d", data_sz, params[1].memref.size);
        res = TEE_ERROR_SHORT_BUFFER;
    }
    else
    {
        InfoMSG("Buffer size valid. Returning data ...");
        TEE_MemMove(params[1].memref.buffer, data, data_sz);
    }

    params[1].memref.size = data_sz; // tell REE what buffer size we need or have

    InfoMSG("adp_read result:");
    print_TEE_ret(res);

    TEE_Free(obj_id);
    TEE_Free(data);

    return res;
}

static TEE_Result adp_list(uint32_t param_types, TEE_Param params[4])
{

    InfoMSG("adp_list called with buffer size %d ...", params[0].memref.size);
    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    list_entry *output_buffer;
    uint32_t output_len;

    InfoMSG("Fetching all data ...");
    uint32_t res = fetch_all_data(&output_buffer, &output_len, META_EXTERNAL_READABLE);

    InfoMSG("Required data size: %u bytes", output_len);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("> adp_list error from fetch_all_data:");
        print_TEE_ret(res);
        return res;
    }

    if (output_len <= params[0].memref.size)
    {
        InfoMSG("Buffer size valid. Returning data ...");
        // copy data from internal buffer to output buffer
        TEE_MemMove(params[0].memref.buffer, output_buffer, output_len);
    }
    else
    {
        // Buffer allocated in REE is too small
        res = TEE_ERROR_SHORT_BUFFER;
        ErrorMSG("> adp_list: buffer not large enough (yet).", res);
        ErrorMSG("Required: %d   Allocated in REE: %d", output_len, params[0].memref.size);
    }

    TEE_Free(output_buffer);            // free internal buffer
    params[0].memref.size = output_len; // tell REE what buffer size we need!

    InfoMSG("adp_list result:");
    print_TEE_ret(res);
    return res;
}

static TEE_Result adp_backup(uint32_t param_types, TEE_Param params[4])
{

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, // data
                        TEE_PARAM_TYPE_MEMREF_OUTPUT, // data_len
                        TEE_PARAM_TYPE_MEMREF_OUTPUT, // key
                        TEE_PARAM_TYPE_NONE);         // key_len

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *data;
    char *key;
    char *signature;
    uint32_t data_len;
    uint32_t key_len;
    uint32_t signature_len;
    uint32_t ret = backup_data(&data, &data_len, &key, &key_len, &signature, &signature_len);
    if (ret != TEE_SUCCESS)
    {
        params[0].memref.size = 0;
        params[1].memref.size = 0;
        params[2].memref.size = 0;
        return ret;
    }

    if (data_len <= params[0].memref.size && key_len <= params[1].memref.size && signature_len <= params[2].memref.size)
    {
        TEE_MemMove(params[0].memref.buffer, data, data_len);
        TEE_MemMove(params[1].memref.buffer, key, key_len);
        TEE_MemMove(params[2].memref.buffer, signature, signature_len);
        params[0].memref.size = data_len;
        params[1].memref.size = key_len;
        params[2].memref.size = signature_len;
    }
    else
    {
        params[0].memref.size = data_len;
        params[1].memref.size = key_len;
        params[2].memref.size = signature_len;
        ret = TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_Free(data);
    TEE_Free(key);
    TEE_Free(signature);
    return ret; // TODO maybe throw an error if we don't have enough memory?
}

static TEE_Result adp_import(uint32_t param_types, TEE_Param params[4])
{

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, // data
                        TEE_PARAM_TYPE_MEMREF_OUTPUT, // key
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t memory_size = params[0].memref.size;
    list_entry *mem = TEE_Malloc(params[0].memref.size, 0);
    if (!mem)
    {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint32_t key_size = params[1].memref.size;
    char *key = TEE_Malloc(params[1].memref.size, 0);
    if (!key)
    {
        TEE_Free(mem);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(mem, params[0].memref.buffer, memory_size);
    TEE_MemMove(key, params[1].memref.buffer, key_size);

    InfoMSG("Restoring data...");
    uint32_t ret = restore_data(mem, memory_size, key, key_size);
    return ret;
}

static TEE_Result adp_get_public_key(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("adp_get_public_key called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_VALUE_OUTPUT);
    TEE_Result res;
    char *data1;
    size_t length1;
    char *data2;
    size_t length2;
    char *data3;
    size_t length3;

    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = get_public_key(&data1, &length1, &data2, &length2, &data3, &length3);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("Could not get public key");
        return res;
    }

    if (length1 > params[0].memref.size)
    {
        params[0].memref.size = length1;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    params[0].memref.size = length1;
    TEE_MemMove(params[0].memref.buffer, data1, length1);

    if (length2 > params[1].memref.size)
    {
        params[1].memref.size = length2;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    params[1].memref.size = length2;
    TEE_MemMove(params[1].memref.buffer, data2, length2);

    if (length3 > params[2].memref.size)
    {
        params[2].memref.size = length3;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    params[2].memref.size = length3;
    TEE_MemMove(params[2].memref.buffer, data3, length3);

    InfoMSG("adp_get_public_key successful");

    params[3].value.a = ADP_ASYMMMETRIC_ALGO;

    res = TEE_SUCCESS;
exit:
    TEE_Free(data1);
    TEE_Free(data2);
    TEE_Free(data3);
    return res;
}

// TODO: Input from params, not test message
static TEE_Result adp_get_signature(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("adp_get_signature called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE,
                        TEE_PARAM_TYPE_NONE);
    TEE_Result res;
    char *digest;
    size_t length;

    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *test_message = "Test message";

    res = sign_message(test_message, strlen(test_message), &digest, &length);

    if (res != TEE_SUCCESS)
    {
        ErrorMSG("Could not sign message");
        return res;
    }

    if (length > params[0].memref.size)
    {
        params[0].memref.size = length;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    params[0].memref.size = length;
    TEE_MemMove(params[0].memref.buffer, digest, length);

    InfoMSG("adp_get_signature successful");

    res = TEE_SUCCESS;
    /* Return the number of byte effectively filled */
exit:
    TEE_Free(digest);
    return res;
}

static TEE_Result adp_init(uint32_t param_types, TEE_Param params[4])
{
    InfoMSG("adp_init called ...");

    const uint32_t exp_param_types =
        TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,  // params
                        TEE_PARAM_TYPE_MEMREF_INPUT,  // server pk
                        TEE_PARAM_TYPE_MEMREF_OUTPUT, // pre_pk
                        TEE_PARAM_TYPE_NONE);         // pubkey only via dedicated call
    TEE_Result res;
    char *pre_pubkey = 0;
    size_t params_len;
    size_t server_pk_len;
    char *server_pk = 0;
    char *pre_params = 0;

    if (param_types != exp_param_types)
    {
        ErrorMSG("Received wrong data types from NormalWorld");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    params_len = params[0].memref.size;
    pre_params = TEE_Malloc(params_len, 0);
    if (!pre_params)
    {

        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(pre_params, params[0].memref.buffer, params_len);

    uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_WRITE;

    res = store_data("pre_params", 10, pre_params, params_len, obj_data_flag, 0);

    if (res != TEE_SUCCESS)
    {
        goto exit;
    }

    server_pk_len = params[1].memref.size;
    server_pk = TEE_Malloc(server_pk_len, 0);
    if (!server_pk)
    {
        TEE_Free(pre_params);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(server_pk, params[1].memref.buffer, server_pk_len);

    obj_data_flag = TEE_DATA_FLAG_ACCESS_WRITE;

    // No export, will be initialized in init
    res = store_data("server_pk", 9, server_pk, server_pk_len, obj_data_flag, META_EXTERNAL_READABLE);

    if (res != TEE_SUCCESS)
    {
        goto exit;
    }

    res = init_keys();

    if (res != TEE_SUCCESS)
    {
        goto exit;
    }
    size_t pubkey_len;
    res = init_pre_keys(pre_params, params_len, &pre_pubkey, &pubkey_len);
    if (pre_pubkey == 0)
    {
        ErrorMSG("Initializing keys failed!");
        return -1;
    }

    params[2].memref.size = pubkey_len;
    TEE_MemMove(params[2].memref.buffer, pre_pubkey, pubkey_len);

    InfoMSG("Device initialization successful");

    res = TEE_SUCCESS;
    /* Return the number of byte effectively filled */
exit:
    TEE_Free(pre_params);
    TEE_Free(pre_pubkey);
    return res;
}

static TEE_Result adp_test()
{
    bool isSupported = TEE_SUCCESS == TEE_IsAlgorithmSupported(TEE_ALG_ED25519, TEE_ECC_CURVE_25519);
    InfoMSG("ED25519 & CURVE_25519 Supported: %d", isSupported);
    return isSupported ? TEE_SUCCESS : TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4])
{

    InfoMSG("\n");
    InfoMSG("----------------------------------");
    InfoMSG("InvokeCommandEntryPoint called ...");
    switch (command)
    {
    case ERATOSTHENES_ADP1_CMD_WRITE_RAW:
        return adp_store(param_types, params, false);
    case ERATOSTHENES_ADP1_CMD_WRITE_PRIVATE_RAW:
        return adp_store(param_types, params, true);
    case ERATOSTHENES_ADP1_CMD_READ_RAW:
        return adp_read(param_types, params);
    case ERATOSTHENES_ADP1_CMD_UPDATE_RAW:
        return adp_update(param_types, params);
    case ERATOSTHENES_ADP1_CMD_DELETE_RAW:
        return adp_delete(param_types, params);
    case ERATOSTHENES_ADP_CMD_LIST_RAW:
        return adp_list(param_types, params);
    case ERATOSTHENES_TEST:
        return adp_test();
    case ERATOSTHENES_ADP1_CMD_GET_PUBLIC_KEY:
        return adp_get_public_key(param_types, params);
    case ERATOSTHENES_ADP1_CMD_GET_SIGNATURE:
        return adp_get_signature(param_types, params);
    case ERATOSTHENES_ADP1_CMD_BACKUP:
        return adp_backup(param_types, params);
    case ERATOSTHENES_ADP1_CMD_IMPORT:
        return adp_import(param_types, params);
    case ERATOSTHENES_INIT:
        return adp_init(param_types, params);
    default:
        ErrorMSG("> Command ID 0x%x is not supported", command);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
