#include "adp_interface.h"
#include <stdint.h>

static TEE_Result open_adp_session(void **sess_ctx) {

	IMSG("[TA1] Opening session to TA 2 ...\n");
	TEE_UUID uuid = ERATOSTHENES_ADP1_UUID;
	TEE_TASessionHandle session;
	uint32_t origin;
	TEE_Result res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, TEE_PARAM_TYPE_NONE, NULL, &session, &origin);

	if(res != TEE_SUCCESS) {
		IMSG("Failed to open session to ADP.\n");
		return res;
	} else {
		IMSG("Opened session to ADP!\n");
	}
	*sess_ctx = session;

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

TEE_Result adp_test() {

	TEE_Result res;
	void * sess_ctx;
	TEE_Param params[4];
	uint32_t origin;

	res = open_adp_session(&sess_ctx);
	if (res != TEE_SUCCESS) {
		EMSG("Error creating ADP TA session");
		return res;
	}

	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);

	DMSG("Invoking ADP overlords:");

	res = TEE_InvokeTACommand(sess_ctx, 
		     TEE_TIMEOUT_INFINITE, 
		     ERATOSTHENES_TEST, 
		     TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE), 
		     params, 
		     &origin);

	if(res != TEE_SUCCESS) {	
		IMSG("ADP Test failed");
		return res;
	} else {
		IMSG("ADP Test success");
	}

	TEE_CloseTASession(sess_ctx);

	return TEE_SUCCESS;
}


TEE_Result adp_store(char * id, size_t id_sz, char * data, size_t data_sz) {

	TEE_Param params[4];
	uint32_t origin;
	void * sess_ctx;
	TEE_Result res;

	res = open_adp_session(&sess_ctx);
	if (res != TEE_SUCCESS) {
		EMSG("Error creating ADP TA session");
		return res;
	}

	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);


	params[0].memref.buffer = id;
	params[0].memref.size = id_sz;

	params[1].memref.buffer = data;
	params[1].memref.size = data_sz;

	res = TEE_InvokeTACommand(sess_ctx, 
		     TEE_TIMEOUT_INFINITE, 
		     ERATOSTHENES_ADP1_CMD_WRITE_RAW, 
		     param_types, 
		     params, 
		     &origin);

	if (res != TEE_SUCCESS) {
		DMSG("ADP write error: %" PRIu32 "\n", origin);
	}

	TEE_CloseTASession(sess_ctx);

	return res;

}


TEE_Result adp_read(char * id, size_t id_sz, char ** data, size_t * data_sz) {

	TEE_Param params[4];
	uint32_t origin;
	void * sess_ctx;
	TEE_Result res;

	res = open_adp_session(&sess_ctx);
	if (res != TEE_SUCCESS) {
		EMSG("Error creating ADP TA session");
		return res;
	}

	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);
	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	*data_sz = READ_BUFF_DEFAULT_SIZE; // initial buffersize 
	char * temp_data = TEE_Malloc(*data_sz, TEE_MALLOC_FILL_ZERO);

	params[0].memref.buffer = id;
	params[0].memref.size = id_sz;

	int max_retries = 5;

	for(uint32_t i = 0; i < max_retries; i++)
	{
		params[1].memref.buffer = temp_data;
		params[1].memref.size = *data_sz;

		res = TEE_InvokeTACommand(sess_ctx, 
		     TEE_TIMEOUT_INFINITE, 
		     ERATOSTHENES_ADP1_CMD_READ_RAW, 
		     param_types, 
		     params, 
		     &origin);

		if(res != TEE_ERROR_SHORT_BUFFER) {
			// Success or other error
			break;
		} // else: TEE_ERROR_SHORT_BUFFER → retry with larger buffer 

		*data_sz = params[1].memref.size;
		temp_data = (char*) TEE_Realloc(temp_data, *data_sz);
	}

	switch (res) {
	case TEE_SUCCESS:
		*data = temp_data;
		break;
	default:
		DMSG("ADP read error: %" PRIu32 "\n", origin);
	}

	TEE_CloseTASession(sess_ctx);

	return res;
}

TEE_Result adp_list(uint32_t param_type, TEE_Param params[4]) {

	uint32_t origin;
	void * sess_ctx;
	TEE_Result res;

	res = open_adp_session(&sess_ctx);
	if (res != TEE_SUCCESS) {
		EMSG("Error creating ADP TA session");
		return res;
	}

	res = TEE_InvokeTACommand(sess_ctx, 
		     TEE_TIMEOUT_INFINITE, 
		     ERATOSTHENES_ADP_CMD_LIST_RAW, 
		     param_type, 
		     params, 
		     &origin);

	TEE_CloseTASession(sess_ctx);

	return res;
}
