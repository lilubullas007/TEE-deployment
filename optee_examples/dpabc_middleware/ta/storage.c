#include <storage.h>

static TEE_Result create_raw_object(uint32_t obj_data_flag, char * obj_id, size_t obj_id_sz, char * data, size_t data_sz) {

	TEE_ObjectHandle object;
	TEE_Result res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					obj_data_flag,
					TEE_HANDLE_NULL,
					NULL, 0,		/* we may not fill it right now */
					&object);

	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		return res;
	}


	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	} else {
		TEE_CloseObject(object);
	}

	return TEE_SUCCESS;
}

static TEE_Result get_raw_object_size(char * obj_id, size_t obj_id_sz, size_t * object_size) {

	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		TEE_CloseObject(object);
		return res;
	}

	*object_size = object_info.dataSize;
	return res;
}

static TEE_Result read_raw_object(char * obj_id, size_t obj_id_sz, char * data, size_t data_sz, uint32_t * read_bytes) {

	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		TEE_CloseObject(object);
		return res;
	}

	if (object_info.dataSize > data_sz) {
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		res = TEE_ERROR_SHORT_BUFFER;
		TEE_CloseObject(object);
		return res;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 read_bytes);
	if (res != TEE_SUCCESS || *read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
		TEE_CloseObject(object);
		return res;
	}

	TEE_CloseObject(object);
	return res;
}

TEE_Result st_store(char * id, size_t id_sz, char * data, size_t data_sz) {

	TEE_Result res;

	if (adp_test() == TEE_SUCCESS) {
		return adp_store(id, id_sz, data, data_sz);
	}

	uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
			TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
			TEE_DATA_FLAG_ACCESS_WRITE_META;	/* we can later destroy or rename the object */
			// TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */
	
	res = create_raw_object(obj_data_flag, id, id_sz, data, data_sz);

	return res;
}

TEE_Result st_read(char * id, size_t id_sz, char ** data, size_t * data_sz) {

	size_t read_bytes;
	TEE_Result res;

	if (adp_test() == TEE_SUCCESS) {
		return adp_read(id, id_sz, data, data_sz);
	}

	res = get_raw_object_size(id, id_sz, data_sz);

	if (res != TEE_SUCCESS) {
		return res;
	}

	*data = TEE_Malloc(*data_sz, TEE_MALLOC_FILL_ZERO);
	res = read_raw_object(id, id_sz, *data, *data_sz, &read_bytes);

	if (res != TEE_SUCCESS) {
		TEE_Free(*data);
	}

	return res;
	
}
