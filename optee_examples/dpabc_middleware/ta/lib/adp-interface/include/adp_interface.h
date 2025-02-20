#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define ERATOSTHENES_ADP1_UUID \
		{ 0x3e68c39a, 0x507f, 0x11ed, \
			{ 0xbd, 0xc3, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02 } }


#define ERATOSTHENES_ADP1_CMD_READ_RAW		7
#define ERATOSTHENES_ADP1_CMD_WRITE_RAW		8
#define ERATOSTHENES_ADP1_CMD_UPDATE_RAW	9
#define ERATOSTHENES_ADP1_CMD_DELETE_RAW	10
#define ERATOSTHENES_ADP_CMD_LIST_RAW 11
#define ERATOSTHENES_TEST 12
#define ERATOSTHENES_ENCRYPT 13
#define ERATOSTHENES_REENCRYPT 14
#define ERATOSTHENES_ADP1_CMD_WRITE_PRIVATE_RAW 15
#define ERATOSTHENES_ADP1_CMD_GET_PUBLIC_KEY 16
#define ERATOSTHENES_ADP1_CMD_GET_SIGNATURE 17
#define ERATOSTHENES_INIT 18
#define ERATOSTHENES_ADP1_CMD_BACKUP 19
#define ERATOSTHENES_ADP1_CMD_IMPORT 20

#define READ_BUFF_DEFAULT_SIZE 512

TEE_Result adp_test();
TEE_Result adp_store(char * id, size_t id_sz, char * data, size_t data_sz);
TEE_Result adp_read(char * id, size_t id_sz, char ** data, size_t * data_sz);
TEE_Result adp_list(uint32_t param_type, TEE_Param params[4]);
