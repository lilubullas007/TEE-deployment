#ifndef __ERATOSTHENES_ADP1_H__
#define __ERATOSTHENES_ADP1_H__
#include <inttypes.h>
/* UUID of the trusted application */
// 3e68c39a-507f-11ed-bdc3-0242ac120002 
#define ERATOSTHENES_ADP1_UUID \
		{ 0x3e68c39a, 0x507f, 0x11ed, \
			{ 0xbd, 0xc3, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02 } }




/*
 * ERATOSTHENES_ADP1_CMD_READ_RAW - Read a secure storage file
 * param[0] (in-memref) ID used the identify the persistent object
 * param[1] (out-memref) Raw data dumped from the persistent object
 * param[2] unused
 * param[3] unused
 */
#define ERATOSTHENES_ADP1_CMD_READ_RAW		7

/*
 * ERATOSTHENES_ADP1_CMD_WRITE_RAW - Create and fill a secure storage file
 * param[0] (in-memref) ID used the identify the persistent object
 * param[1] (in-memref) Raw data to be writen in the persistent object
 * param[2] unused
 * param[3] unused
 */
#define ERATOSTHENES_ADP1_CMD_WRITE_RAW		8

/*
 * ERATOSTHENES_ADP1_CMD_UPDATE_RAW - Create and fill a secure storage file
 * param[0] (in-memref) ID used the identify the persistent object
 * param[1] (in-memref) Raw data to be writen in the persistent object
 * param[2] unused
 * param[3] unused
 */
#define ERATOSTHENES_ADP1_CMD_UPDATE_RAW	9


/*
 * ERATOSTHENES_ADP1_CMD_DELETE_RAW - Create and fill a secure storage file
 * param[0] (in-memref) ID used the identify the persistent object
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define ERATOSTHENES_ADP1_CMD_DELETE_RAW	10

/*
 * ERATOSTHENES_ADP_CMD_LIST_RAW - Create and fill a secure storage file
 * param[0] (out-memref) buffer to store the kv-list
 * param[1] (out-value) 
 * param[2] unused
 * param[3] unused
 */

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

# define COMPONENT_NAME "[ADP (TEE)]"

#define TA_LOG_ENABLED
#define TA_ERRORS_ENABLED

// #define InfoMSG(...) InfoMSG(COMPONENT_NAME __VA_ARGS__)
#ifdef TA_LOG_ENABLED
#define InfoMSG(fmt, ...) IMSG(COMPONENT_NAME " Info: " fmt __VA_OPT__(,) __VA_ARGS__)
#else
#define InfoMSG(fmt, ...) ;
#endif

#ifdef TA_ERRORS_ENABLED
#define ErrorMSG(fmt, ...) IMSG(COMPONENT_NAME " Error: " fmt __VA_OPT__(,) __VA_ARGS__)
#else
#define ErrorMSG(fmt, ...) ;
#endif
// if EMSG is used for errors, log is out of order, since stderr is not flushed fast enough


#endif /* __ERATOSTHENES_ADP1_H__ */

#define ADP_BUILD_DATE "(no build date set)"
#define ADP_BUILD_ISO8601 "(no build date set)"
#define ADP_BUILD_COMMIT "local build"

