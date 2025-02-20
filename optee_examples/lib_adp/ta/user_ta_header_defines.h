/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <adp1_ta.h>

#define TA_UUID				ERATOSTHENES_ADP1_UUID

#define TA_FLAGS			(TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE)
#define TA_STACK_SIZE			((1 * 1024 + 512) * 1024)
#define TA_DATA_SIZE			(3 * 1024 * 1024)
#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
        "Eratosthenes Advanced Data Protector Demo" }, \
    { "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
