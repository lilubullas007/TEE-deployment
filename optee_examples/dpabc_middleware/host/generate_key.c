#include "Dpabc_types.h"
#include "types_impl.h"
#include <Zp.h>
#include <Dpabc.h>
#include <dpabc_middleware.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    DPABC_session session;
    char *key_id;
    int nattr = 5;
    
    if (argc != 2) {
        printf("Usage: %s <key_id>\n", argv[0]);
        return 1;
    }
    
    key_id = argv[1];  // key_id

    if (DPABC_initialize(&session) != STATUS_OK) {
        fprintf(stderr, "Error initializing DPABC\n");
        return 1;
    }

    // Generate key
    if (DPABC_generate_key(&session, key_id, nattr) != STATUS_OK) {
        fprintf(stderr, "Error generating the key\n");
        DPABC_finalize(&session);
        return 1;
    }

    printf("Key successfully generated with key_id: %s\n", key_id);
    
    DPABC_finalize(&session);
    return 0;
}
