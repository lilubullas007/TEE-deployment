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
    char *pk = NULL;
    size_t pk_size;

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
    
    // Retrieve generated key
    if (DPABC_get_key(&session, key_id, &pk, &pk_size) != STATUS_OK) {
        fprintf(stderr, "Error retrieving generated key\n");
        DPABC_finalize(&session);
        return 1;
    }

    // Print key
    printf("Generated Key: ");
    for (size_t i = 0; i < pk_size; i++) {
        printf("%02x", (unsigned char)pk[i]);
    }
    printf("\n");

    free(pk);
    
    DPABC_finalize(&session);
    return 0;
}
