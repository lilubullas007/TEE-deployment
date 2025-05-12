#include <Zp.h>
#include <Dpabc.h>
#include <dpabc_middleware.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void base64_encode(const unsigned char *input, size_t input_len, char *output) {
    int i, j;
    for (i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }
    while (j % 4 != 0) output[j++] = '=';
    output[j] = '\0';
}

int main() {
    char *key_id = "key_signature";
    char *sign_id = "sig_1";
    const int nattr = 6;
    const int epoch_val = 3;

    DPABC_session session;
    if (DPABC_initialize(&session) != STATUS_OK) {
        printf("Error initializing DPABC\n");
        return 1;
    }

    if (DPABC_generate_key(&session, key_id, nattr) != STATUS_OK) {
        printf("Error generating the key\n");
        DPABC_finalize(&session);
        return 1;
    }

    Zp **attr = malloc(nattr * sizeof(Zp *));
    for (int i = 0; i < nattr; i++) {
        int val = i % 3 - 1;
        attr[i] = zpFromInt(val);
    }

    size_t attr_bytes_len = nattr * zpByteSize();
    char *attr_bytes = malloc(attr_bytes_len);
    for (int i = 0; i < nattr; i++)
        zpToBytes(attr_bytes + i * zpByteSize(), attr[i]);

    Zp *epoch_zp = zpFromInt(epoch_val);
    char *epoch_bytes = malloc(zpByteSize());
    zpToBytes(epoch_bytes, epoch_zp);

    // Sign and store
    char *sig = NULL;
    size_t sig_sz = 0;
    if (DPABC_sign(&session, key_id, epoch_bytes, zpByteSize(), attr_bytes, attr_bytes_len, &sig, &sig_sz) != STATUS_OK) {
        printf("Error signing\n");
        goto cleanup;
    }
    
    char *sig_base64 = malloc(((sig_sz + 2) / 3) * 4 + 1);
    base64_encode((unsigned char *)sig, sig_sz, sig_base64);
    printf("Signature (Base64 URL-safe): %s\n", sig_base64);

    
    if (DPABC_storeSignature(&session, sign_id, sig, sig_sz) == STATUS_OK) {
        printf("Signature stored with ID: %s\n", sign_id);
    } else {
        printf("Error storing signature\n");
    }

    /**
    printf("=== Parámetros para verificación ===\n");
    printf("Signature (Base64 URL-safe): %s\n", sig_base64);
    printf("Epoch: %d\n", epoch_val);
    printf("Public key bytes (hex): ");
    for (size_t i = 0; i < pk_sz; i++) {
        printf("%02X", (unsigned char)pk_bytes[i]);
    }
    printf("\n");
    **/

cleanup:
    DPABC_finalize(&session);
    free(attr_bytes);
    free(epoch_bytes);
    free(sig);
    free(attr);
    return 0;
}

