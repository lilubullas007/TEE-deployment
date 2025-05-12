#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Zp.h>
#include <Dpabc.h>
#include <dpabc_middleware.h>

int base64_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

unsigned char *base64_decode(const char *data, size_t *out_len) {
    size_t len = strlen(data);
    size_t padding = (4 - (len % 4)) % 4;
    size_t full_len = len + padding;

    char *input = malloc(full_len + 1);
    strcpy(input, data);
    for (size_t i = 0; i < padding; i++) input[len + i] = '=';
    input[full_len] = '\0';

    size_t output_len = full_len / 4 * 3;
    unsigned char *decoded = malloc(output_len);

    int i, j;
    for (i = 0, j = 0; i < full_len;) {
        int a = base64_index(input[i++]);
        int b = base64_index(input[i++]);
        int c = base64_index(input[i++]);
        int d = base64_index(input[i++]);

        uint32_t triple = (a << 18) | (b << 12) | ((c & 63) << 6) | (d & 63);
        if (j < output_len) decoded[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) decoded[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) decoded[j++] = triple & 0xFF;
    }

    *out_len = j;
    free(input);
    return decoded;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <key_id> <signature_base64>\n", argv[0]);
        return 1;
    }

    const char *key_id = argv[1];
    const char *sig_base64 = argv[2];
    const int nattr = 6;
    const int epoch_val = 3;

    DPABC_session session;
    if (DPABC_initialize(&session) != STATUS_OK) {
        printf("Error initializing DPABC\n");
        return 1;
    }

    // Retrieve public key
    unsigned char *pk_bytes = NULL;
    size_t pk_sz = 0;
    if (DPABC_get_key(&session, key_id, &pk_bytes, &pk_sz) != STATUS_OK) {
        printf("Error retrieving public key\n");
        DPABC_finalize(&session);
        return 1;
    }

    publicKey *pk = dpabcPkFromBytes(pk_bytes);

    size_t sig_len = 0;
    unsigned char *sig_bytes = base64_decode(sig_base64, &sig_len);
    signature *sig = dpabcSignFromBytes(sig_bytes);

    Zp *attrs[nattr];
    for (int i = 0; i < nattr; i++) {
        int val = i % 3 - 1;
        attrs[i] = zpFromInt(val);
    }

    Zp *epoch = zpFromInt(epoch_val);

    // Verify signature
    int result = verify(pk, sig, epoch, (const Zp **)attrs);
    if (result == 1) {
        printf("Signature verified.\n");
    } else {
        printf("Error verifying signature.\n");
    }

    dpabcPkFree(pk);
    dpabcSignFree(sig);
    free(sig_bytes);
    free(pk_bytes);
    DPABC_finalize(&session);
    return 0;
}

