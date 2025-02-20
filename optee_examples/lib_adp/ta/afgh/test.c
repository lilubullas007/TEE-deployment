/*
 * Copyright (c) 2016, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 *
 * Author:
 *       Lukas Burkhalter <lubu@student.ethz.ch>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include "pre-afgh-relic.h"


#define exit(X) TEE_Panic(X)

int basic_test() {
  pre_params_t params;
  pre_sk_t alice_sk, bob_sk;
  pre_pk_t alice_pk, bob_pk;
  pre_token_t token_to_bob;
  pre_plaintext_t plaintext, decrypted;
  pre_ciphertext_t cipher;
  pre_re_ciphertext_t re_cipher;
  uint8_t key1[16];
  uint8_t key2[16];
  int ok = 1;
  gt_null(re_cipher->c1);gt_new(re_cipher->c1);
  gt_null(re_cipher->c1);gt_new(re_cipher->c2);
  // generate random message
  pre_rand_plaintext(plaintext);

  pre_generate_params(params);
  pre_generate_sk(alice_sk, params);
  pre_derive_pk(alice_pk, params, alice_sk);
  pre_generate_sk(bob_sk, params);
  pre_derive_pk(bob_pk, params, bob_sk);

  pre_encrypt(cipher, params, alice_pk, plaintext);

  pre_decrypt(decrypted, params, alice_sk, cipher);

  if (gt_cmp(plaintext->msg, decrypted->msg) == RLC_EQ) {
    IMSG("Encrypt decrypt OK!");
  } else {
    EMSG("Encrypt decrypt failed!");
  }

  pre_generate_token(token_to_bob, params, alice_sk, bob_pk);
  pre_apply_token(re_cipher, token_to_bob, cipher);
  pre_decrypt_re(decrypted, params, bob_sk, re_cipher);

  if (gt_cmp(plaintext->msg, decrypted->msg) == RLC_EQ) {
    IMSG("Re-encrypt decrypt OK!");
  } else {
    EMSG("Re-encrypt decrypt failed!");
  }

  pre_map_to_key(key1, 16, decrypted);
  pre_map_to_key(key2, 16, plaintext);

  for (int i = 0; i < 16; i++) {
    if (key1[i] != key2[i]) {
      ok = 0;
      break;
    }
  }

  if (ok) {
    IMSG("Map to key OK!");
  } else {
    EMSG("Map to key failed!");
  }

  return 0;
}

void encode_decode_test() {
  pre_plaintext_t plaintext, plaintext_decoded, decrypted;
  pre_params_t params, params_decoded;
  pre_sk_t alice_sk, bob_sk, alice_sk_decoded;
  pre_pk_t alice_pk, bob_pk, alice_pk_decoded;
  pre_ciphertext_t alice_cipher1, alice_cipher1_decode;
  pre_re_ciphertext_t bob_re, bob_re_decode;
  pre_token_t token_to_bob, token_to_bob_decode;
  int size;
  char *buff;

  pre_rand_plaintext(plaintext);
  size = get_encoded_plaintext_size(plaintext);
  buff = (char *)malloc(size);
  if (!encode_plaintext(buff, size, plaintext) == RLC_OK) {
    IMSG("Message encode error!");
    exit(1);
  }
  if (!decode_plaintext(plaintext_decoded, buff, size) == RLC_OK) {
    IMSG("Message decode error!");
    exit(1);
  }
  free(buff);

  if (gt_cmp(plaintext->msg, plaintext_decoded->msg) == RLC_EQ) {
    IMSG("Decode message OK!");
  } else {
    IMSG("Decode message Failed!");
  }

  pre_generate_params(params);
  pre_generate_sk(alice_sk, params);
  pre_derive_pk(alice_pk, params, alice_sk);
  pre_generate_sk(bob_sk, params);
  pre_derive_pk(bob_pk, params, bob_sk);
  pre_generate_token(token_to_bob, params, alice_sk, bob_pk);
  pre_encrypt(alice_cipher1, params, alice_pk, plaintext);

  size = get_encoded_params_size(params);
  buff = (char *)malloc(size);
  if (!encode_params(buff, size, params) == RLC_OK) {
    IMSG("Params encode error!");
    exit(1);
  }
  if (!decode_params(params_decoded, buff, size) == RLC_OK) {
    IMSG("Params decode error!");
    exit(1);
  }
  free(buff);

  if (gt_cmp(params->Z, params_decoded->Z) == RLC_EQ &&
      g1_cmp(params->g1, params_decoded->g1) == RLC_EQ &&
      g2_cmp(params->g2, params_decoded->g2) == RLC_EQ) {
    IMSG("Decode params OK!");
  } else {
    IMSG("Decode params failed!");
  }

  size = get_encoded_sk_size(alice_sk);
  buff = (char *)malloc(size);
  if (!encode_sk(buff, size, alice_sk) == RLC_OK) {
    IMSG("Secret key encode error!");
    exit(1);
  }
  if (!decode_sk(alice_sk_decoded, buff, size) == RLC_OK) {
    IMSG("Secret key decode error!");
    exit(1);
  }
  free(buff);

  if (bn_cmp(alice_sk->a, alice_sk_decoded->a) == RLC_EQ &&
      bn_cmp(alice_sk->a_inv, alice_sk_decoded->a_inv) == RLC_EQ) {
    IMSG("Secret key OK!");
  } else {
    IMSG("Secret key failed!");
  }

  size = get_encoded_pk_size(alice_pk);
  buff = (char *)malloc(size);
  if (!encode_pk(buff, size, alice_pk) == RLC_OK) {
    IMSG("Public key encode error!");
    exit(1);
  }
  if (!decode_pk(alice_pk_decoded, buff, size) == RLC_OK) {
    IMSG("Public key decode error!");
    exit(1);
  }
  free(buff);

  if (g1_cmp(alice_pk->pk1, alice_pk_decoded->pk1) == RLC_EQ &&
      g2_cmp(alice_pk->pk2, alice_pk_decoded->pk2) == RLC_EQ) {
    IMSG("Decode public key OK!");
  } else {
    IMSG("Decode public key failed!");
  }

  if (g1_cmp(alice_pk->pk1, alice_pk_decoded->pk1) == RLC_EQ &&
      g2_cmp(alice_pk->pk2, alice_pk_decoded->pk2) == RLC_EQ) {
    IMSG("Public key OK!");
  } else {
    IMSG("Public key failed!");
  }

  size = get_encoded_token_size(token_to_bob);
  buff = (char *)malloc(size);
  if (!encode_token(buff, size, token_to_bob) == RLC_OK) {
    IMSG("Token encode error!");
    exit(1);
  }
  if (!decode_token(token_to_bob_decode, buff, size) == RLC_OK) {
    IMSG("Token decode error!");
    exit(1);
  }
  free(buff);

  if (g2_cmp(token_to_bob->token, token_to_bob_decode->token) == RLC_EQ) {
    IMSG("Decode token OK!");
  } else {
    IMSG("Decode token failed!");
  }

  size = get_encoded_ciphertext_size(alice_cipher1);
  buff = (char *)malloc(size);
  encode_ciphertext(buff, size, alice_cipher1);
  decode_ciphertext(alice_cipher1_decode, buff, size);
  free(buff);

  if (gt_cmp(alice_cipher1->c1, alice_cipher1_decode->c1) == RLC_EQ &&
      g1_cmp(alice_cipher1->c2, alice_cipher1_decode->c2) == RLC_EQ) {
    IMSG("Decode cipher OK!");
  } else {
    IMSG("Decode cipher failed!");
  }

  pre_apply_token(bob_re, token_to_bob, alice_cipher1);

  size = get_encoded_re_ciphertext_size(bob_re);
  buff = (char *)malloc(size);
  encode_re_ciphertext(buff, size, bob_re);
  decode_re_ciphertext(bob_re_decode, buff, size);
  free(buff);

  if (gt_cmp(bob_re->c1, bob_re_decode->c1) == RLC_EQ &&
      gt_cmp(bob_re->c2, bob_re_decode->c2) == RLC_EQ) {
    IMSG("Decode re-encrypted cipher OK!");
  } else {
    IMSG("Decode re-encrypted cipher failed!");
  }
  pre_decrypt(decrypted, params, alice_sk, alice_cipher1);
  if (gt_cmp(decrypted->msg, plaintext->msg) == RLC_EQ) {
    IMSG("Decrypt OK!");
  } else {
    IMSG("Dec Failed!");
  }
}

int test_main_afgh() {
  pre_init();
  IMSG("---- PRE Tests");
  basic_test();
  IMSG("---- Encode/Decode Tests");
  encode_decode_test();
  pre_cleanup();
  return 0;
}
