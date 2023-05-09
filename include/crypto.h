
/*
 * © COPYRIGHT 2022 Corporation CAICT All rights reserved.
 *  http://www.caict.ac.cn
 *  https://bitfactory.cn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 * @author: zhangzhiliang@caict.ac.cn
 * @date: 2023-03-01 16:17:18
 * @file: crypto.h
 */
#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BYTES_SIZE 1024
enum HashType { HASH_TYPE_SHA256 = 0, HASH_TYPE_SM3 = 1, HASH_TYPE_MAX = 2 };
// SHA256_CTX ctx_;
static const char *nb58 =
    "123456789AbCDEFGHJKLMNPQRSTuVWXYZaBcdefghijkmnopqrstUvwxyz";
static const int8_t b58n[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,
    8,  -1, -1, -1, -1, -1, -1, -1, 9,  34, 11, 12, 13, 14, 15, 16, -1, 17, 18,
    19, 20, 21, -1, 22, 23, 24, 25, 26, 52, 28, 29, 30, 31, 32, -1, -1, -1, -1,
    -1, -1, 33, 10, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46, 47, 48,
    49, 50, 51, 27, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1};

typedef struct ctr_state {
  // unsigned char ivec[AES_BLOCK_SIZE];
  unsigned char ivec[17];
  unsigned int num;
  unsigned char ecount[17];
} CTR_STATE;

struct AES_KEY;
typedef struct aes_ctr {
  bool key_valid;
  struct AES_KEY *key;
  char ckey[33];
  int ckey_len;
  unsigned char iv[17];
  int iv_len;
} AES_CTR;

void aes_init(unsigned char *iv, const char *ckey, AES_CTR *aes_ctr);
int init_ctr(CTR_STATE *state, const unsigned char iv[17]);
void lib_encrypt(unsigned char *in_data, AES_CTR *aes_ctr,
                 unsigned char *out_data, int bytes_read);

char *base58_encode(unsigned char *input, int input_len);
char *base58_decode(unsigned char *src, int *decode_len);

void sha256_crypto(const char *str, int len, char *buf);
char *sha256_crypto_base58(const char *input, int len, char *buf);

// void Sha256Update(const void *buffer, size_t len);
// char* Sha256Final();

// sm3 of struct method
typedef struct Sm3_contexts {
  unsigned long total[2];   /*!< number of bytes processed 8 */
  unsigned long state[8];   /*!< intermediate digest state  */
  unsigned char buffer[64]; /*!< data block being processed */

  unsigned char ipad[64]; /*!< HMAC: inner padding        */
  unsigned char opad[64]; /*!< HMAC: outer padding        */
} Sm3_context;            // ctx_
// void Sm3Update(Sm3_context ctx_, const void *buffer, size_t len);
// char* Sm3Final();

void sm3_crypto(const char *str, int len, unsigned char *buf);
char *sm3_crypto_base58(const char *input, int len, char *buf);
void sm3_starts(Sm3_context *ctx);

/**
 * \brief          SM3 process buffer
 *
 * \param ctx      SM3 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void sm3_update(Sm3_context *ctx, unsigned char *input, int ilen);
/**
 * \brief          SM3 final digest
 *
 * \param ctx      SM3 context
 */
void sm3_finish(Sm3_context *ctx, unsigned char output[32]);
void sm3_process(Sm3_context *ctx, unsigned char data[64]);

/**
 * \brief          SM3 HMAC context setup
 *
 * \param ctx      HMAC context to be initialized
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 */
void sm3_hmac_starts(Sm3_context *ctx, unsigned char *key, int keylen);
/**
 * \brief          SM3 HMAC process buffer
 *
 * \param ctx      HMAC context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */

void sm3_hmac_update(Sm3_context *ctx, unsigned char *input, int ilen);

/**
 * \brief          SM3 HMAC final digest
 *
 * \param ctx      HMAC context
 * \param output   SM3 HMAC checksum result
 */
void sm3_hmac_finish(Sm3_context *ctx, unsigned char output[32]);

/**
 * \brief          Output = HMAC-SM3( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   HMAC-SM3 result
 */

void sm3_hmac(unsigned char *key, int keylen, unsigned char *input, int ilen,
              unsigned char output[32]);

#ifdef __cplusplus
}
#endif
#endif