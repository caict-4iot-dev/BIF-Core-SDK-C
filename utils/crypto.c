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
 * @file: crypto.c
 */
#include "crypto.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include <stdint.h>

typedef uint64_t base58_maxint_t;
typedef uint32_t base58_almostmaxint_t;
#define base58_almostmaxint_bits (sizeof(base58_almostmaxint_t) * 8)
static const base58_almostmaxint_t base58_almostmaxint_mask =
    ((((base58_maxint_t)1) << base58_almostmaxint_bits) - 1);

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i)                                                  \
  {                                                                            \
    (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) |        \
          ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]);            \
  }
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                                                  \
  {                                                                            \
    (b)[(i)] = (unsigned char)((n) >> 24);                                     \
    (b)[(i) + 1] = (unsigned char)((n) >> 16);                                 \
    (b)[(i) + 2] = (unsigned char)((n) >> 8);                                  \
    (b)[(i) + 3] = (unsigned char)((n));                                       \
  }
#endif

// sha256 of method
char *base58_encode(unsigned char *input, int input_len) {
  size_t len = input_len;
  size_t rlen = (len / 2 + 1) * 3;
  unsigned char *ret = malloc(rlen + len);
  unsigned char *src = ret + rlen;
  unsigned char *rptr = ret + rlen;
  unsigned char *ptr, *e = src + len - 1;
  size_t i;
  memcpy(src, input, len);
  while (src <= e) {
    if (*src) {
      unsigned char rest = 0;
      ptr = src;
      while (ptr <= e) {
        unsigned int c = rest * 256;
        rest = (c + *ptr) % 58;
        *ptr = (c + *ptr) / 58;
        ptr++;
      }
      --rptr;
      *rptr = nb58[rest];
    } else {
      src++;
    }
  }
  for (i = 0; i < ret + rlen - rptr; i++)
    ret[i] = rptr[i];
  ret[i] = 0;
  return ret;
}

char *base58_decode(unsigned char *src, int *decode_len) {
  size_t len = strlen(src);
  size_t rlen = (len / 4 + 1) * 3;
  unsigned char *ret = malloc(rlen);
  unsigned char *rptr = ret + rlen;
  size_t i;
  unsigned char *ptr;
  for (i = 0; i < len; i++) {
    char rest = b58n[src[i]];
    if (rest < 0) {
      free(ret);
      return NULL;
    }
    for (ptr = ret + rlen - 1; ptr >= rptr; ptr--) {
      unsigned int c = rest + *ptr * 58;
      *ptr = c % 256;
      rest = c / 256;
    }
    if (rest > 0) {
      rptr--;
      if (rptr < ret) {
        free(ret);
        return NULL;
      }
      *rptr = rest;
    }
  }
  for (i = 0; i < ret + rlen - rptr; i++)
    ret[i] = rptr[i];
  ret[i] = 0;
  *decode_len = i;
  return ret;
}

void sha256_crypto(const char *str, int len, char *buf) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, str, len);
  SHA256_Final(buf, &sha256);
}

char *sha256_crypto_base58(const char *input, int len, char *buf) {
  char *temp = NULL;
  sha256_crypto(input, len, temp);
  size_t binsz = strlen(temp);
  size_t b58sz = binsz * 2;
  strcpy(buf, base58_encode((unsigned char *)temp, binsz));
  // base58_encode(buf, &b58sz, temp, binsz)
  if (buf) {
    return buf;
  }
  return NULL;
}
// void Sha256Update(const void *buffer, size_t len);
// char* Sha256Final();

void aes_init(unsigned char *iv, const char *ckey, AES_CTR *aes_ctr) {
  memcpy(aes_ctr->iv, iv, 16);
  aes_ctr->iv[16] = '\0';
  aes_ctr->iv_len = 16;
  memcpy(aes_ctr->ckey, ckey, 32);
  aes_ctr->ckey[32] = '\0';
  aes_ctr->ckey_len = 32;
  aes_ctr->key = (AES_KEY *)malloc(sizeof(AES_KEY));
  aes_ctr->key_valid = true;
}

int init_ctr(CTR_STATE *state, const unsigned char iv[17]) {
  state->num = 0;
  memset(state->ecount, 0, AES_BLOCK_SIZE);
  memcpy(state->ivec, iv, 16);
  state->ivec[16] = '\0';
  return 0;
}
void lib_encrypt(unsigned char *in_data, AES_CTR *aes_ctr,
                 unsigned char *out_data, int bytes_read) {
  int i = 0;
  int mod_len = 0;

  AES_set_encrypt_key((const unsigned char *)aes_ctr->ckey,
                      aes_ctr->ckey_len * 8, aes_ctr->key);

  if (bytes_read < BYTES_SIZE) {
    CTR_STATE state;
    memset(&state, 0, sizeof(CTR_STATE));
    init_ctr(&state, aes_ctr->iv);
    AES_ctr128_encrypt(in_data, out_data, bytes_read, aes_ctr->key, state.ivec,
                       state.ecount, &state.num);
    return;
  }
  // loop block size  = [ BYTES_SIZE ]
  for (i = BYTES_SIZE; i <= bytes_read; i += BYTES_SIZE) {
    CTR_STATE state;
    memset(&state, 0, sizeof(CTR_STATE));
    init_ctr(&state, aes_ctr->iv);
    AES_ctr128_encrypt(in_data, out_data, BYTES_SIZE, aes_ctr->key, state.ivec,
                       state.ecount, &state.num);
    in_data += BYTES_SIZE;
    out_data += BYTES_SIZE;
  }

  mod_len = bytes_read % BYTES_SIZE;
  if (mod_len != 0) {
    CTR_STATE state;
    memset(&state, 0, sizeof(CTR_STATE));
    init_ctr(&state, aes_ctr->iv);
    AES_ctr128_encrypt(in_data, out_data, mod_len, aes_ctr->key, state.ivec,
                       state.ecount, &state.num);
  }
}

void sm3_crypto(const char *str, int len, unsigned char *buf) {
  Sm3_context sm3_ctx;
  sm3_starts(&sm3_ctx);
  sm3_update(&sm3_ctx, (unsigned char *)str, len);
  sm3_finish(&sm3_ctx, buf);
}
char *sm3_crypto_base58(const char *input, int len, char *buf) {
  char *temp = NULL;
  sm3_crypto(input, len, temp);
  size_t binsz = strlen(temp);
  size_t b58sz = binsz * 2;
  strcpy(buf, base58_encode((unsigned char *)temp, binsz));
  // base58_encode(buf, &b58sz, temp, binsz)
  return buf;
}

/*
 * SM3 context setup
 */
void sm3_starts(Sm3_context *ctx) {
  ctx->total[0] = 0;
  ctx->total[1] = 0;

  ctx->state[0] = 0x7380166F;
  ctx->state[1] = 0x4914B2B9;
  ctx->state[2] = 0x172442D7;
  ctx->state[3] = 0xDA8A0600;
  ctx->state[4] = 0xA96F30BC;
  ctx->state[5] = 0x163138AA;
  ctx->state[6] = 0xE38DEE4D;
  ctx->state[7] = 0xB0FB0E4E;
}

void sm3_process(Sm3_context *ctx, unsigned char data[64]) {
  uint32_t SS1, SS2, TT1, TT2, W[68], W1[64];
  uint32_t A, B, C, D, E, F, G, H;
  uint32_t T[64];
  uint32_t Temp1, Temp2, Temp3, Temp4, Temp5;
  int j;
  /*
  #ifdef _DEBUG
  int i;
  #endif
  */
  //  for(j=0; j < 68; j++)
  //      W[j] = 0;
  //  for(j=0; j < 64; j++)
  //      W1[j] = 0;

  for (j = 0; j < 16; j++)
    T[j] = 0x79CC4519;
  for (j = 16; j < 64; j++)
    T[j] = 0x7A879D8A;

  GET_ULONG_BE(W[0], data, 0); // W[0]=data[0] data[1] data[2] data[3]
  GET_ULONG_BE(W[1], data, 4);
  GET_ULONG_BE(W[2], data, 8);
  GET_ULONG_BE(W[3], data, 12);
  GET_ULONG_BE(W[4], data, 16);
  GET_ULONG_BE(W[5], data, 20);
  GET_ULONG_BE(W[6], data, 24);
  GET_ULONG_BE(W[7], data, 28);
  GET_ULONG_BE(W[8], data, 32);
  GET_ULONG_BE(W[9], data, 36);
  GET_ULONG_BE(W[10], data, 40);
  GET_ULONG_BE(W[11], data, 44);
  GET_ULONG_BE(W[12], data, 48);
  GET_ULONG_BE(W[13], data, 52);
  GET_ULONG_BE(W[14], data, 56);
  GET_ULONG_BE(W[15], data, 60);
  /*
  #ifdef _DEBUG
  printf("Message with padding:\n");
  for (i = 0; i < 8; i++)
  printf("%08x ", W[i]);
  printf("\n");
  for (i = 8; i < 16; i++)
  printf("%08x ", W[i]);
  printf("\n");
  #endif
  */

#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

#define SHL(x, n) (((x)&0xFFFFFFFF) << n)
#define ROTL(x, n) (SHL((x), n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))
  for (j = 16; j < 68; j++) {
    // W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^
    // W[j-6]; Why thd release's result is different with the debug's ? Below is
    // okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.

    Temp1 = W[j - 16] ^ W[j - 9];
    Temp2 = ROTL(W[j - 3], 15);
    Temp3 = Temp1 ^ Temp2;
    Temp4 = P1(Temp3);
    Temp5 = ROTL(W[j - 13], 7) ^ W[j - 6];
    W[j] = Temp4 ^ Temp5;
  }

  /*
  #ifdef _DEBUG
  printf("Expanding message W0-67:\n");
  for (i = 0; i < 68; i++)
  {
  printf("%08x ", W[i]);
  if (((i + 1) % 8) == 0) printf("\n");
  }
  printf("\n");
  #endif
  */

  for (j = 0; j < 64; j++) {
    W1[j] = W[j] ^ W[j + 4];
  }

  /*#ifdef _DEBUG
  printf("Expanding message W'0-63:\n");
  for (i = 0; i < 64; i++)
  {
  printf("%08x ", W1[i]);
  if (((i + 1) % 8) == 0) printf("\n");
  }
  printf("\n");
  #endif
  */

  A = ctx->state[0];
  B = ctx->state[1];
  C = ctx->state[2];
  D = ctx->state[3];
  E = ctx->state[4];
  F = ctx->state[5];
  G = ctx->state[6];
  H = ctx->state[7];
  // #ifdef _DEBUG
  //		printf("j     A       B        C         D         E        F G
  // H\n"); 		printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",
  // A, B, C, D, E, F, G, H); #endif

  for (j = 0; j < 16; j++) {
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF0(A, B, C) + D + SS2 + W1[j];
    TT2 = GG0(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
    // #ifdef _DEBUG
    //			printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",
    // j, A, B, C, D, E, F, G, H); #endif
  }

  for (j = 16; j < 64; j++) {
    SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
    SS2 = SS1 ^ ROTL(A, 12);
    TT1 = FF1(A, B, C) + D + SS2 + W1[j];
    TT2 = GG1(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTL(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTL(F, 19);
    F = E;
    E = P0(TT2);
    // #ifdef _DEBUG
    //			printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",
    // j, A, B, C, D, E, F, G, H); #endif
  }

  ctx->state[0] ^= A;
  ctx->state[1] ^= B;
  ctx->state[2] ^= C;
  ctx->state[3] ^= D;
  ctx->state[4] ^= E;
  ctx->state[5] ^= F;
  ctx->state[6] ^= G;
  ctx->state[7] ^= H;
  // #ifdef _DEBUG
  //		printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",
  // ctx->state[0], ctx->state[1], ctx->state[2],
  // ctx->state[3], ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7]);
  // #endif
}

/*
 * SM3 process buffer
 */
void sm3_update(Sm3_context *ctx, unsigned char *input, int ilen) {
  int fill;
  uint32_t left;

  if (ilen <= 0)
    return;

  left = ctx->total[0] & 0x3F;
  fill = 64 - left;

  ctx->total[0] += ilen;
  ctx->total[0] &= 0xFFFFFFFF;

  if (ctx->total[0] < (uint32_t)ilen)
    ctx->total[1]++;

  if (left && ilen >= fill) {
    memcpy((void *)(ctx->buffer + left), (void *)input, fill);
    sm3_process(ctx, ctx->buffer);
    input += fill;
    ilen -= fill;
    left = 0;
  }

  while (ilen >= 64) {
    sm3_process(ctx, input);
    input += 64;
    ilen -= 64;
  }

  if (ilen > 0) {
    memcpy((void *)(ctx->buffer + left), (void *)input, ilen);
  }
}

static const unsigned char sm3_padding[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/*
 * SM3 final digest
 */
void sm3_finish(Sm3_context *ctx, unsigned char output[32]) {
  uint32_t last, padn;
  uint32_t high, low;
  unsigned char msglen[8];

  high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
  low = (ctx->total[0] << 3);

  PUT_ULONG_BE(high, msglen, 0);
  PUT_ULONG_BE(low, msglen, 4);

  last = ctx->total[0] & 0x3F;
  padn = (last < 56) ? (56 - last) : (120 - last);

  sm3_update(ctx, (unsigned char *)sm3_padding, padn);
  sm3_update(ctx, msglen, 8);

  PUT_ULONG_BE(ctx->state[0], output, 0);
  PUT_ULONG_BE(ctx->state[1], output, 4);
  PUT_ULONG_BE(ctx->state[2], output, 8);
  PUT_ULONG_BE(ctx->state[3], output, 12);
  PUT_ULONG_BE(ctx->state[4], output, 16);
  PUT_ULONG_BE(ctx->state[5], output, 20);
  PUT_ULONG_BE(ctx->state[6], output, 24);
  PUT_ULONG_BE(ctx->state[7], output, 28);
}

/*
 * SM3 HMAC context setup
 */
void sm3_hmac_starts(Sm3_context *ctx, unsigned char *key, int keylen) {
  int i;
  unsigned char sum[32];

  if (keylen > 64) {
    sm3_crypto(key, keylen, sum);
    keylen = 32;
    // keylen = ( is224 ) ? 28 : 32;
    key = sum;
  }

  memset(ctx->ipad, 0x36, 64);
  memset(ctx->opad, 0x5C, 64);

  for (i = 0; i < keylen; i++) {
    ctx->ipad[i] = (unsigned char)(ctx->ipad[i] ^ key[i]);
    ctx->opad[i] = (unsigned char)(ctx->opad[i] ^ key[i]);
  }

  sm3_starts(ctx);
  sm3_update(ctx, (unsigned char *)ctx->ipad, 64);

  memset(sum, 0, sizeof(sum));
}

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update(Sm3_context *ctx, unsigned char *input, int ilen) {
  sm3_update(ctx, input, ilen);
}

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish(Sm3_context *ctx, unsigned char output[32]) {
  int hlen;
  unsigned char tmpbuf[32];

  // is224 = ctx->is224;
  hlen = 32;

  sm3_finish(ctx, tmpbuf);
  sm3_starts(ctx);
  sm3_update(ctx, (unsigned char *)ctx->opad, 64);
  sm3_update(ctx, tmpbuf, hlen);
  sm3_finish(ctx, output);

  memset(tmpbuf, 0, sizeof(tmpbuf));
}

/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac(unsigned char *key, int keylen, unsigned char *input, int ilen,
              unsigned char output[32]) {
  Sm3_context ctx;

  sm3_hmac_starts(&ctx, key, keylen);
  sm3_hmac_update(&ctx, input, ilen);
  sm3_hmac_finish(&ctx, output);
  memset(&ctx, 0, sizeof(Sm3_context));
}