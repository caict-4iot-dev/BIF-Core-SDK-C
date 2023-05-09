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
 * @date: 2023-03-01 16:16:36
 * @file: ecc_sm2.h
 */

#ifndef __ECC_SM2_H__
#define __ECC_SM2_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum {
  GFP = 0,
  F2M = 1,
} GROUP_TYPE;

struct BIGNUM;
struct EC_POINT;
struct EC_GROUP;

typedef struct {
  bool valid;
  struct BIGNUM *da;     // Private key
  struct EC_POINT *pkey; // Public key
  char skey_bin[256];
  int skey_len;
  char error[256];
  struct EC_GROUP *group;
  struct EC_GROUP *cfca_group;
} SM2_DATA;

void init(SM2_DATA *sm2_data, struct EC_GROUP *curv);
void sm2_free(SM2_DATA sm2_data);
struct EC_GROUP *get_cfca_group();
char *bn2_fixed_string(struct BIGNUM *bn, int len, int *out_len);
struct EC_GROUP *new_group(GROUP_TYPE type, char *phex, char *ahex, char *bhex,
                           char *xGhex, char *yGhex, char *nhex);
char *get_za(struct EC_GROUP *group, char *id, const struct EC_POINT *pkey);
bool from_skey_bin(char *skey_bin, int skey_len, SM2_DATA *sm2_data);
bool new_random(SM2_DATA *sm2_data);
char *get_skey_bin(struct BIGNUM *dA, int *out_len);
char *sign_sm2(const char *id, const char *msg, int msg_len, SM2_DATA sm2_data,
               int *out_len);

int verify_sm2(struct EC_GROUP *group, const char *pkey, int pkey_len,
               const char *id, const char *msg, const char *strsig,
               int sig_len);
char *get_public_key_sm2(SM2_DATA sm2_data, int *out_len);

#ifdef __cplusplus
}
#endif
#endif