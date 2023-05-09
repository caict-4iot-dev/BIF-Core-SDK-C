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
 * @file: key_store.h
 */

#ifndef __KEYSTORE_H__
#define __KEYSTORE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct scrypt_paramss {
  int n;
  int p;
  int r;
  char salt[128];
} SCRYPT_PARAMS;

typedef struct key_stores {
  char address[128];
  char aesctr_iv[128];
  char cypher_text[256];
  SCRYPT_PARAMS scrypt_params;
  int version;
} KEY_STORE;

KEY_STORE *generate_key_store(char *enc_privateKey, char *password, uint64_t n,
                              int p, int r, int version);
char *decipher_key_store(char *password, KEY_STORE *key_store);

#ifdef __cplusplus
}
#endif
#endif