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
 * @file: private_key_manager.h
 */

#ifndef __PRIVATE_KEY_MANAGER_H__
#define __PRIVATE_KEY_MANAGER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// #include "key_pair_entity.h"
#define ED25519_VALUE 'e'
#define SM2_VALUE 'z'
#define BASE_58_VALUE 'f'

typedef struct {
  char type_key[16];
  char enc_address[128];
  char enc_private_key[256];
  char raw_private_key[256];
  int raw_private_key_len;
  char raw_public_key[256];
  int raw_public_key_len;
  char enc_public_key[256];
} PrivateKeyManager;

typedef enum KeyType {
  ED25519,
  SM2,
} KeyTypes;

int get_private_key_manager(KeyTypes key_type,
                            PrivateKeyManager *private_key_manager);
// 根据原生私钥获取星火私钥
char *get_enc_private_key(const char *raw_private_key, int raw_private_len,
                          KeyTypes key_type);
// 根据星火私钥获取原生私钥
char *get_raw_private_key(const char *enc_private_key, KeyTypes *key_type,
                          int *raw_len);
// 私钥签名
char *sign(char *enc_private_key, char *message, int message_len, int *out_len);
char *sign_test(PrivateKeyManager private_key_manager, char *message);
PrivateKeyManager *get_private_manager_by_enc_private(char *enc_private_key);

#ifdef __cplusplus
}
#endif
#endif