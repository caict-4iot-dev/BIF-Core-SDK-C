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
 * @file: public_key_manager.h
 */

#ifndef __PUBLIC_KEY_MANAGER_H__
#define __PUBLIC_KEY_MANAGER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "private_key_manager.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

char *get_public_by_enc_private(const char *enc_private_Key, KeyTypes *key_type,
                                char *raw_public_key, int *raw_public_len);
// 根据星火私钥获取星火公钥
char *get_enc_public_key(const char *enc_private_Key);
// 原生公钥获取星火公钥
char *get_enc_public_key_by_raw_public(const char *raw_public_key,
                                       int raw_public_len, KeyTypes key_type);
char *encode_address(char *address_temp, int addr_tmp_len,
                     const char *chain_code, KeyTypes key_type);
// 获取星火地址
char *get_enc_address(const char *enc_public_key, const char *chain_code);
char *get_enc_address_by_raw_pkey(const char *raw_public_key,
                                  int raw_public_len, const char *chain_code,
                                  KeyTypes key_type);

// 根据星火公钥获取原生公钥
char *get_raw_public_key(const char *enc_public_key, int *raw_public_len);
// 原生地址是否可用
bool is_address_valid(const char *enc_address);
// 星火公钥验签msg数据
bool verify(char *msg, char *sign_msg, int sign_msg_len, char *enc_public_key);
bool verify_test(char *msg, char *sign_msg,
                 PrivateKeyManager private_key_manager);

#ifdef __cplusplus
}
#endif
#endif