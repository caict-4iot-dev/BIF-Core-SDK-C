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
 * @file: key_pair_entity.h
 */

#ifndef __KEY_PAIR_ENTITY_H__
#define __KEY_PAIR_ENTITY_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "private_key_manager.h"
#include "public_key_manager.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct KeyPairEntitys {
  char enc_address[128];
  char enc_private_key[256];
  char enc_public_key[256];
  char raw_private_key[256];
  int raw_private_key_len;
  char raw_public_key[256];
  int raw_public_key_len;
} KeyPairEntity;

int get_bid_and_key_pair(KeyPairEntity *key_pair_entity);
int get_bid_and_key_pair_by_sm2(KeyPairEntity *key_pair_entity);

#ifdef __cplusplus
}
#endif
#endif