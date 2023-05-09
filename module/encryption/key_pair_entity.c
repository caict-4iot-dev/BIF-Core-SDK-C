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
 * @file: key_pair_entity.c
 */

#include "key_pair_entity.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"

int get_bid_and_key_pair(KeyPairEntity *key_pair_entity) {
  PrivateKeyManager *private_key_manager =
      (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
  memset(private_key_manager, 0, sizeof(PrivateKeyManager));
  int ret = get_private_key_manager(ED25519, private_key_manager);
  if (ret < 0) {
    printf("get_private_key_manager error\n");
    return -1;
  }

  strcpy(key_pair_entity->enc_address, private_key_manager->enc_address);
  strcpy(key_pair_entity->enc_public_key, private_key_manager->enc_public_key);
  memcpy(key_pair_entity->raw_public_key, private_key_manager->raw_public_key,
         private_key_manager->raw_public_key_len);
  key_pair_entity->raw_public_key_len = private_key_manager->raw_public_key_len;
  strcpy(key_pair_entity->enc_private_key,
         private_key_manager->enc_private_key);
  memcpy(key_pair_entity->raw_private_key, private_key_manager->raw_private_key,
         private_key_manager->raw_private_key_len);
  key_pair_entity->raw_private_key_len =
      private_key_manager->raw_private_key_len;
  sdk_free(private_key_manager);
  return 0;
}

int get_bid_and_key_pair_by_sm2(KeyPairEntity *key_pair_entity) {
  PrivateKeyManager *private_key_manager =
      (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
  memset(private_key_manager, 0, sizeof(PrivateKeyManager));
  int ret = get_private_key_manager(SM2, private_key_manager);
  if (ret < 0) {
    printf("get_private_key_manager error\n");
    return -1;
  }

  strcpy(key_pair_entity->enc_address, private_key_manager->enc_address);
  strcpy(key_pair_entity->enc_public_key, private_key_manager->enc_public_key);
  memcpy(key_pair_entity->raw_public_key, private_key_manager->raw_public_key,
         private_key_manager->raw_public_key_len);
  key_pair_entity->raw_public_key_len = private_key_manager->raw_public_key_len;
  strcpy(key_pair_entity->enc_private_key,
         private_key_manager->enc_private_key);
  memcpy(key_pair_entity->raw_private_key, private_key_manager->raw_private_key,
         private_key_manager->raw_private_key_len);
  key_pair_entity->raw_private_key_len =
      private_key_manager->raw_private_key_len;
  sdk_free(private_key_manager);
  return 0;
}