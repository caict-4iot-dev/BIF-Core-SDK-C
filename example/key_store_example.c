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
 * @file: key_store_example.c
 */

// #include "general.h"
#include "key_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  // generate_key_store
  char enc_private_key[128] =
      "priSPKepT8DV8wTAYiAU6LjUPQFqdzN9ndcVPMv9cgNeTBYQ6V";

  char password[64] = "12334";
  int version = 65535;
  KEY_STORE *key_store = (KEY_STORE *)malloc(sizeof(KEY_STORE));
  memset(key_store, 0, sizeof(KEY_STORE));
  uint64_t n = 16384;
  uint32_t r = 8;
  uint32_t p = 1;
  printf("generate_key_store of private_key:%s\n\n", enc_private_key);
  KEY_STORE *key_store_temp =
      generate_key_store(enc_private_key, password, n, p, r, version);
  if (!key_store_temp) {
    printf("generate key failed\n");
    return -1;
  }
  strcpy(key_store->address, key_store_temp->address);
  strcpy(key_store->aesctr_iv, key_store_temp->aesctr_iv);
  strcpy(key_store->cypher_text, key_store_temp->cypher_text);
  strcpy(key_store->scrypt_params.salt, key_store_temp->scrypt_params.salt);
  key_store->version = key_store_temp->version;
  key_store->scrypt_params.n = key_store_temp->scrypt_params.n;
  key_store->scrypt_params.r = key_store_temp->scrypt_params.r;
  key_store->scrypt_params.p = key_store_temp->scrypt_params.p;

  printf("address:%s\n,aesctr_iv:%s\n,cypher_text:%s\n,version:%d\n,salt:%s\n,"
         "n:%d\n,r:%d\n,p:%d\n\n",
         key_store->address, key_store->aesctr_iv, key_store->cypher_text,
         key_store->version, key_store->scrypt_params.salt,
         key_store->scrypt_params.n, key_store->scrypt_params.r,
         key_store->scrypt_params.p);

  // 根据keystore生成对应私钥,keystore结构体可以自定义赋值，此处直接用的上个接口生成的key_store
  char private[256] = {0};
  char *res_decipher = decipher_key_store(password, key_store);
  if (!res_decipher) {
    printf("decipher_key_store of private_key error return NULL\n");
  }
  strcpy(private, res_decipher);
  printf("decipher_key_store of private_key:%s\n", private);
  sdk_free(res_decipher);

  return 0;
}