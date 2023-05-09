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
 * @file: crypto_manager.c
 */

#include "key_pair_entity.h"
#include "private_key_manager.h"
#include "public_key_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 生成公私钥对
  PrivateKeyManager *private_key_manager1 =
      (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
  KeyPairEntity key_pair_entity;
  memset(private_key_manager1, 0, sizeof(PrivateKeyManager));
  memset(&key_pair_entity, 0, sizeof(KeyPairEntity));

  // 创建sm2类型的
  // int ret = get_bid_and_key_pair_by_sm2(&key_pair_entity);
  // 创建默认的ED25519类型公私钥对
  int ret = get_bid_and_key_pair(&key_pair_entity);
  char raw_private_hex[256] = {0};
  char raw_public_hex[256] = {0};

  byte_to_hex_string(key_pair_entity.raw_private_key,
                     key_pair_entity.raw_private_key_len, raw_private_hex);
  byte_to_hex_string(key_pair_entity.raw_public_key,
                     key_pair_entity.raw_public_key_len, raw_public_hex);
  printf("key_pair_entity of "
         "enc_address:%s\n,enc_private_key:%s\n,enc_public_key:%s\n,raw_"
         "private_key:%s\n, raw_public_key:%s\n\n",
         key_pair_entity.enc_address, key_pair_entity.enc_private_key,
         key_pair_entity.enc_public_key, raw_private_hex, raw_public_hex);

  // 创建指定类型private_key_manager
  int res = get_private_key_manager(ED25519, private_key_manager1);
  if (res < 0) {
    printf("type error please input valid type\n");
  }
  // 根据星火私钥创建private_key_manager
  char enc_private_key_new[128] =
      "priSPKgVtTWUQuRPbjiE47s4QohxWc1svjFC6pbQyW4K3JPiae";
  PrivateKeyManager *private_key_manager_by_enc =
      (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
  memset(private_key_manager_by_enc, 0, sizeof(PrivateKeyManager));

  memcpy(private_key_manager_by_enc,
         get_private_manager_by_enc_private(enc_private_key_new),
         sizeof(PrivateKeyManager));
  if (!private_key_manager_by_enc) {
    printf("generate error please input right data\n");
    return -1;
  }
  printf("****+++******>enc_address:%s,enc_privvate:%s,type:%s\n\n",
         private_key_manager_by_enc->enc_address,
         private_key_manager_by_enc->enc_private_key,
         private_key_manager_by_enc->type_key);
  char out_raw_private[256] = {0};
  char out_raw_public[256] = {0};
  char out_sign[256] = {0};

  byte_to_hex_string(private_key_manager1->raw_private_key,
                     private_key_manager1->raw_private_key_len,
                     out_raw_private);
  byte_to_hex_string(private_key_manager1->raw_public_key,
                     private_key_manager1->raw_public_key_len, out_raw_public);

  printf("private_key_manager1 of "
         "enc_address:%s\n,enc_private_key:%s\n,enc_public_key:%s\n,raw_"
         "private_key:%s\n, raw_public_key:%s\n",
         private_key_manager1->enc_address,
         private_key_manager1->enc_private_key,
         private_key_manager1->enc_public_key, out_raw_private, out_raw_public);

  char signature[1024] = {0};
  int sign_len = 0;
  // 通过enc_private_key星火私钥签名
  char *sign_temp = sign(private_key_manager1->enc_private_key, "hello",
                         strlen("hello"), &sign_len);
  memcpy(signature, sign_temp, sign_len);
  signature[sign_len] = '\0';
  byte_to_hex_string(signature, sign_len, out_sign);

  printf("signature:%s\n", out_sign);
  char hello_hex[128] = {0};
  byte_to_hex_string("hello", strlen("hello"), hello_hex);
  printf("helo_hex:%s\n\n", hello_hex);

  // 星火公钥验签
  bool flag = false;
  flag = verify("hello", signature, sign_len,
                private_key_manager1->enc_public_key);
  if (flag) {
    printf("--verify successed\n");
  } else {
    printf("--verify failed\n");
  }

  char enc_public[256] = {0};
  char raw_public_key[256] = {0};
  char raw_public_hex0[256] = {0};
  int raw_public_key_len = 0;
  KeyTypes key_type;
  // key_type = SM2;
  key_type = ED25519;
  // 根据星火私钥获取星火公钥
  strcpy(enc_public, get_enc_public_key(private_key_manager1->enc_private_key));
  printf("--->enc_public_by_enc_pri: %s\n", enc_public);

  byte_to_hex_string(private_key_manager1->raw_public_key,
                     private_key_manager1->raw_public_key_len, raw_public_hex0);
  printf("raw_public_hex:%s\n", raw_public_hex0);

  // 根据原生公钥获取星火公钥
  char *enc_public_key = get_enc_public_key_by_raw_public(
      private_key_manager1->raw_public_key,
      private_key_manager1->raw_public_key_len, key_type);
  printf("get_enc_public_key_by_raw_public:%s\n", enc_public_key);
  int raw_public_len = 0;
  char raw_public[256] = {0};
  char raw_public_hex2[256] = {0};

  // 根据星火公钥获取原生公钥
  char *raw_public_temp =
      get_raw_public_key(private_key_manager1->enc_public_key, &raw_public_len);
  memcpy(raw_public, raw_public_temp, raw_public_len);
  raw_public[raw_public_len] = '\0';
  byte_to_hex_string(raw_public, raw_public_len, raw_public_hex2);
  printf("raw_public_by_enc_pub: %s\n", raw_public_hex2);

  // 根据星火公钥获取星火address
  char address[128] = {0};
  strcpy(address, get_enc_address(private_key_manager1->enc_public_key, ""));
  printf("--->get_enc_address:%s\n", address);

  // 星火地址校验
  char *enc_address = "did:bid:efWNykMYgqX8iBTqDpoNN3Ja8xnSX1vE";
  bool valid = is_address_valid(enc_address);
  printf("is_address_valid:%d \n", valid);

  // 根据原生私钥获取星火私钥
  char enc_private_key[256] = {0};
  strcpy(enc_private_key,
         get_enc_private_key(private_key_manager1->raw_private_key,
                             private_key_manager1->raw_private_key_len,
                             key_type));
  printf("get_enc_private_key by raw_private key:%s\n", enc_private_key);

  // 根据星火私钥获取原生私钥
  char raw_private_key_temp[256] = {0};
  char raw_pri_key_hex[256] = {0};
  int raw_len = 0;
  char *raw_private_key = get_raw_private_key(
      private_key_manager1->enc_private_key, &key_type, &raw_len);
  memcpy(raw_private_key_temp, raw_private_key, raw_len);
  byte_to_hex_string(raw_private_key_temp, raw_len, raw_pri_key_hex);
  printf("raw_pri_key_hex:%s\n", raw_pri_key_hex);

  sdk_free(private_key_manager1);
  return 0;
}