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
 * @file: key_store.c
 */
#include "key_store.h"
#include "crypto.h"
#include "libscrypt.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "private_key_manager.h"
#include "public_key_manager.h"
#include "random.h"

KEY_STORE *generate_key_store(char *enc_privateKey, char *password, uint64_t n,
                              int p, int r, int version) {
  char address[128] = {0};
  // produce random
  char salt[256] = {0};
  int salt_len = 0;
  bool empty_remalloc_flag = false;
  KEY_STORE key_store;
  memset(&key_store, 0, sizeof(KEY_STORE));
  int flag = get_strong_rand_bytes(salt, &salt_len);

  char aes_iv_temp[64] = {0};
  char aes_iv[17] = {0};
  int iv_len = 0;
  int flag_iv = get_strong_rand_bytes(aes_iv_temp, &iv_len);
  memcpy(aes_iv, aes_iv_temp, 16);
  aes_iv[16] = '\0';
  iv_len = 16;
  // produce n p r
  // uint64_t n = 16384;
  // uint32_t r = 8;
  // uint32_t p = 1;
  int dk_len = 32;
  char dk[33] = {0};
  if (!password) {
    return NULL;
  } else if (strlen(password) == 0) {
    return NULL;
  }
  if (n < 0 || r < 0 || p < 0 || version < 0) {
    return NULL;
  }
  if (enc_privateKey != NULL && strlen(enc_privateKey) != 0) {
    PrivateKeyManager *private_manager =
        (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
    memset(private_manager, 0, sizeof(PrivateKeyManager));
    memcpy(private_manager, get_private_manager_by_enc_private(enc_privateKey),
           sizeof(PrivateKeyManager));
    strcpy(address, private_manager->enc_address);

  } else {
    PrivateKeyManager *private_key_manager =
        (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
    memset(private_key_manager, 0, sizeof(PrivateKeyManager));
    int ret = get_private_key_manager(ED25519, private_key_manager);
    strcpy(address, private_key_manager->enc_address);
    enc_privateKey = (char *)malloc(256);
    memset(enc_privateKey, 0, sizeof(256));
    empty_remalloc_flag = true;

    strcpy(enc_privateKey, private_key_manager->enc_private_key);
  }

  int res =
      libscrypt_scrypt((uint8_t *)password, strlen(password), (uint8_t *)salt,
                       salt_len, n, r, p, (uint8_t *)dk, dk_len);
  AES_CTR aes_ctr;
  memset(&aes_ctr, 0, sizeof(AES_CTR));
  aes_init(aes_iv, dk, &aes_ctr);

  unsigned char out_data[256] = {0};
  char salt_hex_str[128] = {0};
  char iv_hex_str[128] = {0};
  char cyper_text_hex_str[256] = {0};

  lib_encrypt(enc_privateKey, &aes_ctr, out_data, strlen(enc_privateKey));
  key_store.version = version;
  key_store.scrypt_params.n = n;
  key_store.scrypt_params.p = p;
  key_store.scrypt_params.r = r;
  byte_to_hex_string(salt, salt_len, salt_hex_str);
  byte_to_hex_string(aes_iv, iv_len, iv_hex_str);
  // byte_to_hex_string(out_data, strlen(out_data), cyper_text_hex_str);
  byte_to_hex_string(out_data, 50, cyper_text_hex_str);
  memset(key_store.scrypt_params.salt, 0, sizeof(key_store.scrypt_params.salt));
  strcpy(key_store.scrypt_params.salt, salt_hex_str);
  strcpy(key_store.address, address);
  strcpy(key_store.aesctr_iv, iv_hex_str);
  strcpy(key_store.cypher_text, cyper_text_hex_str);
  if (empty_remalloc_flag) {
    sdk_free(enc_privateKey);
  }
  sdk_free(aes_ctr.key);
  return &key_store;
}

char *decipher_key_store(char *password, KEY_STORE *key_store) {
  char salt[512] = {0};
  int salt_byte_len = 0;
  char aesctr_iv[33] = {0};
  int aesctr_iv_byte_len = 0;
  char cypher_text[256] = {0};
  int cypher_text_byte_len = 0;
  int32_t nkey_len = 16;
  int dk_len = 32;
  char dk[33] = {0};

  if (!password) {
    return NULL;
  } else if (strlen(password) == 0) {
    return NULL;
  }
  if (!key_store) {
    return NULL;
  } else if (key_store->scrypt_params.n < 0) {
    return NULL;
  } else if (key_store->scrypt_params.p < 0) {
    return NULL;
  } else if (key_store->scrypt_params.r < 0) {
    return NULL;
  } else if (key_store->version < 0) {
    return NULL;
  }
  uint64_t n = key_store->scrypt_params.n;
  uint32_t r = key_store->scrypt_params.r;
  uint32_t p = key_store->scrypt_params.p;
  int32_t version = key_store->version;
  hex_string_to_byte(key_store->scrypt_params.salt, salt, &salt_byte_len);
  salt[salt_byte_len] = '\0';
  hex_string_to_byte(key_store->aesctr_iv, aesctr_iv, &aesctr_iv_byte_len);
  aesctr_iv[aesctr_iv_byte_len] = '\0';
  hex_string_to_byte(key_store->cypher_text, cypher_text,
                     &cypher_text_byte_len);
  cypher_text[cypher_text_byte_len] = '\0';
  int res =
      libscrypt_scrypt((uint8_t *)password, strlen(password), (uint8_t *)salt,
                       salt_byte_len, n, r, p, (uint8_t *)dk, dk_len);
  dk[dk_len] = '\0';
  if (res == -1) {
    printf("res decipher_key_store:%d,passwd error\n", res);
    return NULL;
  }
  AES_CTR aes_ctr;
  memset(&aes_ctr, 0, sizeof(AES_CTR));
  aes_init(aesctr_iv, dk, &aes_ctr);
  unsigned char *out_data = (unsigned char *)malloc(256);
  memset(out_data, 0, 256);
  lib_encrypt(cypher_text, &aes_ctr, out_data, cypher_text_byte_len);
  sdk_free(aes_ctr.key);
  return out_data;
}