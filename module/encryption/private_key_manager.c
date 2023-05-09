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
 * @file: private_key_manager.c
 */
#include "private_key_manager.h"
#include "crypto.h"
#include "curl/curl.h"
#include "ecc_sm2.h"
#include "ed25519.h"
#include "general.h"
#include "openssl/aes.h"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ec.h"
#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "public_key_manager.h"
#include "random.h"
#include "util.h"


extern EC_GROUP *cfca_group_;
int get_private_key_manager(KeyTypes key_type,
                            PrivateKeyManager *private_key_manager) {
  char raw_public_key[256] = {0};
  char raw_private_key[256] = {0};
  char type_key[32] = {0};
  char temp_private[32] = {0};
  bool private_flag = false;
  SM2_DATA sm2_data;
  int raw_private_len = 0, sm2_data_len = 0;
  if (!private_key_manager) {
    return -1;
  }
  switch (key_type) {
  case ED25519:
    private_flag = get_strong_rand_bytes(raw_private_key, &raw_private_len);
    if (!private_flag) {
      return -1;
    }
    ed25519_publickey((const unsigned char *)raw_private_key,
                      (unsigned char *)raw_public_key);
    sm2_data_len = 32;
    strcpy(type_key, "ed25519");
    break;
  case SM2:
    get_cfca_group();
    init(&sm2_data, cfca_group_);
    bool flag_random = new_random(&sm2_data);

    char *temp_raw_private = get_skey_bin(sm2_data.da, &raw_private_len);
    memcpy(raw_private_key, temp_raw_private, raw_private_len);
    raw_private_key[raw_private_len] = '\0';
    if (temp_raw_private)
      free(temp_raw_private);

    char *temp_raw_public = get_public_key_sm2(sm2_data, &sm2_data_len);
    memcpy(raw_public_key, temp_raw_public, sm2_data_len);
    raw_public_key[sm2_data_len] = '\0';
    if (temp_raw_public)
      free(temp_raw_public);
    strcpy(type_key, "sm2");
    break;
  default:
    return -1;
  }
  strcpy(
      private_key_manager->enc_address,
      get_enc_address_by_raw_pkey(raw_public_key, sm2_data_len, "", key_type));
  memcpy(private_key_manager->raw_private_key, raw_private_key,
         raw_private_len);
  private_key_manager->raw_private_key[raw_private_len] = '\0';
  private_key_manager->raw_private_key_len = raw_private_len;

  strcpy(private_key_manager->enc_private_key,
         get_enc_private_key(raw_private_key, raw_private_len,
                             key_type)); // sigsegv
  memcpy(private_key_manager->raw_public_key, raw_public_key, sm2_data_len);
  private_key_manager->raw_public_key[sm2_data_len] = '\0';
  private_key_manager->raw_public_key_len = sm2_data_len;

  char *enc_public_temp =
      get_enc_public_key_by_raw_public(raw_public_key, sm2_data_len, key_type);
  memcpy(private_key_manager->enc_public_key, enc_public_temp,
         strlen(enc_public_temp));
  private_key_manager->enc_public_key[strlen(enc_public_temp)] = '\0';
  if (enc_public_temp)
    free(enc_public_temp);
  strcpy(private_key_manager->type_key, type_key);

  return 0;
}

// 原生私钥转星火私钥
char *get_enc_private_key(const char *raw_private_key, int raw_private_len,
                          KeyTypes key_type) {
  char buf_private[256] = {0};
  buf_private[0] = 0x18;
  buf_private[1] = 0x9E;
  buf_private[2] = 0x99;

  if (!raw_private_key) {
    return NULL;
  } else if (raw_private_len == 0) {
    return NULL;
  }
  switch (key_type) {
  case ED25519:
    buf_private[3] = ED25519_VALUE;
    break;
  case SM2:
    buf_private[3] = SM2_VALUE;
    break;
  default:
    return NULL;
  }
  buf_private[4] = BASE_58_VALUE;
  // buf_private[5] = '\0';
  memcpy(buf_private + 5, raw_private_key, raw_private_len);
  int pri_len = raw_private_len + 5;
  buf_private[pri_len] = '\0';
  char b58[256] = {0};
  strcpy(b58, base58_encode(buf_private, pri_len));
  return b58;
}

// 星火私钥转原生私钥
char *get_raw_private_key(const char *enc_private_key, KeyTypes *key_type,
                          int *raw_len) {
  char raw_private_key[256] = {0};
  size_t out_len = 0;
  int decode_len = 0;
  if (!enc_private_key) {
    return NULL;
  } else if (strlen(enc_private_key) == 0) {
    return NULL;
  }
  char *d58 = base58_decode((unsigned char *)enc_private_key, &decode_len);
  memcpy(raw_private_key, d58, decode_len);
  raw_private_key[decode_len] = '\0';
  if (d58)
    free(d58);
  if (raw_private_key[3] != ED25519_VALUE && raw_private_key[3] != SM2_VALUE) {
    printf("error enc_private_key !ED25519_VALUE or !SM2\n");
    return NULL;
  }
  switch (raw_private_key[3]) {
  case ED25519_VALUE:
    *key_type = ED25519;
    break;
  case SM2_VALUE:
    *key_type = SM2;
    break;
  default:
    return NULL;
  }
  if (raw_private_key[4] != BASE_58_VALUE)
    return NULL;

  char *raw_private_key_final = (char *)malloc(256);
  memset(raw_private_key_final, 0, 256);
  // snprintf(raw_private_key_final , strlen(raw_private_key) + 1,"%s",
  // &raw_private_key[5]);
  memcpy(raw_private_key_final, raw_private_key + 5, decode_len - 5);
  raw_private_key_final[decode_len - 5] = '\0';
  *raw_len = decode_len - 5;
  return raw_private_key_final;
}

char *sign(char *enc_private_key, char *message, int message_len,
           int *out_len) {
  KeyTypes key_type;
  unsigned char sig[1024];
  // unsigned int sig_len = 64;
  char *sig_final = (char *)malloc(256);
  memset(sig_final, 0, 256);

  if (!enc_private_key || !message) {
    return NULL;
  }
  if (strlen(enc_private_key) == 0 || message_len == 0) {
    return NULL;
  }
  PrivateKeyManager *private_key_manager =
      (PrivateKeyManager *)malloc(sizeof(PrivateKeyManager));
  memset(private_key_manager, 0, sizeof(PrivateKeyManager));
  PrivateKeyManager *private_key_manager_temp =
      get_private_manager_by_enc_private(enc_private_key);
  if (!private_key_manager_temp) {
    sdk_free(private_key_manager);
    return NULL;
  }
  memcpy(private_key_manager, private_key_manager_temp,
         sizeof(PrivateKeyManager));

  if (strstr(private_key_manager->type_key, "ed25519")) {
    printf("=====ed25519 \n");
    ed25519_sign((unsigned char *)message, message_len,
                 (const unsigned char *)private_key_manager->raw_private_key,
                 (unsigned char *)private_key_manager->raw_public_key, sig);
    *out_len = 64;
    memcpy(sig_final, sig, *out_len);
    sig_final[*out_len] = '\0';
    if (private_key_manager)
      sdk_free(private_key_manager);
    return sig_final;
  } else if (strstr(private_key_manager->type_key, "sm2")) {
    SM2_DATA sm2_data;
    get_cfca_group();
    init(&sm2_data, cfca_group_);
    from_skey_bin(private_key_manager->raw_private_key,
                  private_key_manager->raw_private_key_len, &sm2_data);
    if (private_key_manager)
      sdk_free(private_key_manager);
    return sign_sm2("1234567812345678", message, message_len, sm2_data,
                    out_len);
  } else {
    printf("Failed to verify.Unknown signature type\n");
  }
  return sig_final;
}

PrivateKeyManager *get_private_manager_by_enc_private(char *enc_private_key) {
  char raw_public_key[256] = {0};
  int raw_public_key_len = 0;
  KeyTypes key_type;
  PrivateKeyManager private_manager;
  int raw_len = 0;

  if (!enc_private_key) {
    return NULL;
  } else if (strlen(enc_private_key) == 0) {
    return NULL;
  }
  strcpy(private_manager.enc_private_key, enc_private_key);
  char *enc_publickey_temp = get_public_by_enc_private(
      enc_private_key, &key_type, raw_public_key, &raw_public_key_len);
  if (!enc_publickey_temp) {
    return NULL;
  }
  strcpy(private_manager.enc_public_key, enc_publickey_temp);
  char *enc_address_temp = get_enc_address_by_raw_pkey(
      raw_public_key, raw_public_key_len, "", key_type);
  if (!enc_address_temp) {
    return NULL;
  }
  strcpy(private_manager.enc_address, enc_address_temp);
  memcpy(private_manager.raw_public_key, raw_public_key, raw_public_key_len);
  private_manager.raw_public_key[raw_public_key_len] = '\0';
  private_manager.raw_public_key_len = raw_public_key_len;
  char *raw_temp = get_raw_private_key(enc_private_key, &key_type, &raw_len);
  if (!raw_temp) {
    return NULL;
  }
  memcpy(private_manager.raw_private_key, raw_temp, raw_len);
  private_manager.raw_private_key[raw_len] = '\0';
  private_manager.raw_private_key_len = raw_len;
  if (raw_temp)
    free(raw_temp);

  switch (key_type) {
  case ED25519:
    strcpy(private_manager.type_key, "ed25519");
    break;
  case SM2:
    strcpy(private_manager.type_key, "sm2");
    break;
  default:
    return NULL;
  }

  return &private_manager;
}

char *sign_test(PrivateKeyManager private_key_manager, char *message) {
  KeyTypes key_type;
  unsigned char sig[10240];
  char raw_private_key[256] = {0};
  unsigned int sig_len = 64;
  char sig_final[64] = {0};

  ed25519_sign((unsigned char *)message, strlen(message),
               (const unsigned char *)private_key_manager.raw_private_key,
               (unsigned char *)private_key_manager.raw_public_key, sig);
  snprintf(sig_final, strlen(sig) + 1, "%.64s", &sig[0]);
  return sig_final;
}
