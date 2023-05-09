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
 * @file: public_key_manager.c
 */
#include "public_key_manager.h"
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
#include "random.h"
#include "util.h"


extern EC_GROUP *cfca_group_;

char *get_public_by_enc_private(const char *enc_private_Key, KeyTypes *key_type,
                                char *raw_public_key, int *raw_public_key_len) {
  char raw_private_key[256] = {0};
  SM2_DATA sm2_data;
  int out_len = 0;
  int raw_len = 0;
  if (!enc_private_Key) {
    return NULL;
  } else if (strlen(enc_private_Key) == 0) {
    return NULL;
  }
  char *raw_temp = get_raw_private_key(enc_private_Key, key_type, &raw_len);
  if (!raw_temp) {
    return NULL;
  }
  memcpy(raw_private_key, raw_temp, raw_len);
  raw_private_key[raw_len] = '\0';
  if (raw_temp)
    free(raw_temp);
  if (!raw_len) {
    return NULL;
  }
  switch (*key_type) {
  case ED25519:
    ed25519_publickey((unsigned char *)raw_private_key,
                      (unsigned char *)raw_public_key);
    out_len = 32;
    *raw_public_key_len = out_len;
    // snprintf(raw_public_key, strlen(raw_private_key) + 1, "%s",
    // &raw_private_key[32]);
    break;
  case SM2:
    get_cfca_group();
    init(&sm2_data, cfca_group_);
    from_skey_bin(raw_private_key, raw_len, &sm2_data);
    char *raw_public_temp = get_public_key_sm2(sm2_data, &out_len);
    memcpy(raw_public_key, raw_public_temp, out_len);
    raw_public_key[out_len] = '\0';
    *raw_public_key_len = out_len;
    if (raw_public_temp)
      free(raw_public_temp);
    break;
  default:
    return NULL;
  }
  return get_enc_public_key_by_raw_public(raw_public_key, out_len, *key_type);
}

// 根据星火私钥获取星火公钥
char *get_enc_public_key(const char *enc_private_Key) {
  KeyTypes key_type;
  char raw_private_key[256] = {0};
  char raw_public_key[256] = {0};
  SM2_DATA sm2_data;
  int out_len = 0;
  int raw_len = 0;
  if (!enc_private_Key) {
    return NULL;
  } else if (strlen(enc_private_Key) == 0) {
    return NULL;
  }
  char *raw_temp = get_raw_private_key(enc_private_Key, &key_type, &raw_len);
  memcpy(raw_private_key, raw_temp, raw_len);
  raw_private_key[raw_len] = '\0';
  if (raw_temp)
    free(raw_temp);
  if (!raw_len) {
    return NULL;
  }
  switch (key_type) {
  case ED25519:
    ed25519_publickey((unsigned char *)raw_private_key,
                      (unsigned char *)raw_public_key);
    out_len = 32;
    break;
  case SM2:
    get_cfca_group();
    init(&sm2_data, cfca_group_);
    from_skey_bin(raw_private_key, raw_len, &sm2_data);
    char *raw_public_temp = get_public_key_sm2(sm2_data, &out_len);
    memcpy(raw_public_key, raw_public_temp, out_len);
    raw_public_key[out_len] = '\0';
    if (raw_public_temp)
      free(raw_public_temp);
    break;
  default:
    return NULL;
  }
  return get_enc_public_key_by_raw_public(raw_public_key, out_len, key_type);
}

// 原生公钥转星火公钥
char *get_enc_public_key_by_raw_public(const char *raw_public_key,
                                       int raw_public_len, KeyTypes key_type) {
  char buff[256] = {0};
  char *out = (char *)malloc(256);
  memset(out, 0, 256);
  buff[0] = 0xB0;
  if (!raw_public_key || raw_public_len == 0) {
    return NULL;
  }
  switch (key_type) {
  case ED25519:
    buff[1] = ED25519_VALUE;
    break;
  case SM2:
    buff[1] = SM2_VALUE;
    break;
  default:
    return NULL;
  }

  buff[2] = BASE_58_VALUE;
  memcpy(buff + 3, raw_public_key, raw_public_len);
  int len = raw_public_len + 3;
  buff[len] = '\0';
  // snprintf(buff + 3, strlen(buff), "%s", &raw_public_key[0]);
  byte_to_hex_string(buff, len, out);
  return out;
}

char *encode_address(char *address_temp, int addr_tmp_len,
                     const char *chain_code, KeyTypes key_type) {
  char no_prefix_address[128] = {0};
  char enc_address[128] = {0};
  // char addr_temp[128] = {0};
  char *addr_temp = (char *)malloc(128);
  memset(addr_temp, 0, 128);
  size_t b58sz = 0;
  if (!address_temp || addr_tmp_len == 0) {
    return NULL;
  }
  if (key_type == ED25519) {
    no_prefix_address[0] = ED25519_VALUE;
  } else if (key_type == SM2) {
    no_prefix_address[0] = SM2_VALUE;
  } else {
    return NULL;
  }
  no_prefix_address[1] = BASE_58_VALUE;
  char *noprefix_address_temp = base58_encode(address_temp, addr_tmp_len);
  // strcpy(enc_address, noprefix_address_temp);
  strcat(no_prefix_address, noprefix_address_temp);
  if (noprefix_address_temp) {
    free(noprefix_address_temp);
    noprefix_address_temp = NULL;
  }
  if (strlen(chain_code) == 0) {
    strcpy(addr_temp, "did:bid:");
    strcat(addr_temp, no_prefix_address);
  } else {
    strcpy(addr_temp, "did:bid:");
    strcat(addr_temp, chain_code);
    strcat(addr_temp, ":");
    strcat(addr_temp, no_prefix_address);
  }
  return addr_temp;
}
char *get_enc_address(const char *enc_public_key, const char *chain_code) {
  KeyTypes key_type;
  int raw_public_len = 0;
  char raw_public[256] = {0};
  char enc_public_hex_byte[256] = {0};
  int enc_public_byte_len = 0;

  if (!enc_public_key) {
    return NULL;
  } else if (strlen(enc_public_key) == 0) {
    return NULL;
  }
  char *raw_public_temp = get_raw_public_key(enc_public_key, &raw_public_len);
  memcpy(raw_public, raw_public_temp, raw_public_len);
  raw_public[raw_public_len] = '\0';

  hex_string_to_byte(enc_public_key, enc_public_hex_byte, &enc_public_byte_len);
  enc_public_hex_byte[enc_public_byte_len] = '\0';
  if (enc_public_hex_byte[1] == ED25519_VALUE) {
    key_type = ED25519;
  } else {
    key_type = SM2;
  }

  return get_enc_address_by_raw_pkey(raw_public, raw_public_len, chain_code,
                                     key_type);
}
char *get_enc_address_by_raw_pkey(const char *raw_public_key,
                                  int raw_public_len, const char *chain_code,
                                  KeyTypes key_type) {
  char buf[256] = {0};
  char result[256] = {0};
  if (!raw_public_key) {
    return NULL;
  } else if (raw_public_len == 0) {
    return NULL;
  }
  if (key_type == ED25519) {
    sha256_crypto(raw_public_key, raw_public_len, buf);
    memcpy(result, buf + 10, 22);
    result[22] = '\0';
  } else if (key_type == SM2) {
    sm3_crypto(raw_public_key, raw_public_len, (unsigned char *)buf);
    // snprintf(result, 256, "%s", &buf[10]);
    memcpy(result, buf + 10, 22);
    result[22] = '\0';
  } else {
    return NULL;
  }

  return encode_address(result, 22, chain_code, key_type);
}
// 星火公钥转原生公钥
char *get_raw_public_key(const char *enc_public_key, int *raw_public_len) {
  char raw_public_key_final[256] = {0};
  char raw_public_key[256] = {0};
  int raw_public_key_len = 0;
  if (!enc_public_key) {
    return NULL;
  } else if (raw_public_len == 0) {
    return NULL;
  }
  hex_string_to_byte(enc_public_key, raw_public_key, &raw_public_key_len);
  // strcpy(raw_public_key, hex_string_to_bin(enc_public_key));
  if (!raw_public_key_len) {
    return NULL;
  }
  memcpy(raw_public_key_final, raw_public_key + 3, raw_public_key_len - 3);
  *raw_public_len = raw_public_key_len - 3;
  raw_public_key_final[*raw_public_len] = '\0';

  return raw_public_key_final;
}

bool verify(char *msg, char *sign_msg, int sign_msg_len, char *enc_public_key) {
  bool is_ok = false;
  KeyTypes key_type;
  char enc_public_hex_byte[256] = {0};
  int enc_public_byte_len = 0;
  int raw_public_len = 0;
  char raw_public[256] = {0};

  if (!msg || !sign_msg || sign_msg_len == 0) {
    return false;
  } else if (strlen(msg) == 0 || !enc_public_key) {
    return false;
  } else if (strlen(enc_public_key) == 0) {
    return false;
  }
  char *raw_public_temp = get_raw_public_key(enc_public_key, &raw_public_len);
  memcpy(raw_public, raw_public_temp, raw_public_len);
  raw_public[raw_public_len] = '\0';

  hex_string_to_byte(enc_public_key, enc_public_hex_byte, &enc_public_byte_len);
  enc_public_hex_byte[enc_public_byte_len] = '\0';
  if (enc_public_hex_byte[1] == ED25519_VALUE) {
    printf("ED25519 value\n");
    return ed25519_sign_open((unsigned char *)msg, strlen(msg),
                             (unsigned char *)raw_public,
                             (unsigned char *)sign_msg) == 0;

  } else if (enc_public_hex_byte[1] == SM2_VALUE) {
    printf("SM2 value\n");
    return verify_sm2(get_cfca_group(), raw_public, raw_public_len,
                      "1234567812345678", msg, sign_msg, sign_msg_len) == 1;
  }
  printf("\n===++====failed to verify.Unknow signature type:%c\n",
         enc_public_hex_byte[1]);

  return is_ok;
}
bool is_address_valid(const char *enc_address) {
  char temp_enc_address[64] = {0};
  char *items[5] = {NULL};
  char *enc_split_address = NULL;
  if (!enc_address) {
    printf("invalid address NULL\n");
    return false;
  } else if (strlen(enc_address) == 0) {
    return false;
  }
  strcpy(temp_enc_address, enc_address);
  if (strlen(temp_enc_address) == 0) {
    printf("invalid address NULL\n");
    return false;
  }
  int item_len = spit_words(':', temp_enc_address, items);
  if (item_len != 3 && item_len != 4) {
    return false;
  }
  if (item_len == 3) {
    enc_split_address = items[2];
  } else {
    enc_split_address = items[3];
  }
  if (!strstr(enc_split_address, "ef") && !strstr(enc_split_address, "zf")) {
    printf("invalid address\n");
    return false;
  }
  int decode_len = 0;
  char *base58_decode_data = base58_decode(enc_split_address + 2, &decode_len);
  if (decode_len != 22) {
    printf("enc_split_address:%s\n", enc_split_address + 2);
    printf("invalid address decode58_data:%s != 22\n", base58_decode_data);
    sdk_free(base58_decode_data);
    return false;
  }
  sdk_free(base58_decode_data);
  return true;
}

bool verify_test(char *msg, char *sign_msg,
                 PrivateKeyManager private_key_manager) {
  bool is_ok;
  KeyTypes key_type;

  return ed25519_sign_open((unsigned char *)msg, strlen(msg),
                           (unsigned char *)private_key_manager.raw_public_key,
                           (unsigned char *)sign_msg) == 0;
}