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
 * @file: mnemonic.c
 */
#include "mnemonic/mnemonic.h"
#include "mnemonic/bip32.h"
#include "mnemonic/bip39_english.h"
#include "mnemonic/curves.h"
#include "mnemonic/options.h"
#include "mnemonic/pbkdf2.h"
#include "mnemonic/sha2.h"
#include "util.h"
#if USE_BIP39_CACHE

static int bip39_cache_index = 0;
static CONFIDENTIAL struct {
  bool set;
  char mnemonic[256];
  char passphrase[64];
  uint8_t seed[512 / 8];
} bip39_cache[BIP39_CACHE_SIZE];

#endif

const char *mnemonic_from_data(const uint8_t *data, int len) {
  if (len % 4 || len < 16 || len > 32) {
    return 0;
  }

  uint8_t bits[32 + 1];

  // sha256_crypto(data, len, bits);
  sha256_Raw(data, len, bits);
  // checksum
  bits[len] = bits[0];
  // data
  memcpy(bits, data, len);

  int mlen = len * 3 / 4;
  static CONFIDENTIAL char mnemo[24 * 10];

  int i, j, idx;
  char *p = mnemo;
  for (i = 0; i < mlen; i++) {
    idx = 0;
    for (j = 0; j < 11; j++) {
      idx <<= 1;
      idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
    }
    strcpy(p, wordlist[idx]);
    p += strlen(wordlist[idx]);
    *p = (i < mlen - 1) ? ' ' : 0;
    p++;
  }
  memzero(bits, sizeof(bits));

  return mnemo;
}

const char *mnemonic_generate(int strength) {
  if (strength % 32 || strength < 128 || strength > 256) {
    return NULL;
  }
  // 目前默认只支持128位，12个单词
  else if (strength != 128) {
    return NULL;
  }
  uint8_t data[32];
  random_buffer(data, 32);
  const char *r = mnemonic_from_data(data, strength / 8);
  memzero(data, sizeof(data));
  return r;
}

void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total)) {
  int passphraselen = strlen(passphrase);
#if USE_BIP39_CACHE
  int mnemoniclen = strlen(mnemonic);
  // check cache
  if (mnemoniclen < 256 && passphraselen < 64) {
    for (int i = 0; i < BIP39_CACHE_SIZE; i++) {
      if (!bip39_cache[i].set)
        continue;
      if (strcmp(bip39_cache[i].mnemonic, mnemonic) != 0)
        continue;
      if (strcmp(bip39_cache[i].passphrase, passphrase) != 0)
        continue;
      // found the correct entry
      memcpy(seed, bip39_cache[i].seed, 512 / 8);
      return;
    }
  }
#endif
  uint8_t salt[8 + 256];
  memcpy(salt, "mnemonic", 8);
  memcpy(salt + 8, passphrase, passphraselen);
  static CONFIDENTIAL PBKDF2_HMAC_SHA512_CTX pctx;
  pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)mnemonic, strlen(mnemonic),
                          salt, passphraselen + 8, 1);
  if (progress_callback) {
    progress_callback(0, BIP39_PBKDF2_ROUNDS);
  }

  for (int i = 0; i < 16; i++) {
    pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 16);
    if (progress_callback) {
      progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 16,
                        BIP39_PBKDF2_ROUNDS);
    }
  }
  pbkdf2_hmac_sha512_Final(&pctx, seed);
  memzero(salt, sizeof(salt));
#if USE_BIP39_CACHE
  // store to cache
  if (mnemoniclen < 256 && passphraselen < 64) {
    bip39_cache[bip39_cache_index].set = true;
    strcpy(bip39_cache[bip39_cache_index].mnemonic, mnemonic);
    strcpy(bip39_cache[bip39_cache_index].passphrase, passphrase);
    memcpy(bip39_cache[bip39_cache_index].seed, seed, 512 / 8);
    bip39_cache_index = (bip39_cache_index + 1) % BIP39_CACHE_SIZE;
  }
#endif
}
char *generate_private_keys_by_crypto(const char *mnemonic,
                                      const char *hd_path) {
  int keylength = 64;
  uint8_t bip39_seed[keylength];
  if (!mnemonic || !hd_path) {
    return NULL;
  }
  if (strlen(mnemonic) == 0 || strlen(hd_path) == 0) {
    return NULL;
  }
  mnemonic_to_seed(mnemonic, "", bip39_seed, 0);

  char rootkey[112];
  uint32_t fingerprint = 0;
  HDNode node;
  int r = hdnode_from_seed(bip39_seed, 64, SECP256K1_NAME, &node);
  if (r != 1) {
    printf("hdnode_from_seed failed (%d).", r);
    return NULL;
  }

  hdnode_fill_public_key(&node);
  // root private key
  r = hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey,
                               sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_private failed (%d).", r);
    return NULL;
  }
  // root public key
  r = hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey,
                              sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_public failed (%d).", r);
    return NULL;
  }
  char *hd_path_temp = delete_one_symbol(hd_path);
  char *items[6] = {NULL};
  int item_len = spit_words('/', hd_path_temp, items);

  // m/44'/0/0'/0/0   m/44/0/0/0/0
  if (item_len < 6) {
    printf("invalid hd_path\n");
    return NULL;
  }
  hdnode_private_ckd_prime(&node, atoi(items[1]));
  hdnode_private_ckd_prime(&node, atoi(items[2]));
  hdnode_private_ckd_prime(&node, atoi(items[3]));
  hdnode_private_ckd(&node, atoi(items[4]));
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd(&node, atoi(items[5]));
  hdnode_fill_public_key(&node);
  // child hex private key
  hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey,
                           sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_private failed (%d).", r);
    return NULL;
  }
  // child hex public key
  hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey,
                          sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_public failed (%d).", r);
    return NULL;
  }
  char enc_private_key[256] = {0};
  strcpy(enc_private_key, get_enc_private_key(node.private_key, 32, ED25519));
  return enc_private_key;
}

char *generate_private_keys_by_crypto_type(const char *mnemonic,
                                           const char *hd_path,
                                           KeyTypes key_type) {
  int keylength = 64;
  uint8_t bip39_seed[keylength];
  if (!mnemonic || !hd_path) {
    return NULL;
  }
  if (strlen(mnemonic) == 0 || strlen(hd_path) == 0) {
    return NULL;
  }
  if (key_type != ED25519) {
    if (key_type != SM2) {
      return NULL;
    }
  }
  mnemonic_to_seed(mnemonic, "", bip39_seed, 0);

  char rootkey[112];
  uint32_t fingerprint = 0;
  HDNode node;
  int r = hdnode_from_seed(bip39_seed, 64, SECP256K1_NAME, &node);
  if (r != 1) {
    printf("hdnode_from_seed failed (%d).", r);
    return NULL;
  }

  hdnode_fill_public_key(&node);
  // root private key
  r = hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey,
                               sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_private failed (%d).", r);
    return NULL;
  }
  // root public key
  r = hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey,
                              sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_public failed (%d).", r);
    return NULL;
  }
  char *hd_path_temp = delete_one_symbol(hd_path);
  char *items[6] = {NULL};
  int item_len = spit_words('/', hd_path_temp, items);

  // m/44'/0/0'/0/0   m/44/0/0/0/0
  if (item_len < 6) {
    printf("invalid hd_path\n");
    return NULL;
  }
  hdnode_private_ckd_prime(&node, atoi(items[1]));
  hdnode_private_ckd_prime(&node, atoi(items[2]));
  hdnode_private_ckd_prime(&node, atoi(items[3]));
  hdnode_private_ckd(&node, atoi(items[4]));
  fingerprint = hdnode_fingerprint(&node);
  hdnode_private_ckd(&node, atoi(items[5]));
  hdnode_fill_public_key(&node);
  // child hex private key
  hdnode_serialize_private(&node, fingerprint, PRIVKEY_PREFIX, rootkey,
                           sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_private failed (%d).", r);
    return NULL;
  }
  // child hex public key
  hdnode_serialize_public(&node, fingerprint, PUBKEY_PREFIX, rootkey,
                          sizeof(rootkey));
  if (r <= 0) {
    printf("hdnode_serialize_public failed (%d).", r);
    return NULL;
  }
  char enc_private_key[256] = {0};
  strcpy(enc_private_key,
         get_enc_private_key(node.private_key, 32, key_type)); // sigsegv

  return enc_private_key;
}
