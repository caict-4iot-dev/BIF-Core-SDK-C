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
 * @file: mnemonic.h
 */

#ifndef __MNEMONIC_H__
#define __MNEMONIC_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "private_key_manager.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BIP39_PBKDF2_ROUNDS 2048
#define PUBKEY_PREFIX 0x0488b21e  // xpub
#define PRIVKEY_PREFIX 0x0488ade4 // xprv

const char *mnemonic_from_data(const uint8_t *data, int len);
const char *mnemonic_generate(int strength); // strength in bits
// passphrase must be at most 256 characters or code may crash
void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total));
char *generate_private_keys_by_crypto_type(const char *mnemonic,
                                           const char *hd_path,
                                           KeyTypes key_type);
char *generate_private_keys_by_crypto(const char *mnemonic,
                                      const char *hd_path);

#ifdef __cplusplus
}
#endif
#endif
