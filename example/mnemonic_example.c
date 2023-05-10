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
 * @file: mnemonic_example.c
 */

#include "mnemonic.h"
#include "public_key_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char **argv) {
  // generate mnemonic
  const char *mnemo = mnemonic_generate(128);
  if (!mnemo) {
    printf("mnemonic of cryto bit must 128bit\n\n");
  }
  printf("mnemonic: %s\n\n", mnemo);

  char *enc_private_key = (char *)malloc(256);
  memset(enc_private_key, 0, 256);
  const char hd_path[32] = "m/44'/0/0'/0/0";
  const char mnemonic[512] = "swift old dial that wave naive seminar lecture "
                             "increase coyote scheme end";
                             
  // 无type参数时默认生成ED25519的私钥
  strcpy(enc_private_key,
         generate_private_keys_by_crypto_type(mnemonic, hd_path, SM2));

  printf("enc_private_key:%s\n", enc_private_key);

  char enc_public[256] = {0};
  char enc_address[128] = {0};
  char raw_public_key[256] = {0};
  int raw_public_key_len = 0;
  KeyTypes key_type;
  // key_type = SM2;
  key_type = ED25519;
  strcpy(enc_public,
         get_public_by_enc_private(enc_private_key, &key_type, raw_public_key,
                                   &raw_public_key_len));
  strcpy(enc_address, get_enc_address_by_raw_pkey(
                          raw_public_key, raw_public_key_len, "", key_type));
  printf("enc_address:%s\n", enc_address);
  if (enc_private_key)
    free(enc_private_key);
  enc_private_key = NULL;

  return 0;
}