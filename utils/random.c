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
 * @date: 2023-03-01 16:16:36
 * @file: random.c
 */

#include "random.h"
#include "crypto.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/sha.h"


static inline int64_t get_performance_counter() {
  int64_t counter = 0;
  struct timeval t;
  gettimeofday(&t, NULL);
  counter = (int64_t)(t.tv_sec * 1000000 + t.tv_usec);
  return counter;
}
void memory_clean(void *ptr, size_t len) {
  memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
}
void rand_add_seed() {
  // Seed with CPU performance counter
  int64_t nCounter = get_performance_counter();
  RAND_add(&nCounter, sizeof(nCounter), 1.5);
  memory_clean((void *)&nCounter, sizeof(nCounter));
}
bool get_rand_bytes(unsigned char *buf, int num) {
  return RAND_bytes(buf, num) == 1;
}
bool get_os_rand(unsigned char *buf, int num) {
  int i = 0;
  srand((unsigned int)time(NULL));
  for (i = 0; i < num; i++) {
    int rand_num = rand() % 255; // 产生一个0-255之间的数
    buf[i] = (unsigned char)rand_num;
  }
  return true;
}

bool get_strong_rand_bytes(char *out, int *raw_private_len) {
  unsigned char buf[128] = {0};
  unsigned char out_temp[256] = {0};
  rand_add_seed();
  if (!get_rand_bytes(buf, 64))
    return false;
  // if (!get_rand_bytes(buf + 32, 32))
  //     return false;

  sha256_crypto(buf, 64, out_temp);
  memcpy(out, out_temp, 32);
  out[32] = '\0';
  *raw_private_len = 32;
  return true;
}