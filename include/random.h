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
 * @file: random.h
 */

#ifndef __RANDOM_H__
#define __RANDOM_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "stdbool.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

static inline int64_t get_performance_counter();
void memory_clean(void *ptr, size_t len);
void rand_add_seed();
bool get_rand_bytes(unsigned char *buf, int num);
bool get_os_rand(unsigned char *buf, int num);
bool get_strong_rand_bytes(char *out, int *raw_private_len);

#ifdef __cplusplus
}
#endif
#endif