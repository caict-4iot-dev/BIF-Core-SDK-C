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
 * @file: util.h
 */

#ifndef __UTIL_H__
#define __UTIL_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int byte_to_hex_string(unsigned char *in, int len, char *out);
int hex_string_to_byte(char *in, unsigned char *out, int *out_len);
char *delete_one_symbol(char *src);

int spit_words(char chop, char *srcStr, char **word);
int get_cstring_size(char *str, int size);
uint32_t random32(void);
void random_buffer(uint8_t *buf, size_t len);
void memzero(void *s, size_t n);
#ifdef __cplusplus
}
#endif
#endif