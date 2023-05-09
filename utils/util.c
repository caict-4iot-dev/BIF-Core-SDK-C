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
 * @file: util.c
 */
#include "util.h"

int byte_to_hex_string(unsigned char *in, int len, char *out) {
  int i = 0;
  for (i = 0; i < len; i++) {
    if ((in[i] >> 4) >= 10 && (in[i] >> 4) <= 15)
      out[2 * i] = (in[i] >> 4) + 'A' - 10;
    else
      out[2 * i] = (in[i] >> 4) | 0x30;

    if ((in[i] & 0x0f) >= 10 && (in[i] & 0x0f) <= 15)
      out[2 * i + 1] = (in[i] & 0x0f) + 'A' - 10;
    else
      out[2 * i + 1] = (in[i] & 0x0f) | 0x30;
  }
  return 0;
}

int hex_string_to_byte(char *in, unsigned char *out, int *out_len) {
  int len = (int)strlen(in);
  char *str = (char *)malloc(len + 1);
  memset(str, 0, len + 1);
  memcpy(str, in, len);
  str[len] = '\0';
  int i = 0;
  for (i = 0; i < len; i += 2) {
    // 小写转大写
    if (str[i] >= 'a' && str[i] <= 'f')
      str[i] = str[i] & ~0x20;
    if (str[i + 1] >= 'a' && str[i] <= 'f')
      str[i + 1] = str[i + 1] & ~0x20;
    // 处理第前4位
    if (str[i] >= 'A' && str[i] <= 'F')
      out[i / 2] = (str[i] - 'A' + 10) << 4;
    else
      out[i / 2] = (str[i] & ~0x30) << 4;
    // 处理后4位, 并组合起来
    if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
      out[i / 2] |= (str[i + 1] - 'A' + 10);
    else
      out[i / 2] |= (str[i + 1] & ~0x30);
  }
  *out_len = len / 2;
  free(str);
  return 0;
}

char *delete_one_symbol(char *src) {
  int i = 0;
  int len = strlen(src);
  for (i = len - 1; i >= 0; i--) {
    if (src[i] == '\'')
      strcpy(&src[i], &src[i + 1]);
  }
  return src;
}

int spit_words(char chop, char *srcStr, char **word) {
  int index = 0;
  int i = 0;
  char *str = srcStr;
  while (*(str + i) != '\0') {
    if (*(str + i) == chop) {
      word[index] = str;
      word[index++][i] = '\0';
      str = (str + i + 1);
      i = -1;
    }
    if (*(str + i) == '\r') {
      word[index] = str;
      word[index++][i] = '\0';
      str = (str + i);
      i = 0;
      break;
    }
    i++;
  }
  if (strlen(str) > 0) {
    word[index++] = str;
  }
  return index;
}

int get_cstring_size(char *str, int size) {
  char *pend = str + size - 1;
  while (pend >= str && *pend == 0) {
    --pend;
  }
  return pend - str + 1;
}

uint32_t random32(void) {
  static int initialized = 0;
  if (!initialized) {
    srand((unsigned)time(NULL));
    initialized = 1;
  }
  return ((rand() & 0xFF) | ((rand() & 0xFF) << 8) | ((rand() & 0xFF) << 16) |
          ((uint32_t)(rand() & 0xFF) << 24));
}

void __attribute__((weak)) random_buffer(uint8_t *buf, size_t len) {
  uint32_t r = 0;
  size_t i = 0;
  for (i = 0; i < len; i++) {
    if (i % 4 == 0) {
      r = random32();
    }
    buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
  }
}
void memzero(void *s, size_t n) { memset(s, 0, n); }