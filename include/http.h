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
 * @file: http.h
 */

#ifndef __HTTP_H__
#define __HTTP_H__
#ifdef __cplusplus
extern "C" {
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct bufs {
  void *data;
  size_t len;
} buf_t;

int http_get(const char *url, int timeout, void **value, size_t *valueLen);
int http_post(const char *url, const char *data, int timeout, void **value,
              size_t *valueLen);

size_t saveRespData(void *data, size_t size, size_t nmemb, void *args);

#ifdef __cplusplus
}
#endif
#endif