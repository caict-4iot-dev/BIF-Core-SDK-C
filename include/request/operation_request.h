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
 * @file: operation_request.h
 */

#ifndef __OPERATIONREQUEST_H__
#define __OPERATIONREQUEST_H__
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

// BifSigner 签名者结构体
typedef struct BifSigners {
  char address[128];
  int64_t weight;
} BifSigner;

#ifdef __cplusplus
}
#endif
#endif