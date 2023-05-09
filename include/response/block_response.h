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
 * @file: block_response.h
 */

#ifndef __BLOCKRESPONSE_H__
#define __BLOCKRESPONSE_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "base.h"
#include "transaction_response.h"
#include <stdint.h>

// 获取区块高度响应体
typedef struct BifBlockGetNumber {
  BifBaseResponse baseResponse;
  char *value;          // 服务返回的响应数据
  int64_t block_number; // 最新的区块高度，对应底层链的字段seq
} BifBlockGetNumberResponse;

// 获取区块信息响应体
typedef struct BifBlockGetInfoResponses {
  BifBaseResponse baseResponse;
  char *value;
} BifBlockGetInfoResponse;

#ifdef __cplusplus
}
#endif
#endif