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
 * @file: block_request.h
 */

#ifndef __BLOCKREQUEST_H__
#define __BLOCKREQUEST_H__
#ifdef __cplusplus
extern "C" {
#endif
#include <limits.h>
#include <stdint.h>

// BifBlockGetTransactionsRequest 查询指定区块高度下的所有交易请求体
typedef struct BifBlockGetTransaction {
  int64_t block_number; // 必填，指定的区块高度，对应底层字段seq
  int domainid;         // 选填，域id
} BifBlockGetTransactionsRequest;

// BifBlockGetInfoRequest 获取指定区块信息请求体
typedef struct BifBlockGetInfo {
  int64_t block_number; // 必填，待查询的区块高度
  int domainid;         // 选填，域id
} BifBlockGetInfoRequest;

// BifBlockGetInfoRequest 获取指定区块信息请求体
typedef struct BifBlockGetLatestInfo {
  int domainid; // 选填，域id
} BifBlockGetLatestInfoRequest;

// BifBlockGetValidatorsRequest 获取指定区块中所有验证节点数请求体
typedef struct BifBlockGetValidators {
  int64_t block_number; // 必填，待查询的区块高度，必须大于0
  int domainid;         // 选填，域id
} BifBlockGetValidatorsRequest;

#ifdef __cplusplus
}
#endif
#endif