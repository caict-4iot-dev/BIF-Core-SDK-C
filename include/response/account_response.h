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
 * @file: account_response.h
 */

#ifndef __ACCOUNT_RESPONSE_H__
#define __ACCOUNT_RESPONSE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "../request/operation_request.h"
#include "base.h"
#include <stdint.h>

// BifAccountGetInfoResponse 获取指定的账户信息返回体
typedef struct BifAccountResponses {
  BifBaseResponse baseResponse;
  char *value;
  long balance;
} BifAccountResponse;

// BifAccountGetBalanceResponse 获取指定账户的星火令的余额返回体
typedef struct BifAccountGetBalanceResponses {
  BifBaseResponse baseResponse;
  char *value;
} BifAccountGetBalanceResponse;

// BifMetadataInfo 账户信息
typedef struct BifMetadataInfos {
  char key[1024];   // metadata的关键词
  char value[4096]; // metadata的内容
  int64_t version;  // metadata的版本
} BifMetadataInfo;

typedef struct BifTypeThresholds {
  int type;
  int64_t threshold;
} BifTypeThreshold;

typedef struct BifThresholds {
  int64_t txThreshold;
  BifTypeThreshold Thresholds[512];
} BifThreshold;

typedef struct BifPrivs {
  int64_t masterWeight;
  BifSigner signers[512];
  BifThreshold thresholds; // thresholds
} BifPriv;

typedef struct BifAccountPrivResults {
  char address[64]; // 账户地址
  BifPriv priv;     // 账户权限
} BifAccountPrivResult;

// BifAccountPrivResponse 获取账户权限返回体
typedef struct BifAccountPrivResponses {
  BifBaseResponse baseResponse;
  BifAccountPrivResult result;
} BifAccountPrivResponse;

// BifAccountGetNonceResponse 获取指定账户的nonce值返回体
typedef struct BifAccountGetNonceResponses {
  BifBaseResponse baseResponse;
  int64_t nonce;
} BifAccountGetNonceResponse;

typedef struct BifCreateAccountResponses {
  BifBaseResponse baseResponse;
  char hash[128];
} BifCreateAccountResponse;

#ifdef __cplusplus
}
#endif
#endif