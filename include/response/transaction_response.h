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
 * @file: transaction_response.h
 */

#ifndef __TRANSACTION_RESPONSE_H__
#define __TRANSACTION_RESPONSE_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "account_response.h"
#include "base.h"
#include "block_response.h"
#include "sds.h"
#include "sdscompat.h"
#include <stdint.h>

// BifTransactionGetInfoResponse 根据交易hash查询交易响应体
typedef struct BifTransactionGetInfoResponses {
  BifBaseResponse baseResponse;
  char *value;
} BifTransactionGetInfoResponse;

typedef struct BifTransactionSubmitResponses {
  BifBaseResponse baseResponse;
  char *value;
} BifTransactionSubmitResponse;

typedef struct BifTransactionGetTxCacheSizeResponses {
  BifBaseResponse baseResponse;
  char *value;
  // int64_t queueSize;
} BifTransactionGetTxCacheSizeResponse;

#ifdef __cplusplus
}
#endif
#endif