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
 * @file: contract_response.h
 */

#ifndef __CONTRACTRESPONSE_H__
#define __CONTRACTRESPONSE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "base.h"
#include "block_response.h"
#include "transaction_response.h"
#include <stdint.h>

// BifContractCheckValidResponse 检测合约账户的有效性返回体
typedef struct BifContractCheckValidResponses {
  BifBaseResponse baseResponse;
  char *value; // 是否有效
} BifContractCheckValidResponse;

// 合约响应体
typedef struct BifContractGetInfoResponses {
  BifBaseResponse baseResponse;
  char *value;
} BifContractGetInfoResponse;

#ifdef __cplusplus
}
#endif
#endif