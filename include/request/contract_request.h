
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
 * @file: contract_request.h
 */
#ifndef __CONTRACTREQUEST_H__
#define __CONTRACTREQUEST_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "operation_request.h"
#include "request/account_request.h"
#include "sds.h"
#include "sdscompat.h"
#include <limits.h>
#include <stdint.h>

enum TYPE {
  TYPE_V8 = 0,
  TYPE_EVM = 1,
  TYPE_SYSTEM = 2,
  TYPE_WASM = 3,
  TYPE_JVM = 4,
};
// BifContractCheckValidRequest 检测合约账户的有效性请求体
typedef struct BifContractCheckValidRequests {
  char contract_address[128]; // 待检测的合约账户地址
  int domainid;               // domainid,如无需初始化为0
} BifContractCheckValidRequest;

// BifContractCreateRequest 创建合约请求体
typedef struct BifContractCreateRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  int64_t fee_limit;     // 可选，交易花费的手续费，默认1000000L
  char private_key[128]; // 必填，交易源账户私钥
  char remarks[128];     // 交易备注
  int64_t
      ceil_ledger_seq; // 可选，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  int64_t init_balance; // 必填，给合约账户的初始化星火令，单位PT，1 星火令 =
                        // 10^8 PT, 大小限制[1, Long.MAX_VALUE]
  int contract_type; // 选填，合约的类型，默认是0 , 0: javascript，1 :evm 。
  sds payload;       // 必填，对应语种的合约代码
  sds init_input;    // 选填，合约代码中init方法的入参
  int64_t gas_price; // 选填
  int nonce;
  int domainid; // 选填
} BifContractCreateRequest;

// BifContractGetAddressRequest 根据交易Hash查询合约地址请求体
typedef struct BifContractGetAddressRequests {
  int domainid;   // 域id,如无则初始化默认值0
  char hash[128]; // 创建合约交易的hash
} BifContractGetAddressRequest;

// BifContractCallRequest 合约查询接口请求体
typedef struct BifContractCallRequests {
  char source_address[128];   // 选填，合约触发账户地址
  char contract_address[128]; // 必填，合约账户地址
  sds input;                  // 选填，合约入参
  int64_t fee_limit;
  int64_t gas_price;
  // int opt_type;        // 选填，合约类型 默认是0 , 0: javascript，1 :evm
  int domainid;
} BifContractCallRequest;

// BIFContractInvokeRequest 合约调用请求体
typedef struct BifContractInvokeRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  int64_t fee_limit; //  选填，交易花费的手续费，默认设置1000000L
  char private_key[128]; // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  char remarks[1024]; // 选填，用户自定义给交易的备注，16进制格式
  char contract_address[128]; // 必填，合约账户地址
  int64_t amount;             // 必填，转账金额
  sds input;                  // 选填，待触发的合约的main()入参
  int64_t gas_price;          // 选填
  int nonce;
  int domainid;
} BifContractInvokeRequest;

typedef struct OperationBatchs {
  char contract_address[128]; // 必填，合约账户地址
  int64_t amount;             // 必填，转账金额
  sds input; // 选填，合约input数据 sds为封装的char *类型的处理
} OperationBatch;

typedef struct BifBatchContractInvokeRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  int64_t fee_limit; //  选填，交易花费的手续费，默认设置1000000L
  char private_key[128]; // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  char remarks[1024];  // 选填，用户自定义给交易的备注
  OperationBatch operation_batch_data
      [200]; // 必填，创建批量合约的数据，批量超过100个会返回错误
  int operation_batch_num; // 必填，上述批量operation结构体个数
  int64_t gas_price;       // 选填
  int nonce;
  int domainid; // 选填
} BifBatchContractInvokeRequest;

#ifdef __cplusplus
}
#endif
#endif