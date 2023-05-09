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
 * @file: transaction_request.h
 */
#ifndef __TRANSACTIONREQUEST_H__
#define __TRANSACTIONREQUEST_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "sds.h"
#include "sdscompat.h"
#include <limits.h>
#include <stdint.h>

// BIFTransactionGasSendRequest 发送交易请求体
typedef struct BifTransactionGasSendRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  char remarks[1024];  // 选填写，用户自定义给交易的备注
  char dest_address[128]; // 必填，目的地址
                          // int operation_type;
  int64_t amount;         // 必填，转账金额
  int64_t fee_limit;      // 选填
  int64_t gas_price;      // 选填
  int domainid;           // 选填
} BifTransactionGasSendRequest;

typedef struct BatchGasSendOperations {
  char dest_address[128]; // 必填，目的地址
  int64_t amount;         // 必填，转账金额
} BatchGasSendOperation;

// BifBatchGasSendRequest 发送批量交易请求体
typedef struct BifTransactionBatchGasSendRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  char remarks[1024];  // 选填写，用户自定义给交易的备注
  BatchGasSendOperation batch_gas_send_operation
      [200]; // 必填，批量转移星火令结构体,批量超过100会报错
  int batch_gas_send_num; // 必填，批量转移星火令结构体数量
  int64_t fee_limit;      // 选填
  int64_t gas_price;      // 选填
  int domainid;           // 选填
} BifBatchGasSendRequest;

typedef struct BifParseBlobs {
  char env[32];
  char *blob;
} BifParseBlobRequest;

// BifTransactionGetInfoRequest 根据交易hash查询交易请求体
typedef struct BifTransactionGetInfoRequests {
  char hash[128]; // 交易hash
  int domainid;   // 域id
} BifTransactionGetInfoRequest;

typedef struct BifTransactionSubmitRequests {
  char *serialization;  // 必填，交易序列化blob
  char sign_data[1024]; // 必填，交易签名hex数据
  char public_key[256]; // 必填，星火公钥
} BifTransactionSubmitRequest;

typedef struct BifContractCreateOperations {
  int type;          // 选填，合约类型，默认是0
  long init_balance; // 必填，转账金额
  sds payload;       // 必填，合约payload
  sds init_input;    // 选填,合约函数入参
} BifContractCreateOperation;

typedef struct BifCallOperations {
  char dest_address[128]; // 必填，合约目的地址
  sds input;              // 选填,合约函数入参
  long amount;            // 必填，转账金额
} BifCallOperation;

typedef struct BifPayCoinOperations {
  char dest_address[128]; // 必填，合约目的地址
  sds input;              // 选填,合约函数入参
  long amount;            // 必填，转账金额
} BifPayCoinOperation;

// evaluateFee 发送交易评估请求体
typedef struct BifEvaluateFeeRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  char remarks[1024];       // 选填，用户自定义给交易的备注
  int operation_type;       // 选填，交易类型，默认是6
  int64_t fee_limit;        // 选填
  int64_t gas_price;        // 选填
  BifCallOperation call_operation; // 选填，如果是合约调用时必填
  BifContractCreateOperation create_contract_operation; // 选填，合约创建时必填
  BifPayCoinOperation pay_coin_operation; // 选填，合约转账时必填
  int domainid;                           // 选填
  int signature_number;                   // 选填
} BifEvaluateFeeRequest;

typedef struct OperationDatas {
  BifCallOperation call_operation; // 选填，如果是合约调用则必填
  BifContractCreateOperation create_contract_operation; // 选填，合约创建时必填
  BifPayCoinOperation pay_coin_operation; // 选填，如果是转账则必填
} OperationData;

// evaluateFee 批量交易评估请求体
typedef struct BifEvaluateFeeBatchRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  char remarks[1024];       // 选填，用户自定义给交易的备注
  OperationData operation_datas[200]; // 必填，批量操作的数据结构体
  int operation_num; // 必填，上述批量操作结构体数组实际数量
  int64_t fee_limit; // 选填
  int64_t gas_price; // 选填
  int domainid;      // 选填
  int signature_number; // 选填
} BifEvaluateFeeBatchRequest;

// BIFTransactionSerializeRequest ...
typedef struct BifTransactionSerializeRequests {
  char source_address[128];
  int64_t nonce;
  int64_t gas_price;
  int64_t fee_limit;
  int64_t ceil_ledger_seq;
  char remarks[1024];
  int operation_type;
  char dest_address[128]; // 必填，目的地址
  int64_t amount;         // 必填，转账金额
  int domainid;
} BifTransactionSerializeRequest;

// BifSerializeBatchRequests ...
typedef struct BifSerializeBatchRequests {
  char source_address[128];
  int64_t nonce;
  int64_t gas_price;
  int64_t fee_limit;
  int64_t ceil_ledger_seq;
  char remarks[1024];
  int operation_type;
  // char input[2048];
  BatchGasSendOperation
      batch_gas_send_operation[200]; // 必填，批量转移星火令结构体
  int batch_gas_send_num;
  int domainid;
} BifBatchSerializeRequest;

typedef struct BifTransactionCacheRequest {
  char hash[128];
} BifTransactionCacheRequest;

#ifdef __cplusplus
}
#endif
#endif