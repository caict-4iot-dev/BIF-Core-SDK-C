
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
 * @file: account_request.h
 */
#ifndef __ACCOUNT_REQUEST_H__
#define __ACCOUNT_REQUEST_H__
#ifdef __cplusplus
extern "C" {
#endif
#include "response/account_response.h"
#include "sds.h"
#include "sdscompat.h"
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

// typeThreshold 指定类型交易门限
typedef struct typeThreshold {
  int master_weight; // 操作类型，必须大于0,一般设置1
  int tx_threshold;  // 门限值，必须大于0,一般设置1
} TypeThreshold;

typedef struct metadatast {
  sds key;
  sds value;
  int version;
} MetaDatas;

typedef struct operationst {
  char dest_address[128]; // 必填，目标账户地址
  int64_t init_balance; // 必填，初始化星火令，单位PT，1 星火令 = 10^8 PT
} OperationsCreateAccount;

// BifCreateAccountRequest 创建账户请求体
typedef struct BifCreateAccountRequests {
  // OperationsCreateAccount *create_account_operation;
  char dest_address[128]; // 必填，目标账户地址
  int64_t init_balance; // 必填，初始化星火令，单位PT，1 星火令 = 10^8 PT
  char private_key[128]; // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 可选，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char remarks[1024];       // 选填，用户交易备注
  int64_t fee_limit;        // 选填
  int64_t gas_price;        // 选填
  int domainid;             // 选填
  int nonce;                // 用户不需填
} BifCreateAccountRequest;

// BifAccountGetInfoRequest 获取指定的账户信息请求体
typedef struct BifAccountGetInfoRequests {
  char address[128]; // 必填，待查询的区块链账户地址
  int domainid;      // 选填，域id，默认要设置0
} BifAccountGetInfoRequest;

// BifAccountGetNonceRequest 获取指定账户的nonce值请求体
typedef struct BifAccountGetNonceRequests {
  char address[128]; // 必填，待查询的区块链账户地址
  int domainid;      // 选填，域id，默认要设置0
} BifAccountGetNonceRequest;

// BifAccountGetBalanceRequest 获取指定账户的星火令的余额请求体
typedef struct BifAccountGetBalanceRequests {
  char address[128]; // 必填，待查询的区块链账户地址
  int domainid;      // 选填，域id，默认要设置0
} BifAccountGetBalanceRequest;

typedef struct operations {
  int type;         // 用户不需要填
  char Key[1024];   // 必填，metadata的关键词，长度限制[1, 1024]
  char *value;      // 必填，metadata的内容，长度限制[0, 256000]
  int64_t version;  // 选填，metadata的版本
  bool delete_flag; // 选填，是否删除metadata
} OperationsData;
// BifAccountSetMetadatasRequest 设置metadatas请求体
typedef struct BifAccountSetMetadatasRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  char remarks[1024];       // 选填,交易备注信息
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  int64_t fee_limit;   // 选填
  int64_t gas_price;   // 选填
  OperationsData operations_array[100]; // 必填 ，OperationsData结构体
  int operations_num; // 必填 ，OperationsData结构体变量个数
  int nonce;          // 用户不需填写
  int domainid;       // 选填
} BifAccountSetMetadatasRequest;

// BifAccountGetMetadatasRequest 获取指定账户的metadatas信息请求体
typedef struct BifAccountGetMetadatasRequests {
  char address[128]; // 必填，待查询的账户地址
  char key[1048];    // 选填，metadata关键字，长度限制[1,
                     // 1024]，有值为精确查找，无值为全部查找
  int domainid;      // 默认要设置0
} BifAccountGetMetadatasRequest;

// BifAccountSetPrivilegeRequest 设置权限请求体
typedef struct BifAccountSetPrivilegeRequests {
  char sender_address[128]; // 必填，交易源账号，即交易的发起方
  char private_key[128];    // 必填，交易源账户私钥
  int64_t
      ceil_ledger_seq; // 选填，区块高度限制,
                       // 如果大于0，则交易只有在该区块高度之前（包括该高度）才有效
  BifSigner signers[1024]; // 选填，签名者权重列表
  int signers_num;         // 选填，signers结构体变量实际个数
  char tx_threshold[64]; // 选填，交易门限，大小限制[0, Long.MAX_VALUE]
  BifTypeThreshold typeThresholds[1024]; // 选填，指定类型交易门限
  int type_threshold_num; // 选填，typeThresholds结构体变量实际个数
  char master_weight[64]; // 选填
  int64_t fee_limit;      // 选填
  int64_t gas_price;      // 选填
  char remarks[1024];     // 选填，用户交易备注
  int nonce;              // 不需用户填写
  int domainid;           // 选填
} BifAccountSetPrivilegeRequest;

#ifdef __cplusplus
}
#endif
#endif