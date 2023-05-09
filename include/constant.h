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
 * @file: constant.h
 */

#ifndef __CONSTANT_H__
#define __CONSTANT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define METADATA_KEY_MIN (1)
#define METADATA_KEY_MAX (1024)
#define METADATA_VALUE_MAX (256000)
#define HASH_HEX_LENGTH (64)
#define OPT_TYPE_MIN (0)
#define OPT_TYPE_MAX (2)

// 交易默认值
#define GAS_PRICE (100)
#define FEE_LIMIT (1000000)
// 合约查询类型
#define CONTRACT_QUERY_OPT_TYPE (2)

// 账号参数
#define VERSION (0)
// #define SUCCESS (0)
#define ERRORCODE (4)
#define INIT_NONCE (0)
#define INIT_ZERO (0)
#define INIT_ONE (1)
#define DOMAINID_ERRORCODE (170)

#define INIT_ZERO_L (0)
#define INIT_ONE_L (1)
// CONTRACT_TYPE_EVM合约类型evm合约
#define CONTRACT_TYPE_EVM (1)

#ifdef __cplusplus
}
#endif
#endif