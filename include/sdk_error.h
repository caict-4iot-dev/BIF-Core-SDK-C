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
 * @file: sdk_error.h
 */

#ifndef __SDKERROR_H__
#define __SDKERROR_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "response/base.h"
#include <stdio.h>

// sdk error info
typedef enum {
  SUCCESS = 0,
  ACCOUNT_CREATE_ERROR,
  INVALID_AMOUNT_ERROR,
  INVALID_SOURCEADDRESS_ERROR,
  INVALID_DESTADDRESS_ERROR,
  INVALID_INITBALANCE_ERROR,
  SOURCEADDRESS_EQUAL_DESTADDRESS_ERROR,
  INVALID_ADDRESS_ERROR,
  CONNECTNETWORK_ERROR,
  NO_METADATAS_ERROR,
  INVALID_DATAKEY_ERROR,
  INVALID_DATAVALUE_ERROR,
  INVALID_DATAVERSION_ERROR,
  INVALID_MASTERWEIGHT_ERROR,
  INVALID_SIGNER_ADDRESS_ERROR,
  INVALID_SIGNER_WEIGHT_ERROR,
  INVALID_TX_THRESHOLD_ERROR,
  INVALID_TYPETHRESHOLD_TYPE_ERROR,
  INVALID_TYPE_THRESHOLD_ERROR,
  INVALID_CONTRACT_HASH_ERROR,
  INVALID_GAS_AMOUNT_ERROR,
  INVALID_CONTRACTADDRESS_ERROR,
  CONTRACTADDRESS_NOT_CONTRACTACCOUNT_ERROR,
  SOURCEADDRESS_EQUAL_CONTRACTADDRESS_ERROR,
  INVALID_FROMADDRESS_ERROR,
  FROMADDRESS_EQUAL_DESTADDRESS_ERROR,
  INVALID_SPENDER_ERROR,
  PAYLOAD_EMPTY_ERROR,
  INVALID_CONTRACT_TYPE_ERROR,
  INVALID_NONCE_ERROR,
  INVALID_GASPRICE_ERROR,
  INVALID_FEELIMIT_ERROR,
  OPERATIONS_EMPTY_ERROR,
  INVALID_CEILLEDGERSEQ_ERROR,
  OPERATIONS_ONE_ERROR,
  INVALID_SIGNATURENUMBER_ERROR,
  INVALID_HASH_ERROR,
  INVALID_SERIALIZATION_ERROR,
  PRIVATEKEY_NULL_ERROR,
  PRIVATEKEY_ONE_ERROR,
  SIGNDATA_NULL_ERROR,
  INVALID_BLOCKNUMBER_ERROR,
  PUBLICKEY_NULL_ERROR,
  URL_EMPTY_ERROR,
  CONTRACTADDRESS_CODE_BOTH_NULL_ERROR,
  INVALID_OPTTYPE_ERROR,
  GET_ALLOWANCE_ERROR,
  SIGNATURE_EMPTY_ERROR,
  OPERATION_TYPE_ERROR,
  CONNECTN_BLOCKCHAIN_ERROR,
  SYSTEM_ERROR,
  REQUEST_NULL_ERROR,
  INVALID_CONTRACTBALANCE_ERROR,
  INVALID_PRITX_FROM_ERROR,
  INVALID_PRITX_PAYLAOD_ERROR,
  INVALID_PRITX_TO_ERROR,
  INVALID_PRITX_HASH_ERROR,
  INVALID_DOMAINID_ERROR,
  OPERATIONS_LENGTH_ERROR,
} operation;

typedef struct {
  operation op;
  BifBaseResponse res;
} SdkError;

#ifdef __cplusplus
}
#endif
#endif