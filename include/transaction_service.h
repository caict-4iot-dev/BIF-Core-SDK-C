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
 * @file: transaction_service.h
 */

#ifndef __TRANSACTION_SERVICE_H__
#define __TRANSACTION_SERVICE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "request/transaction_request.h"
#include "response/transaction_response.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

BifTransactionGetTxCacheSizeResponse *get_tx_cache_size(int domainid,
                                                        const char *url);
BifTransactionGetInfoResponse *
get_transaction_info(BifTransactionGetInfoRequest req, const char *url);
BifTransactionGetInfoResponse *
get_tx_cache_data(BifTransactionGetInfoRequest req, const char *url);
BifTransactionGetInfoResponse *parse_blob(BifParseBlobRequest req,
                                          const char *url);

BifTransactionSubmitResponse *bif_submit(BifTransactionSubmitRequest req,
                                         const char *url);
char *serializable_transaction(BifTransactionSerializeRequest req,
                               const char *url);
char *batch_serializable_transaction(BifBatchSerializeRequest req,
                                     const char *url);
BifTransactionSubmitResponse *gas_send(BifTransactionGasSendRequest req,
                                       const char *url);
BifTransactionSubmitResponse *batch_gas_send(BifBatchGasSendRequest req,
                                             const char *url);
BifTransactionGetInfoResponse *evaluate_fee(BifEvaluateFeeRequest req,
                                            const char *url);
BifTransactionGetInfoResponse *
evaluate_batch_fee(BifEvaluateFeeBatchRequest req, const char *url);
void transaction_info_response_release(
    BifTransactionGetInfoResponse *transaction_info_response);
void transaction_submit_response_release(
    BifTransactionSubmitResponse *transaction_submit_response);
void transaction_cachesize_response_release(
    BifTransactionGetTxCacheSizeResponse *transaction_cachesize_response);

#ifdef __cplusplus
}
#endif
#endif