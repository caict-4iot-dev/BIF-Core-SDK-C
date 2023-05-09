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
 * @file: general.h
 */

#ifndef __GENERAL_H__
#define __GENERAL_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "request/account_request.h"
#include "request/block_request.h"
#include "request/contract_request.h"
#include "request/transaction_request.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADDRESS_MAX_LENGTH 128
/****************************************************************
 * api function
 ****************************************************************/
// sprintf < 0 failed
int account_get_info_url(const char *url, BifAccountGetInfoRequest *req,
                         char *accountUrl);
int account_get_metadata_url(const char *url,
                             BifAccountGetMetadatasRequest *req, char *metaUrl);
int contract_getInfo_url(const char *url, BifContractCheckValidRequest *req,
                         char *contract_url);
int evaluation_fee_url(const char *url, char *transaction_evaluation_url);

int transaction_submit_url(const char *url, char *submitUrl);
int contract_call_query_url(const char *url, char *contract_query_url);
int transaction_get_info_url(const char *url, BifTransactionGetInfoRequest *req,
                             char *transaction_by_hash_url);
int get_transactions_url(const char *url, BifBlockGetTransactionsRequest *req,
                         char *get_number_url);
int transaction_blob_url(const char *url, char *blob_url);
int parse_blob_url(const char *url, BifParseBlobRequest *req, char *blob_url);

int block_get_number_url(const char *url, const int domainid,
                         char *get_number_url);
int block_get_info_url(const char *url, BifBlockGetInfoRequest *req,
                       char *block_info_url);
int block_latest_info_url(const char *url, BifBlockGetLatestInfoRequest *req,
                          char *block_latest_url);
int get_validators_url(const char *url, BifBlockGetValidatorsRequest *req,
                       char *validator_url);
int get_latest_validators_url(const char *url,
                              BifBlockGetValidatorsRequest *req,
                              char *validators_url);

int get_tx_cache_size_url(int domainid, const char *url,
                          char *tx_cache_size_url);
int get_tx_cache_url(const char *url, BifTransactionGetInfoRequest *req,
                     char *cache_data_url);
void sdk_free(void *p);
void *sdk_malloc(size_t size);
int check_addr_prefix(const char *address);

#ifdef __cplusplus
}
#endif
#endif