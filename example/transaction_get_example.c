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
 * @file: transaction_get_example.c
 */

// #include "account_service.h"
// #include "block_service.h"
// #include "contract_service.h"
// #include "general.h"
// #include "http.h"
// #include "key_pair_entity.h"
// #include "private_key_manager.h"
// #include "public_key_manager.h"
// #include "sdk_error.h"
#include "transaction_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 交易服务模块-获取交易池交易条数接口
  BifTransactionGetTxCacheSizeResponse *res_get_tx_cache_size;
  int domainid = 1;
  res_get_tx_cache_size = get_tx_cache_size(domainid, bif_url);
  if (res_get_tx_cache_size->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_get_tx_cache_size->baseResponse.code,
           res_get_tx_cache_size->baseResponse.msg);
  else
    printf("%s\n\n", res_get_tx_cache_size->value);
  transaction_cachesize_response_release(res_get_tx_cache_size); // 释放内存

  // 根据hash获取交易信息
  BifTransactionGetInfoRequest req_transaction_get_info;
  BifTransactionGetInfoResponse *res_transaction_get_info;
  memset(&req_transaction_get_info, 0, sizeof(BifTransactionGetInfoRequest));
  req_transaction_get_info.domainid = 0;
  char hash_data[] =
      "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
  strcpy(req_transaction_get_info.hash, hash_data);

  res_transaction_get_info =
      get_transaction_info(req_transaction_get_info, bif_url);
  if (res_transaction_get_info->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_transaction_get_info->baseResponse.code,
           res_transaction_get_info->baseResponse.msg);
  else
    printf("%s\n\n", res_transaction_get_info->value);
  transaction_info_response_release(res_transaction_get_info);

  // 获取交易池信息
  BifTransactionGetInfoRequest req_get_cache_data;
  BifTransactionGetInfoResponse *res_get_cache_data;
  memset(&req_get_cache_data, 0, sizeof(BifTransactionGetInfoRequest));
  req_get_cache_data.domainid = 0;
  char hash_temp[] =
      "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
  // strcpy(req_get_cache_data.hash, hash_temp);
  res_get_cache_data = get_tx_cache_data(req_get_cache_data, bif_url);
  if (res_get_cache_data->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_get_cache_data->baseResponse.code,
           res_get_cache_data->baseResponse.msg);
  else
    printf("%s\n\n", res_get_cache_data->value);
  transaction_info_response_release(res_get_cache_data);

  // parseblob接口
  BifTransactionGetInfoResponse *res_blob;
  BifParseBlobRequest req_blob;
  memset(&req_blob, 0, sizeof(BifParseBlobRequest));

  char blob_data[] =
      "0a296469643a6269643a6566324175414a69643164423232726b334d3676423663556331"
      "454e6e7066456510022234080752300a286469643a6269643a65664e69515045476e6854"
      "5071614661746f463170397767723135325036384610081a027b7d2a080123456789abcd"
      "ef30c0843d3801";
  int len = strlen(blob_data) + 1;
  req_blob.blob = (char *)malloc(len);
  memset(req_blob.blob, 0, len);
  strcpy(req_blob.blob, blob_data);
  res_blob = parse_blob(req_blob, bif_url);
  if (res_blob->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_blob->baseResponse.code,
           res_blob->baseResponse.msg);
  else
    printf("%s\n\n", res_blob->value);
  sdk_free(req_blob.blob); // 释放请求体中使用的内存变量接口
  transaction_info_response_release(res_blob); // 释放最后响应体的内存资源

  return 0;
}
