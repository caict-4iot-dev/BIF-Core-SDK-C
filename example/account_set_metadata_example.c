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
 * @file: account_set_metadata_example.c
 */

#include "account_service.h"
#include "general.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 设置账户metadatas
  BifAccountResponse *res_set_account_metasatas;
  BifAccountSetMetadatasRequest req_set_account_metasatas;

  char *key = "zzl04";
  char *value = "hello1";
  req_set_account_metasatas.operations_array[0].value =
      (char *)sdk_malloc(strlen(value) + 1);

  req_set_account_metasatas.operations_num = 1; // operations_array个数
  // memset(&req_set_account_metasatas,0,
  // sizeof(BifAccountSetMetadatasRequest));
  memset(&req_set_account_metasatas.private_key, 0,
         sizeof(req_set_account_metasatas.private_key));
  memset(&req_set_account_metasatas.sender_address, 0,
         sizeof(req_set_account_metasatas.private_key));
  memset(&req_set_account_metasatas.remarks, 0,
         sizeof(req_set_account_metasatas.remarks));

  // req_set_account_metasatas.ceil_ledger_seq = 0;
  req_set_account_metasatas.domainid = 0;
  req_set_account_metasatas.fee_limit = 0;
  req_set_account_metasatas.gas_price = 0;
  strcpy(req_set_account_metasatas.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  strcpy(req_set_account_metasatas.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

  strcpy(req_set_account_metasatas.operations_array[0].Key, key);
  strcpy(req_set_account_metasatas.operations_array[0].value, value);
  req_set_account_metasatas.operations_array[0].delete_flag = false;

  res_set_account_metasatas = set_metadatas(req_set_account_metasatas, bif_url);
  if (res_set_account_metasatas->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_set_account_metasatas->baseResponse.code,
           res_set_account_metasatas->baseResponse.msg);
  else
    printf("%s\n", res_set_account_metasatas->value);
  account_response_release(res_set_account_metasatas); // 释放内存资源
  account_request_meta_release(
      &req_set_account_metasatas); // 释放request中metadata内存资源

  return 0;
}