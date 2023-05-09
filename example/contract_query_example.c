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
 * @file: contract_query_example.c
 */

#include "contract_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 创建合约example
  BifContractGetInfoResponse *res_contract_query;
  BifContractCallRequest req_contract_query;
  memset(&req_contract_query, 0, sizeof(BifContractCallRequest));
  char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";

  input_sds_initialize(&req_contract_query.input,
                       init_input); // 初始化赋值给sds类型的变量接口
  // strcpy(req_contract_query.contract_address,
  // "efjijAvhn6hVCnEueAm52rp9N6hwS2bf");
  strcpy(req_contract_query.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  strcpy(req_contract_query.source_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  // req_contract_query.domainid = 0;
  // req_contract_query.gas_price = 100;
  // req_contract_query.fee_limit = 1000000000;

  res_contract_query = contract_query(req_contract_query, bif_url);
  if (res_contract_query->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_contract_query->baseResponse.code,
           res_contract_query->baseResponse.msg);
  else
    printf("%s\n", res_contract_query->value);
  contract_info_response_release(res_contract_query);
  // 释放请求体中sds类型的内存变量
  contract_sds_request_release(req_contract_query.input);

  return 0;
}