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
 * @file: contract_create_example.c
 */

#include "contract_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 创建合约example
  BifContractGetInfoResponse *res_create_contract;
  BifContractCreateRequest req_create_contract;
  memset(&req_create_contract, 0, sizeof(BifContractCreateRequest));
  char payload[] =
      "\"use strict\";function queryBanance1(address)\r\n{return \" test query "
      "private contract\";}\r\nfunction create1(input)\r\n{let key = "
      "\"private_tx_\"+input.id;let value = \"set private id "
      "\"+input.id;Chain.store(key,value);}\r\nfunction "
      "init(input)\r\n{return;}\r\nfunction "
      "main(input)\r\n{return;}\r\nfunction query1(input)\r\n{let key = "
      "\"private_tx_\"+input.id;let data = Chain.load(key);return data;}";
  input_sds_initialize(&req_create_contract.payload,
                       payload); // 初始化赋值请求中sds类型变量接口
  // req_create_contract.payload = sdscpy(req_create_contract.payload, payload);
  // // 类似库函数memcpy的封装
  //  req_create_contract.domainid = 0;
  req_create_contract.gas_price = 10;
  req_create_contract.fee_limit = 100000000;

  strcpy(req_create_contract.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  strcpy(req_create_contract.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  req_create_contract.contract_type = TYPE_V8;
  req_create_contract.init_balance = 100000000;

  res_create_contract = contract_create(req_create_contract, bif_url);
  if (res_create_contract->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_create_contract->baseResponse.code,
           res_create_contract->baseResponse.msg);
  else
    printf("%s\n", res_create_contract->value);
  contract_info_response_release(res_create_contract);
  contract_sds_request_release(req_create_contract.payload);

  return 0;
}