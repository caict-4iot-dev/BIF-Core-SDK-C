
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
 * @file: contract_invoke_example.c
 */
#include "contract_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 创建合约example
  BifContractGetInfoResponse *res_contract_invoke;
  BifContractInvokeRequest req_contract_invoke;
  memset(&req_contract_invoke, 0, sizeof(BifContractInvokeRequest));
  char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";
  input_sds_initialize(&req_contract_invoke.input,
                       init_input); // 初始化赋值给sds类型的变量接口
  // 根据实际部署节点的合约地址等测试信息
  strcpy(req_contract_invoke.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  strcpy(req_contract_invoke.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_contract_invoke.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  strcpy(req_contract_invoke.remarks, "test1234");
  // req_contract_invoke.domainid = 0;
  // req_contract_invoke.gas_price = 100;
  // req_contract_invoke.fee_limit = 2000000;
  req_contract_invoke.amount = 0;

  res_contract_invoke = contract_invoke(req_contract_invoke, bif_url);
  if (res_contract_invoke->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_contract_invoke->baseResponse.code,
           res_contract_invoke->baseResponse.msg);
  else
    printf("%s\n", res_contract_invoke->value);
  contract_info_response_release(res_contract_invoke);
  // 释放请求体中sds类型的内存变量
  contract_sds_request_release(req_contract_invoke.input);

  return 0;
}