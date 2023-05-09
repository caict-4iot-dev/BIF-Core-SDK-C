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
 * @file: contract_batch_invoke_example.c
 */

#include "contract_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 创建合约example
  BifContractGetInfoResponse *res_batch_invoke;
  BifBatchContractInvokeRequest req_batch_invoke;
  memset(&req_batch_invoke, 0, sizeof(BifBatchContractInvokeRequest));
  char init_input[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv\",\"return\":\"returns(string)\"}";
  char init_input2[] =
      "{\"function\":\"queryBanance(string)\",\"args\":\"did:bid:"
      "ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU\",\"return\":\"returns(string)\"}";

  input_sds_initialize(&req_batch_invoke.operation_batch_data[0].input,
                       init_input); // 初始化赋值请求中sds类型变量值接口
  input_sds_initialize(&req_batch_invoke.operation_batch_data[1].input,
                       init_input);

  strcpy(req_batch_invoke.operation_batch_data[0].contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  strcpy(req_batch_invoke.operation_batch_data[1].contract_address,
         "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU");
  req_batch_invoke.operation_batch_data[0].amount = 0;
  req_batch_invoke.operation_batch_data[1].amount = 0;
  req_batch_invoke.operation_batch_num = 2; // operation_batch_data结构体数量

  strcpy(req_batch_invoke.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_batch_invoke.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  strcpy(req_batch_invoke.remarks, "0123456789abcdef");
  // req_batch_invoke.domainid = 0;
  // req_batch_invoke.gas_price = 200;
  // req_batch_invoke.fee_limit = 2000000;
  // req_batch_invoke.ceil_ledger_seq = 0;

  res_batch_invoke = contract_batch_invoke(req_batch_invoke, bif_url);
  if (res_batch_invoke->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_batch_invoke->baseResponse.code,
           res_batch_invoke->baseResponse.msg);
  else
    printf("%s\n", res_batch_invoke->value);
  // sdk接口使用完，最后要调用释放内存函数
  contract_info_response_release(res_batch_invoke);
  // 释放请求体中sds类型的内存变量
  contract_sds_request_release(req_batch_invoke.operation_batch_data[0].input);
  // 释放请求体中sds类型的内存变量
  contract_sds_request_release(req_batch_invoke.operation_batch_data[1].input);

  return 0;
}
