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
 * @date: 2023-05-09 09:57:00
 * @file: evaluate_batch_example.c
 */

#include "transaction_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  BifEvaluateFeeBatchRequest req_evaluate;
  BifTransactionGetInfoResponse *res_evaluate;
  memset(&req_evaluate, 0, sizeof(BifEvaluateFeeBatchRequest));

  req_evaluate.operation_datas[0].call_operation.amount = 10;
  req_evaluate.operation_datas[1].call_operation.amount = 12;
  strcpy(req_evaluate.operation_datas[0].call_operation.dest_address,
         "did:bid:zf6LBRqPHfXjg46JqkCTqGb8QM9GTFB78");
  strcpy(req_evaluate.operation_datas[1].call_operation.dest_address,
         "did:bid:ef2CENizhXm2VJYmHV1a8HULb2Xg32QcU");
  req_evaluate.operation_num = 2;
  strcpy(req_evaluate.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_evaluate.remarks, "0123456789abcdef");
  strcpy(req_evaluate.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

  res_evaluate = evaluate_batch_fee(req_evaluate, bif_url);
  if (res_evaluate->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_evaluate->baseResponse.code,
           res_evaluate->baseResponse.msg);
  else
    printf("%s\n", res_evaluate->value);
  transaction_info_response_release(res_evaluate);

  return 0;
}