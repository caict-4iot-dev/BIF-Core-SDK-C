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
 * @file: transaction_batch_gas_send_example.c
 */

#include "transaction_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  // 序列化交易gasSend发交易接口
  BifBatchGasSendRequest req_batch_gas_send;
  BifTransactionSubmitResponse *res_gas_send;
  memset(&req_batch_gas_send, 0, sizeof(BifBatchGasSendRequest));

  req_batch_gas_send.batch_gas_send_operation[0].amount = 100;
  strcpy(req_batch_gas_send.batch_gas_send_operation[0].dest_address,
         "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbjf");
  req_batch_gas_send.batch_gas_send_operation[1].amount = 100;
  strcpy(req_batch_gas_send.batch_gas_send_operation[1].dest_address,
         "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbjg");
  req_batch_gas_send.batch_gas_send_num = 2;

  strcpy(req_batch_gas_send.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_batch_gas_send.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

  res_gas_send = batch_gas_send(req_batch_gas_send, bif_url);
  if (res_gas_send->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_gas_send->baseResponse.code,
           res_gas_send->baseResponse.msg);
  else
    printf("%s\n", res_gas_send->value);
  transaction_submit_response_release(res_gas_send);

  return 0;
}