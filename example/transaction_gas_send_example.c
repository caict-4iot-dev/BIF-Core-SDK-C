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
 * @file: transaction_gas_send_example.c
 */

#include "transaction_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 序列化交易gasSend发交易接口
  BifTransactionGasSendRequest req_gas_send;
  BifTransactionSubmitResponse *res_gas_send;
  memset(&req_gas_send, 0, sizeof(BifTransactionGasSendRequest));

  req_gas_send.amount = 11;
  // req_gas_send.domainid = 0;
  // req_gas_send.fee_limit = 10000000;
  // req_gas_send.gas_price = 1;
  strcpy(req_gas_send.dest_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEp");
  // strcpy(req_gas_send.dest_address,
  // "did:bid:zf32dF6p2NA1Dzw6ySQThL2v9W3Dmbje");
  strcpy(req_gas_send.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_gas_send.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");

  res_gas_send = gas_send(req_gas_send, bif_url);
  if (res_gas_send->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_gas_send->baseResponse.code,
           res_gas_send->baseResponse.msg);
  else
    printf("%s\n", res_gas_send->value);
  transaction_submit_response_release(res_gas_send);

  return 0;
}
