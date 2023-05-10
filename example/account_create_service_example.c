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
 * @file: account_create_service_example.c
 */

#include "account_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  // 创建账户
  BifAccountResponse *res_create_account;
  BifCreateAccountRequest req_create_account;
  memset(&req_create_account, 0, sizeof(BifCreateAccountRequest));

  req_create_account.domainid = 0;
  strcpy(req_create_account.private_key,
         "priSPKir4tnCmj6wmBxyaL2ZuAF5TKpf81mYRv4LbeGTGWRjrr");
  strcpy(req_create_account.sender_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  strcpy(req_create_account.dest_address,
         "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnofEi");
  req_create_account.init_balance = 1000000;
  strcpy(req_create_account.remarks, "testremarks");

  res_create_account = create_account(req_create_account, bif_url);
  if (res_create_account->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_create_account->baseResponse.code,
           res_create_account->baseResponse.msg);
  else
    printf("%s\n", res_create_account->value);
  account_response_release(res_create_account); // 释放内存资源

  return 0;
}