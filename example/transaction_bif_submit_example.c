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
 * @file: transaction_bif_submit_example.c
 */

#include "transaction_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  // 根据已有交易blob及签名信息的序列化交易bif_submit接口
  BifTransactionSubmitRequest req_submit;
  BifTransactionSubmitResponse *res_submit;
  memset(&req_submit, 0, sizeof(req_submit));

  char public_key[] =
      "b0656681fe6bbb5ef40fa464b6fb8335da40c6814be2a1fed750228deda2ac2d496e6e";
  char serializa[] =
      "0a296469643a6269643a6566324175414a69643164423232726b334d3676423663556331"
      "454e6e7066456510022234080752300a286469643a6269643a65664e69515045476e6854"
      "5071614661746f463170397767723135325036384610081a027b7d2a080123456789abcd"
      "ef30c0843d3801";
  char sign_data[] =
      "00d337a3bbd669bb8c3fbe96dd1bc0a7f9f15d888da3e065e9fa006954452a709373eec2"
      "add701881f4fb67addd31630b1f6fadbf029125c350e95b0df752401";
  strcpy(req_submit.public_key, public_key);
  req_submit.serialization = (char *)malloc(strlen(serializa) + 1);
  memset(req_submit.serialization, 0, strlen(serializa) + 1);
  strcpy(req_submit.serialization, serializa);
  strcpy(req_submit.sign_data, sign_data);

  res_submit = bif_submit(req_submit, bif_url);
  if (res_submit->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_submit->baseResponse.code,
           res_submit->baseResponse.msg);
  else
    printf("bif_submit res:%s\n", res_submit->value);
  transaction_submit_response_release(res_submit);
  sdk_free(req_submit.serialization);
  return 0;
}
