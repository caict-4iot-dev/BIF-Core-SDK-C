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
 * @file: account_set_privilege_example.c
 */

#include "account_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  // 设置账户metadatas
  BifAccountResponse *res_set_privilege;
  BifAccountSetPrivilegeRequest req_set_privilege;
  memset(&req_set_privilege, 0, sizeof(BifAccountSetPrivilegeRequest));
  char *address = "did:bid:efNiQPEGnhTPqaFatoF1p9wgr152P68F";

  req_set_privilege.signers_num = 1;
  strcpy(req_set_privilege.signers[0].address, address);
  
  strcpy(req_set_privilege.private_key,
         "priSPKs6YyWpMo5VDxTKLFbLYczZP1i3cffrR9c4UbsyXhFcRz");
  strcpy(req_set_privilege.sender_address,
         "did:bid:efVcUVBoUjXokjYoWW7VoLC3K6BxnpaZ");
  req_set_privilege.type_threshold_num = 2;
  req_set_privilege.typeThresholds[0].type = 1;
  req_set_privilege.typeThresholds[0].threshold = 100;
  req_set_privilege.typeThresholds[1].type = 7;
  req_set_privilege.typeThresholds[1].threshold = 200;
  strcpy(req_set_privilege.master_weight, "1");
  strcpy(req_set_privilege.remarks, "test12");
  req_set_privilege.signers_num = 1;
  strcpy(req_set_privilege.signers[0].address,
         "did:bid:efjijAvhn6hVCnEueAm52rp9N6hwS24r");
  req_set_privilege.signers[0].weight = 1000;
  res_set_privilege = set_privilege(req_set_privilege, bif_url);
  if (res_set_privilege->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_set_privilege->baseResponse.code,
           res_set_privilege->baseResponse.msg);
  else
    printf("%s\n", res_set_privilege->value);
  account_response_release(res_set_privilege); // 释放内存资源

  return 0;
}