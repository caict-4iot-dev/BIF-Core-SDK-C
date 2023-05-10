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
 * @file: account_get_service_example.c
 */

#include "account_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://test.bifcore.bitfactory.cn";

  // 账户服务模块-get查询指定账户基础信息接口
  BifAccountGetInfoRequest req_account_base;
  BifAccountResponse *res_account_base;
  memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
  strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

  req_account_base.domainid = 0;
  // 获取账户信息接口的函数
  res_account_base = get_account(req_account_base, bif_url);

  // 获取账户信息
  if (res_account_base->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_account_base->baseResponse.code,
           res_account_base->baseResponse.msg);
  else
    printf("%s\n\n", res_account_base->value);
  account_response_release(res_account_base); //释放内存资源


  // 获取账户balance
  memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
  strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  res_account_base = get_account_balance(req_account_base, bif_url);
  if (res_account_base->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_account_base->baseResponse.code,
           res_account_base->baseResponse.msg);
  else
    printf("%s\n\n", res_account_base->value);
  account_response_release(res_account_base); //释放内存资源

  // 查询指定地址的metadatas接口
  BifAccountGetMetadatasRequest req_metadata;
  BifAccountResponse *res_metadata;
  memset(&req_metadata, 0, sizeof(req_metadata));
  req_metadata.domainid = 0;
  // strcpy(req_metadata.key, "zzl03");
  strcpy(req_metadata.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");

  res_metadata = get_account_metadatas(req_metadata, bif_url);
  if (res_metadata->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_metadata->baseResponse.code,
           res_metadata->baseResponse.msg);
  else
    printf("get_account_metadatas: %s\n\n", res_metadata->value);
  account_response_release(res_metadata); //释放内存资源

  // 获取指定账户权限接口
  memset(&req_account_base, 0, sizeof(BifAccountGetInfoRequest));
  strcpy(req_account_base.address, "did:bid:ef2AuAJid1dB22rk3M6vB6cUc1ENnpfEe");
  res_account_base = get_account_priv(req_account_base, bif_url);
  if (res_account_base->baseResponse.code != 0)
    printf("code:%d,msg:%s\n\n", res_account_base->baseResponse.code,
           res_account_base->baseResponse.msg);
  else
    printf("%s\n\n", res_account_base->value);
  account_response_release(res_account_base); //释放内存资源

  // 获取所需的nonce值
  BifAccountGetInfoRequest req_nonce;
  memset(&req_nonce, 0, sizeof(req_nonce));
  req_nonce.domainid = 0;
  memset(req_nonce.address, 0, sizeof(req_nonce.address));
  strcpy(req_nonce.address, "did:bid:zfVjEZWe3u2NPpqn7J5Cww1jK3VnW646");
  res_account_base = get_nonce(req_nonce, bif_url);
  if (res_account_base->baseResponse.code != 0)
    printf("code:%d,msg:%s\n\n", res_account_base->baseResponse.code,
           res_account_base->baseResponse.msg);
  else
    printf("%s\n\n", res_account_base->value);
  account_response_release(res_account_base); //释放内存资源

  return 0;
}