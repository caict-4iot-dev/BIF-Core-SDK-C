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
 * @file: contract_get_example.c
 */

#include "contract_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  // 合约模块-根据address domainid获取合约地址是否可用接口
  BifContractCheckValidRequest req_check_contract_addr;
  BifContractCheckValidResponse *res_contract_check_addr;
  memset(&req_check_contract_addr, 0, sizeof(BifContractCheckValidRequest));
  // req_check_contract_addr.domainid = 21;
  strcpy(req_check_contract_addr.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  res_contract_check_addr =
      check_contract_address(req_check_contract_addr, bif_url);

  if (res_contract_check_addr->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_contract_check_addr->baseResponse.code,
           res_contract_check_addr->baseResponse.msg);
  else
    printf("check_contract_address:%s\n\n", res_contract_check_addr->value);
  contract_valid_response_release(res_contract_check_addr);

  // 合约模块-根据address domainid获取合约信息接口
  BifContractCheckValidRequest req_contract_info;
  BifContractCheckValidResponse *res_contract_info;
  memset(&req_contract_info, 0, sizeof(BifContractCheckValidRequest));
  req_contract_info.domainid = 0;
  strcpy(req_contract_info.contract_address,
         "did:bid:efoyBUQzHSCeCj3VQk4uSxiZW9GRYcJv");
  res_contract_info = get_contract_info(req_contract_info, bif_url);

  if (res_contract_info->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_contract_info->baseResponse.code,
           res_contract_info->baseResponse.msg);
  else
    printf("get_contract_info:%s\n", res_contract_info->value);
  contract_valid_response_release(res_contract_info);

  // 合约模块-get_contract_address接口
  BifContractGetAddressRequest req_contract_addr;
  BifContractGetInfoResponse *res_contract_addr;
  memset(&req_contract_addr, 0, sizeof(BifContractGetAddressRequest));
  // req_contract_addr.domainid = 21;
  // hash根据实际节点交易生成的值即可
  char hash_test[] =
      "2f25e770b7ede0966a920cc91503d5354be0b87e2cb3d237869449cd4290101f";
  strcpy(req_contract_addr.hash, hash_test);
  res_contract_addr = get_contract_address(req_contract_addr, bif_url);

  if (res_contract_addr->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_contract_addr->baseResponse.code,
           res_contract_addr->baseResponse.msg);
  else
    printf("get_contract_address:%s\n", res_contract_addr->value);
  contract_info_response_release(res_contract_addr);

  return 0;
}