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
 * @file: block_get_service_example.c
 */

#include "block_service.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char bif_url[64] = "http://172.17.6.84:30010";

  BifBlockGetTransactionsRequest req;
  BifBlockGetNumberResponse *res;
  memset(&req, 0, sizeof(req));
  req.domainid = 0;
  // 查询区块高度
  res = get_block_number(req, bif_url);
  if (res->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res->baseResponse.code, res->baseResponse.msg);
  else
    printf("get_block_number res:%s,seq:%d\n", res->value, res->block_number);
  block_get_num_response_release(res);

  // 查询对应区块的交易信息
  BifBlockGetTransactionsRequest req_tranction;
  BifBlockGetInfoResponse *res_tranction;
  memset(&req_tranction, 0, sizeof(BifBlockGetTransactionsRequest));
  req_tranction.block_number = 104928;
  res_tranction = get_transactions(req_tranction, bif_url);
  if (res_tranction->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_tranction->baseResponse.code,
           res_tranction->baseResponse.msg);
  else
    printf("res_tranction res:%s\n", res_tranction->value);
  block_info_response_release(res_tranction);

  // 查询指定区块的所有信息
  BifBlockGetInfoRequest req_block_get_info;
  BifBlockGetInfoResponse *res_block_get_info;
  memset(&req_block_get_info, 0, sizeof(BifBlockGetInfoRequest));
  req_block_get_info.block_number = 11500;
  req_block_get_info.domainid = 0;
  res_block_get_info = get_block_info(req_block_get_info, bif_url);
  // printf("resBlockGetInfo all:%s\n", resBlockGetInfo->value);
  if (res_block_get_info->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_block_get_info->baseResponse.code,
           res_block_get_info->baseResponse.msg);
  else
    printf("res_block_get_info res:%s\n", res_block_get_info->value);
  block_info_response_release(res_block_get_info);

  // 查询获取最新区块信息
  BifBlockGetLatestInfoRequest req_block_get_latest_info;
  BifBlockGetInfoResponse *res_block_get_latest_info;
  memset(&req_block_get_latest_info, 0, sizeof(BifBlockGetLatestInfoRequest));
  req_block_get_latest_info.domainid = 0;
  res_block_get_latest_info =
      get_block_latest_info(req_block_get_latest_info, bif_url);
  if (res_block_get_latest_info->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_block_get_latest_info->baseResponse.code,
           res_block_get_latest_info->baseResponse.msg);
  else
    printf("res_block_get_latest_info:%s\n", res_block_get_latest_info->value);
  block_info_response_release(res_block_get_latest_info);

  // 查询指定区块高度的validator信息
  BifBlockGetValidatorsRequest req_get_validators;
  BifBlockGetInfoResponse *res_get_validators;
  req_get_validators.block_number = 1150;
  req_get_validators.domainid = 0;
  res_get_validators = get_validators(req_get_validators, bif_url);
  if (res_get_validators->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_get_validators->baseResponse.code,
           res_get_validators->baseResponse.msg);
  else
    printf("res_get_validators:%s\n", res_get_validators->value);
  block_info_response_release(res_get_validators);

  // 查询最新区块的validator信息
  BifBlockGetValidatorsRequest req_latest_validators;
  BifBlockGetInfoResponse *res_latest_validators;
  req_latest_validators.domainid = 0;
  res_latest_validators = get_latest_validators(req_latest_validators, bif_url);
  if (res_latest_validators->baseResponse.code != 0)
    printf("code:%d,msg:%s\n", res_latest_validators->baseResponse.code,
           res_latest_validators->baseResponse.msg);
  else
    printf("res_latest_validators:%s\n", res_latest_validators->value);
  block_info_response_release(res_latest_validators);

  return 0;
}