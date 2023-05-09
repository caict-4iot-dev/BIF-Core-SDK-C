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
 * @file: contract_service.h
 */

#ifndef __CONTRACT_SERVICE_H__
#define __CONTRACT_SERVICE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "request/contract_request.h"
#include "response/contract_response.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

BifContractCheckValidResponse *
check_contract_address(BifContractCheckValidRequest req, const char *url);
BifContractCheckValidResponse *
get_contract_info(BifContractCheckValidRequest req, const char *url);
BifContractGetInfoResponse *
get_contract_address(BifContractGetAddressRequest req, const char *url);
BifContractGetInfoResponse *contract_create(BifContractCreateRequest req,
                                            const char *url);
BifContractGetInfoResponse *contract_query(BifContractCallRequest req,
                                           const char *url);
BifContractGetInfoResponse *contract_invoke(BifContractInvokeRequest req,
                                            const char *url);
BifContractGetInfoResponse *
contract_batch_invoke(BifBatchContractInvokeRequest req, const char *url);
// 初始化赋值sds类型变量的接口
void input_sds_initialize(sds *input, char *buf);
// 合约响应结构体的内存释放函数接口
void contract_info_response_release(
    BifContractGetInfoResponse *contract_response);
void contract_valid_response_release(BifContractCheckValidResponse *contract_valid_response);
void contract_sds_request_release(sds contract_sds_request);

#ifdef __cplusplus
}
#endif
#endif