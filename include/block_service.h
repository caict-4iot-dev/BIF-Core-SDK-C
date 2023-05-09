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
 * @date: 2023-03-01 16:16:36
 * @file: block_service.h
 */

#ifndef __BLOCK_SERVICE_H__
#define __BLOCK_SERVICE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "request/block_request.h"
#include "response/block_response.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

BifBlockGetNumberResponse *get_block_number(BifBlockGetTransactionsRequest req,
                                            const char *url);
BifBlockGetInfoResponse *get_transactions(BifBlockGetTransactionsRequest req,
                                          const char *url);
BifBlockGetInfoResponse *get_block_info(BifBlockGetInfoRequest req,
                                        const char *url);
BifBlockGetInfoResponse *get_block_latest_info(BifBlockGetLatestInfoRequest req,
                                               const char *url);
BifBlockGetInfoResponse *get_validators(BifBlockGetValidatorsRequest req,
                                        const char *url);
BifBlockGetInfoResponse *get_latest_validators(BifBlockGetValidatorsRequest req,
                                               const char *url);

void block_get_num_response_release(BifBlockGetNumberResponse *res_block);
void block_info_response_release(BifBlockGetInfoResponse *res_block);

#ifdef __cplusplus
}
#endif
#endif