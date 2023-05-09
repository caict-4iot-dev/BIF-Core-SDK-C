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
 * @file: account_service.h
 */

#ifndef __ACCOUNT_SERVICE_H__
#define __ACCOUNT_SERVICE_H__
#ifdef __cplusplus
extern "C" {
#endif

#include "request/account_request.h"
#include "response/account_response.h"
#include "transaction_service.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

BifAccountResponse *get_account(BifAccountGetInfoRequest req, const char *url);
BifAccountResponse *get_account_balance(BifAccountGetInfoRequest req,
                                        const char *url);
BifAccountResponse *get_account_metadatas(BifAccountGetMetadatasRequest req,
                                          const char *url);
int get_nonce_parse_json(BifAccountGetInfoRequest req, const char *url);
BifAccountResponse *get_nonce(BifAccountGetInfoRequest req, const char *url);

BifAccountResponse *get_account_priv(BifAccountGetInfoRequest req,
                                     const char *url);
BifAccountResponse *create_account(BifCreateAccountRequest req,
                                   const char *url);
BifAccountResponse *set_metadatas(BifAccountSetMetadatasRequest req,
                                  const char *url);
BifAccountResponse *set_privilege(BifAccountSetPrivilegeRequest req,
                                  const char *url);
void account_response_release(BifAccountResponse *account_response);
void account_request_meta_release(BifAccountSetMetadatasRequest *req);

#ifdef __cplusplus
}
#endif
#endif