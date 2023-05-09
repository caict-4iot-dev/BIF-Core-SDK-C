
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
 * @file: block_service.c
 */
#include "block_service.h"
#include "curl/curl.h"
#include "general.h"
#include "http.h"
#include "jansson.h"
#include "sdk_error.h"

extern SdkError system_error;
extern SdkError connectnetwork_error;
extern SdkError invalid_domainid_error;
extern SdkError request_empty_error;
extern SdkError invalid_blocknumber_error;
BifBlockGetNumberResponse *get_block_number(BifBlockGetTransactionsRequest req,
                                            const char *url) {
  BifBlockGetNumberResponse *res;
  char get_number_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  json_error_t error;

  res = (BifBlockGetNumberResponse *)malloc(sizeof(BifBlockGetNumberResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  int ret = block_get_number_url(url, req.domainid, get_number_url);
  ret = http_get(get_number_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  res->value = value;
  res->baseResponse.code = 0;

  json_t *valueJson = json_loads(value, 0, &error);
  json_t *result = json_object_get(valueJson, "result");
  json_t *header = json_object_get(result, "header");
  res->block_number = json_integer_value(json_object_get(header, "seq"));
  json_decref(valueJson);

  // 返回res响应
  return res;
}
BifBlockGetInfoResponse *get_transactions(BifBlockGetTransactionsRequest req,
                                          const char *url) {

  BifBlockGetInfoResponse *res;
  char transactions_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifBlockGetInfoResponse *)malloc(sizeof(BifBlockGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (req.block_number <= 0) {
    res->baseResponse = invalid_blocknumber_error.res;
    return res;
  }
  int ret = get_transactions_url(url, &req, transactions_url);
  ret = http_get(transactions_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifBlockGetInfoResponse *get_block_info(BifBlockGetInfoRequest req,
                                        const char *url) {
  BifBlockGetInfoResponse *res;
  char block_info_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifBlockGetInfoResponse *)malloc(sizeof(BifBlockGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (req.block_number <= 0) {
    res->baseResponse = invalid_blocknumber_error.res;
    return res;
  }

  int ret = block_get_info_url(url, &req, block_info_url);
  ret = http_get(block_info_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  // 返回res响应
  return res;
}

BifBlockGetInfoResponse *get_block_latest_info(BifBlockGetLatestInfoRequest req,
                                               const char *url) {
  BifBlockGetInfoResponse *res;
  char block_latest_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifBlockGetInfoResponse *)malloc(sizeof(BifBlockGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }

  int ret = block_latest_info_url(url, &req, block_latest_url);
  ret = http_get(block_latest_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  // 返回res响应
  return res;
}

BifBlockGetInfoResponse *get_validators(BifBlockGetValidatorsRequest req,
                                        const char *url) {
  BifBlockGetInfoResponse *res;
  char block_validators_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifBlockGetInfoResponse *)malloc(sizeof(BifBlockGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (req.block_number <= 0) {
    res->baseResponse = invalid_blocknumber_error.res;
    return res;
  }
  int ret = get_validators_url(url, &req, block_validators_url);
  ret = http_get(block_validators_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  // 返回res响应
  return res;
}

BifBlockGetInfoResponse *get_latest_validators(BifBlockGetValidatorsRequest req,
                                               const char *url) {
  BifBlockGetInfoResponse *res;
  char validators_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifBlockGetInfoResponse *)malloc(sizeof(BifBlockGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }

  int ret = get_latest_validators_url(url, &req, validators_url);
  ret = http_get(validators_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  // 返回res响应
  return res;
}
void block_get_num_response_release(BifBlockGetNumberResponse *res_block) {
  sdk_free(res_block->value);
  sdk_free(res_block);
}
void block_info_response_release(BifBlockGetInfoResponse *res_block) {
  sdk_free(res_block->value);
  sdk_free(res_block);
}