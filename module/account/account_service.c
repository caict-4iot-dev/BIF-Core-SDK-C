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
 * @file: account_service.c
 */
#include "account_service.h"
#include "block_service.h"
#include "constant.h"
#include "curl/curl.h"
#include "general.h"
#include "http.h"
#include "jansson.h"
#include "sdk_error.h"
#include "sds.h"
#include "sdscompat.h"

extern SdkError system_error;
extern SdkError connectnetwork_error;
extern SdkError invalid_domainid_error;
extern SdkError request_empty_error;
extern SdkError invalid_blocknumber_error;
extern SdkError invalid_address_error;
extern SdkError invalid_datakey_error;
extern SdkError invalid_dstaddress_error;
extern SdkError invalid_initbalance_error;
extern SdkError privatekey_empty_error;
extern SdkError invalid_datavalue_error;
extern SdkError invalid_feelimit_error;
extern SdkError invalid_gasprice_error;
extern SdkError invalid_masterweight_error;
extern SdkError invalid_ceilledgerseq_error;
extern SdkError invalid_signerweight_error;
extern SdkError invalid_txthreshold_error;
extern SdkError invalid_typethreshold_error;
extern SdkError invalid_threshold_error;
#define UINT_MAX (INT_MAX * 2L + 1)

BifAccountResponse *get_account(BifAccountGetInfoRequest req, const char *url) {
  BifAccountResponse *res;
  char account_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }

  int ret = account_get_info_url(url, &req, account_url);
  ret = http_get(account_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifAccountResponse *get_account_balance(BifAccountGetInfoRequest req,
                                        const char *url) {
  BifAccountResponse *res;
  char get_nonce_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (!req.address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    res->baseResponse = invalid_address_error.res;
    // printf("invalid_address:%s, code:%d,msg:%s\n", req.address,
    // invalid_address_error.res.code,invalid_address_error.res.msg);
    return res;
  }

  int ret = account_get_info_url(url, &req, get_nonce_url);
  ret = http_get(get_nonce_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  int len = valueLen + 1;
  res->value = (char *)malloc(len);
  memset(res->value, 0, len);

  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *root = json_object();
    json_t *result = json_object();

    json_t *data = json_object_get(valueJson, "result");
    res->balance = 0;
    res->balance = json_integer_value(json_object_get(data, "balance"));
    json_object_set_new(root, "error_code", json_integer(error_code));
    json_object_set_new(result, "balance", json_integer(res->balance));
    json_object_set_new(root, "result", result);
    char *json_str = json_dumps(root, JSON_ENCODE_ANY);
    memcpy(res->value, json_str, strlen(json_str));
    json_decref(valueJson);
  } else {
    memcpy(res->value, value, len);
    json_decref(valueJson);
  }
  res->baseResponse.code = 0;
  if (value)
    free(value);
  // 返回res响应
  return res;
}

int get_nonce_parse_json(BifAccountGetInfoRequest req, const char *url) {
  char get_nonce_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  uint16_t nonce = 0;
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    return -1;
  }
  int ret = account_get_info_url(url, &req, get_nonce_url);
  ret = http_get(get_nonce_url, 5, &value, &valueLen);
  if (ret < 0) {
    return -1;
  }
  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *data = json_object_get(valueJson, "result");
    nonce = json_integer_value(json_object_get(data, "nonce"));
    json_decref(valueJson);
    return nonce;
  } else {
    return -1;
  }
  json_decref(valueJson);
  if (value)
    free(value);
  return 0;
}

BifAccountResponse *get_nonce(BifAccountGetInfoRequest req, const char *url) {
  char get_nonce_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  uint16_t nonce = 0;
  BifAccountResponse *res;
  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (!req.address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }

  int ret = account_get_info_url(url, &req, get_nonce_url);
  ret = http_get(get_nonce_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  int len = valueLen + 1;
  res->value = (char *)malloc(len);
  memset(res->value, 0, len);
  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *data = json_object_get(valueJson, "result");
    nonce = json_integer_value(json_object_get(data, "nonce"));
    json_t *root = json_object();
    json_t *result = json_object();

    json_object_set_new(root, "error_code", json_integer(error_code));
    json_object_set_new(result, "nonce", json_integer(nonce));
    json_object_set_new(root, "result", result);
    char *json_str = json_dumps(root, JSON_ENCODE_ANY);
    memcpy(res->value, json_str, strlen(json_str));
    json_decref(valueJson);
  } else {
    memcpy(res->value, value, len);
    json_decref(valueJson);
  }
  if (value)
    free(value);
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifAccountResponse *get_account_priv(BifAccountGetInfoRequest req,
                                     const char *url) {
  BifAccountResponse *res;
  char get_nonce_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (!req.address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }

  int ret = account_get_info_url(url, &req, get_nonce_url);
  ret = http_get(get_nonce_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  int len = valueLen + 1;
  res->value = (char *)malloc(len);
  memset(res->value, 0, len);

  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *root = json_object();
    json_t *result = json_object();
    json_t *priv_dump = json_object();
    json_t *thresholds_dump = json_object();

    json_t *data = json_object_get(valueJson, "result");
    json_t *priv_bif = json_object_get(data, "priv");

    json_object_set_new(root, "error_code", json_integer(error_code));
    json_object_set_new(result, "priv", priv_bif);
    json_object_set_new(root, "result", result);
    char *json_str = json_dumps(root, JSON_ENCODE_ANY);
    memcpy(res->value, json_str, len);
    json_decref(valueJson);
  } else {
    memcpy(res->value, value, len);
    json_decref(valueJson);
  }
  res->baseResponse.code = 0;
  if (value)
    free(value);
  // 返回res响应
  return res;
}

BifAccountResponse *get_account_metadatas(BifAccountGetMetadatasRequest req,
                                          const char *url) {
  BifAccountResponse *res;
  char get_metadatas_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (!req.address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.address) < 0 ||
      strlen(req.address) > ADDRESS_MAX_LENGTH || strlen(req.address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!req.key) {
    res->baseResponse = invalid_datakey_error.res;
    return res;
  } else if ((strlen(req.key) != 0 && strlen(req.key) < 1) ||
             strlen(req.key) > 1024) {
    res->baseResponse = invalid_datakey_error.res;
    return res;
  }

  int ret = account_get_metadata_url(url, &req, get_metadatas_url);
  if (ret == -1) {
    res->baseResponse = invalid_datakey_error.res;
    return res;
  }
  ret = http_get(get_metadatas_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  int len = valueLen + 1;
  res->value = (char *)malloc(len);
  memset(res->value, 0, len);

  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *root = json_object();
    json_t *result = json_object();
    json_t *array_metadata = json_array();
    char address[128] = {0};

    json_t *data = json_object_get(valueJson, "result");
    json_t *metadatas = json_object_get(data, "metadatas");
    int index = 0;
    json_t *value = NULL;

    json_object_set_new(root, "error_code", json_integer(error_code));
    json_array_foreach(metadatas, index, value) {
      json_t *metadata_dump = json_object();
      char *key = json_string_value(json_object_get(value, "key"));
      char *value_json = json_string_value(json_object_get(value, "value"));
      int version_json = json_integer_value(json_object_get(value, "version"));

      json_object_set_new(metadata_dump, "key", json_string(key));
      json_object_set_new(metadata_dump, "value", json_string(value_json));
      json_object_set_new(metadata_dump, "version", json_integer(version_json));
      json_array_append_new(array_metadata, metadata_dump);
    }
    json_object_set_new(result, "metadatas", array_metadata);
    json_object_set_new(root, "result", result);
    char *json_str = json_dumps(root, JSON_ENCODE_ANY);
    memcpy(res->value, json_str, len);
    json_decref(valueJson);

  } else {
    memcpy(res->value, value, len);
    json_decref(valueJson);
  }
  res->baseResponse.code = 0;
  if (value)
    free(value);
  // 返回res响应
  return res;
}

BifAccountResponse *create_account(BifCreateAccountRequest req,
                                   const char *url) {
  BifAccountResponse *res;
  char account_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (req.ceil_ledger_seq < 0) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.sender_address) < INIT_ZERO ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.sender_address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!req.dest_address) {
    res->baseResponse = invalid_dstaddress_error.res;
    return res;
  }
  if (check_addr_prefix(req.dest_address) < INIT_ZERO ||
      strlen(req.dest_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.dest_address) == 0) {
    res->baseResponse = invalid_dstaddress_error.res;
    return res;
  }
  if (req.init_balance <= INIT_ZERO || req.init_balance > LONG_MAX) {
    res->baseResponse = invalid_initbalance_error.res;
    return res;
  }
  if (!req.private_key) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (strlen(req.private_key) == INIT_ZERO) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (req.fee_limit < 0) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  } else if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price < 0) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  } else if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  BifAccountGetInfoRequest req_nonce;
  // 1.获取指定操作所需的nonce
  req_nonce.domainid = req.domainid;
  memset(req_nonce.address, 0, sizeof(req_nonce.address));
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    req.nonce = 1;
  } else {
    req.nonce = nonce + 1;
  }

  json_t *root = json_object();
  json_t *items_json = json_object();
  json_t *transaction_json = json_object();
  json_t *operation_data = json_object();
  json_t *create_account_data = json_object();
  // json_t *crontract_data = json_object();
  json_t *priv_data = json_object();
  json_t *thresholds_data = json_object();

  json_t *array_private = json_array();
  // json_t *array_metadatas = json_array();
  json_t *array_operations = json_array();
  json_t *array_items = json_array();

  json_array_append_new(array_private, json_string(req.private_key));
  json_object_set_new(items_json, "private_keys", array_private);

  if (req.ceil_ledger_seq > 0) {
    BifBlockGetTransactionsRequest req_block;
    BifBlockGetNumberResponse *res_block;
    memset(&req_block, 0, sizeof(req_block));
    req_block.domainid = req.domainid;
    // 查询区块高度
    res_block = get_block_number(req_block, url);

    req.ceil_ledger_seq = req.ceil_ledger_seq + res_block->block_number;
    sdk_free(res_block->value);
    sdk_free(res_block);
    json_object_set_new(transaction_json, "ceil_ledger_seq",
                        json_integer(req.ceil_ledger_seq));
  }
  json_object_set_new(transaction_json, "fee_limit",
                      json_integer(req.fee_limit));
  json_object_set_new(transaction_json, "gas_price",
                      json_integer(req.gas_price));
  json_object_set_new(transaction_json, "nonce", json_integer(req.nonce));
  json_object_set_new(transaction_json, "domain_id",
                      json_integer(req.domainid));
  json_object_set_new(transaction_json, "source_address",
                      json_string(req.sender_address));
  json_object_set_new(operation_data, "type", json_integer(1));
  json_object_set_new(create_account_data, "dest_address",
                      json_string(req.dest_address));
  json_object_set_new(create_account_data, "init_balance",
                      json_integer(req.init_balance));

  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(create_account_data, "metadata",
                          json_string(remarks_hex));
    }
  }
  json_object_set_new(priv_data, "master_weight", json_integer(1));
  json_object_set_new(thresholds_data, "tx_threshold", json_integer(1));
  json_object_set_new(priv_data, "thresholds", thresholds_data);
  json_object_set_new(create_account_data, "priv", priv_data);
  json_object_set_new(operation_data, "create_account", create_account_data);
  json_array_append_new(array_operations, operation_data);
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, account_url);
  ret = http_post(account_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    if (post_data)
      free(post_data);
    return res;
  }
  // int len = valueLen + 1;
  // res->value = (char*)malloc(len);
  // memset(res->value, 0, len);
  res->value = value;
  res->baseResponse.code = 0;

  if (post_data)
    free(post_data);
  return res;
}
BifAccountResponse *set_metadatas(BifAccountSetMetadatasRequest req,
                                  const char *url) {
  BifAccountResponse *res;
  char metadata_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (check_addr_prefix(req.sender_address) < INIT_ZERO ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      !strlen(req.sender_address)) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (strlen(req.private_key) == INIT_ZERO) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (req.ceil_ledger_seq < 0) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  for (i = 0; i < req.operations_num; i++) {
    if (strlen(req.operations_array[i].Key) < 1 ||
        strlen(req.operations_array[i].Key) > 1024) {
      res->baseResponse = invalid_datakey_error.res;
      return res;
    }
    if (strlen(req.operations_array[i].value) > 256000) {
      res->baseResponse = invalid_datavalue_error.res;
      return res;
    }
  }
  BifAccountGetInfoRequest req_nonce;
  // 1.获取指定操作所需的nonce
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    req.nonce = 1;
  } else {
    req.nonce = nonce + 1;
  }
  if (req.fee_limit < 0) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  } else if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price < 0) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  } else if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  json_t *root = json_object();
  json_t *items_json = json_object();
  json_t *transaction_json = json_object();

  json_t *array_operations = json_array();
  json_t *array_private = json_array();
  json_t *array_items = json_array();

  json_array_append_new(array_private, json_string(req.private_key));
  json_object_set_new(items_json, "private_keys", array_private);

  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(transaction_json, "metadata",
                          json_string(remarks_hex));
    }
  }

  json_object_set_new(transaction_json, "fee_limit",
                      json_integer(req.fee_limit));
  json_object_set_new(transaction_json, "gas_price",
                      json_integer(req.gas_price));
  json_object_set_new(transaction_json, "nonce", json_integer(req.nonce));
  json_object_set_new(transaction_json, "domain_id",
                      json_integer(req.domainid));
  json_object_set_new(transaction_json, "source_address",
                      json_string(req.sender_address));
  if (req.ceil_ledger_seq > 0) {
    BifBlockGetTransactionsRequest req_block;
    BifBlockGetNumberResponse *res_block;
    memset(&req_block, 0, sizeof(req_block));
    req_block.domainid = req.domainid;
    // 查询区块高度
    res_block = get_block_number(req_block, url);

    req.ceil_ledger_seq = req.ceil_ledger_seq + res_block->block_number;
    sdk_free(res_block->value);
    sdk_free(res_block);
    json_object_set_new(transaction_json, "ceil_ledger_seq",
                        json_integer(req.ceil_ledger_seq));
  }
  for (i = 0; i < req.operations_num; i++) {
    json_t *operation_data = json_object();
    json_t *set_meta_data = json_object();
    json_object_set_new(operation_data, "type", json_integer(4));
    json_object_set_new(set_meta_data, "key",
                        json_string(req.operations_array[i].Key));
    json_object_set_new(set_meta_data, "value",
                        json_string(req.operations_array[i].value));
    if (req.operations_array[i].version > 0) {
      json_object_set_new(set_meta_data, "version",
                          json_integer(req.operations_array[i].version));
    }
    if (req.operations_array[i].delete_flag) {
      json_object_set_new(set_meta_data, "delete_flag",
                          json_integer(req.operations_array[i].delete_flag));
    }
    json_object_set_new(operation_data, "set_metadata", set_meta_data);
    json_array_append_new(array_operations, operation_data);
  }
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, metadata_url);
  ret = http_post(metadata_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  if (post_data)
    free(post_data);
  return res;
}

BifAccountResponse *set_privilege(BifAccountSetPrivilegeRequest req,
                                  const char *url) {
  BifAccountResponse *res;
  char privilege_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res = (BifAccountResponse *)malloc(sizeof(BifAccountResponse));
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
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.sender_address) < INIT_ZERO ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      !strlen(req.sender_address)) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!req.private_key) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (strlen(req.private_key) == INIT_ZERO) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (atol(req.master_weight) > UINT_MAX || atol(req.master_weight) < 0) {
    res->baseResponse = invalid_masterweight_error.res;
    return res;
  }
  if (atol(req.tx_threshold) < 0 || atol(req.tx_threshold) > LONG_MAX) {
    res->baseResponse = invalid_txthreshold_error.res;
    return res;
  }
  if (req.ceil_ledger_seq < 0) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  if (req.fee_limit < 0) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  }
  if (req.gas_price < 0) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.signers_num > 0) {
    for (int j = 0; j < req.signers_num; j++) {
      if (check_addr_prefix(req.signers[j].address) < 0) {
        res->baseResponse = invalid_address_error.res;
        return res;
      }
      if (req.signers[j].weight > UINT_MAX || req.signers[j].weight < 0) {
        res->baseResponse = invalid_signerweight_error.res;
        return res;
      }
    }
  }
  if (req.type_threshold_num > 0) {
    for (int k = 0; k < req.type_threshold_num; k++) {
      if (req.typeThresholds[k].type < 0) {
        res->baseResponse = invalid_typethreshold_error.res;
        return res;
      }
      if (req.typeThresholds[k].threshold > LONG_MAX ||
          req.typeThresholds[k].threshold < 0) {
        res->baseResponse = invalid_threshold_error.res;
        return res;
      }
    }
  }

  BifAccountGetInfoRequest req_nonce;
  // 1.获取指定操作所需的nonce
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    req.nonce = 1;
  } else {
    req.nonce = nonce + 1;
  }
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  json_t *root = json_object();
  json_t *items_json = json_object();
  json_t *transaction_json = json_object();
  json_t *operation_data = json_object();
  json_t *set_privilege = json_object();

  json_t *array_signers = json_array();
  json_t *array_thresholds = json_array();
  json_t *array_private = json_array();
  json_t *array_operations = json_array();
  json_t *array_items = json_array();

  json_array_append_new(array_private, json_string(req.private_key));
  json_object_set_new(items_json, "private_keys", array_private);

  json_object_set_new(transaction_json, "fee_limit",
                      json_integer(req.fee_limit));
  json_object_set_new(transaction_json, "gas_price",
                      json_integer(req.gas_price));
  json_object_set_new(transaction_json, "nonce", json_integer(req.nonce));
  json_object_set_new(transaction_json, "domain_id",
                      json_integer(req.domainid));
  json_object_set_new(transaction_json, "source_address",
                      json_string(req.sender_address));
  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(transaction_json, "metadata",
                          json_string(remarks_hex));
    }
  }
  if (req.ceil_ledger_seq > 0) {
    BifBlockGetTransactionsRequest req_block;
    BifBlockGetNumberResponse *res_block;
    memset(&req_block, 0, sizeof(req_block));
    req_block.domainid = req.domainid;
    // 查询区块高度
    res_block = get_block_number(req_block, url);

    req.ceil_ledger_seq = req.ceil_ledger_seq + res_block->block_number;
    sdk_free(res_block->value);
    sdk_free(res_block);
    json_object_set_new(transaction_json, "ceil_ledger_seq",
                        json_integer(req.ceil_ledger_seq));
  }
  json_object_set_new(operation_data, "type", json_integer(9));
  if (req.master_weight && strlen(req.master_weight) > 0) {
    json_object_set_new(set_privilege, "master_weight",
                        json_string(req.master_weight));
  }
  if (req.tx_threshold && strlen(req.tx_threshold) > 0) {
    json_object_set_new(set_privilege, "tx_threshold",
                        json_string(req.tx_threshold));
  }

  if (req.signers_num > 0) {
    for (i = 0; i < req.signers_num; i++) {
      json_t *signers_json = json_object();
      if (req.signers[i].address && strlen(req.signers[i].address) > 0) {
        json_object_set_new(signers_json, "address",
                            json_string(req.signers[i].address));
      }
      json_object_set_new(signers_json, "weight",
                          json_integer(req.signers[i].weight));
      json_array_append_new(array_signers, signers_json);
    }
    json_object_set_new(set_privilege, "signers", array_signers);
  }
  if (req.type_threshold_num > 0) {
    for (i = 0; i < req.type_threshold_num; i++) {
      json_t *thresholds_json = json_object();
      json_object_set_new(thresholds_json, "type",
                          json_integer(req.typeThresholds[i].type));
      json_object_set_new(thresholds_json, "threshold",
                          json_integer(req.typeThresholds[i].threshold));
      json_array_append_new(array_thresholds, thresholds_json);
    }
    json_object_set_new(set_privilege, "type_thresholds", array_thresholds);
  }

  json_object_set_new(operation_data, "set_privilege", set_privilege);
  json_array_append_new(array_operations, operation_data);
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, privilege_url);
  ret = http_post(privilege_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;

  if (post_data)
    free(post_data);
  return res;
}

void account_response_release(BifAccountResponse *account_response) {
  sdk_free(account_response->value);
  sdk_free(account_response);
}

void account_request_meta_release(BifAccountSetMetadatasRequest *req) {
  int i = 0;
  for (i = 0; i < req->operations_num; i++) {
    sdk_free(req->operations_array[i].value);
  }
}