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
 * @file: contract_service.c
 */
#include "contract_service.h"
#include "constant.h"
#include "curl/curl.h"
#include "general.h"
#include "http.h"
#include "jansson.h"
#include "sdk_error.h"
#include "util.h"

extern SdkError system_error;
extern SdkError connectnetwork_error;
extern SdkError invalid_domainid_error;
extern SdkError request_empty_error;
extern SdkError invalid_blocknumber_error;
extern SdkError invalid_contractaddress_error;
extern SdkError invalid_hash_error;
extern SdkError invalid_address_error;
extern SdkError privatekey_empty_error;
extern SdkError invalid_initbalance_error;
extern SdkError payload_empty_error;
extern SdkError invalid_feelimit_error;
extern SdkError invalid_gasprice_error;
extern SdkError system_error;
extern SdkError invalid_srcaddress_error;
extern SdkError invalid_notcontractaddr_error;
extern SdkError invalid_amount_error;
extern SdkError invalid_ceilledgerseq_error;
extern SdkError invalid_contracttype_error;
extern SdkError srcaddress_nocontracaddr_error;
extern SdkError operations_length_error;
BifContractCheckValidResponse *
check_contract_address(BifContractCheckValidRequest req, const char *url) {
  BifContractCheckValidResponse *res;
  char contract_addr_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  json_error_t error;

  res = (BifContractCheckValidResponse *)malloc(
      sizeof(BifContractCheckValidResponse));
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
  if (!req.contract_address) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (strlen(req.contract_address) == 0) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (!is_address_valid(req.contract_address)) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }

  int ret = contract_getInfo_url(url, &req, contract_addr_url);
  ret = http_get(contract_addr_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  res->value = (char *)malloc(valueLen + 1);
  memset(res->value, 0x0, valueLen + 1);

  bool is_valid = false;
  json_t *valueJson = json_loads(value, 0, &error);
  res->baseResponse.code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (res->baseResponse.code == 0) {
    json_t *data = json_object_get(valueJson, "result");
    json_t *contract_json = json_object_get(data, "contract");
    char *payload_str =
        json_string_value(json_object_get(contract_json, "payload"));
    if (!payload_str) {
      is_valid = false;
    } else {
      is_valid = true;
    }
    json_t *root = json_object();
    json_t *result = json_object();
    json_object_set_new(root, "error_code", json_integer(0));
    json_object_set_new(root, "error_desc", json_string("Success"));
    json_object_set_new(result, "is_valid", json_boolean(is_valid));
    json_object_set_new(root, "result", result);
    char *json_str = json_dumps(root, JSON_ENCODE_ANY);

    memcpy(res->value, json_str, strlen(json_str));
    if (json_str)
      free(json_str);

  } else {
    memcpy(res->value, value, valueLen);
  }
  res->baseResponse.code = 0;
  if (value)
    free(value);
  json_decref(valueJson);
  // 返回res响应
  return res;
}

BifContractCheckValidResponse *
get_contract_info(BifContractCheckValidRequest req, const char *url) {
  BifContractCheckValidResponse *res;
  char contract_info_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  json_error_t error;

  res = (BifContractCheckValidResponse *)malloc(
      sizeof(BifContractCheckValidResponse));
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
  if (strlen(req.contract_address) == 0) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (!is_address_valid(req.contract_address)) {
    res->baseResponse = invalid_notcontractaddr_error.res;
    return res;
  }

  int ret = contract_getInfo_url(url, &req, contract_info_url);
  ret = http_get(contract_info_url, 5, &value, &valueLen);

  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  json_t *valueJson = json_loads(value, 0, &error);
  ret = json_integer_value(json_object_get(valueJson, "error_code"));
  if (ret == 0) {
    json_t *data = json_object_get(valueJson, "result");
    json_t *contract_json = json_object_get(data, "contract");
    char *payload_str =
        json_string_value(json_object_get(contract_json, "payload"));
    if (!payload_str) {
      json_decref(valueJson);
      res->baseResponse = invalid_notcontractaddr_error.res;
      return res;
    } else {
      res->value = value;
    }
  } else {
    res->value = value;
  }
  res->baseResponse.code = 0;
  json_decref(valueJson);
  // 返回res响应
  return res;
}

BifContractGetInfoResponse *
get_contract_address(BifContractGetAddressRequest req, const char *url) {
  BifContractGetInfoResponse *res;
  char contract_info_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  json_error_t error;

  res =
      (BifContractGetInfoResponse *)malloc(sizeof(BifContractGetInfoResponse));
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
  if (!req.hash) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (strlen(req.hash) == 0) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (strlen(req.hash) != HASH_HEX_LENGTH) {
    res->baseResponse = invalid_hash_error.res;
    return res;
  }
  BifTransactionGetInfoRequest req_addr;
  req_addr.domainid = req.domainid;
  strcpy(req_addr.hash, req.hash);

  int ret = transaction_get_info_url(url, &req_addr, contract_info_url);
  ret = http_get(contract_info_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  json_t *valueJson = json_loads(value, 0, &error);
  res->baseResponse.code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (res->baseResponse.code == 0) {
    int len = valueLen + 1;
    res->value = (char *)malloc(len);
    memset(res->value, 0, len);
    json_t *data = json_object_get(valueJson, "result");
    json_t *transactions_json = json_object_get(data, "transactions");
    int index = 0;
    json_t *value = NULL;
    json_array_foreach(transactions_json, index, value) {
      json_t *metadata_dump = json_object();
      char *error_desc =
          json_string_value(json_object_get(value, "error_desc"));
      if (!error_desc) {
        json_decref(valueJson);
        sdk_free(value);
        sdk_free(res->value);
        res->baseResponse = system_error.res;
        return res;
      }
      memcpy(res->value, error_desc, strlen(error_desc));
      sdk_free(value);
    }

  } else {
    res->value = value;
  }
  res->baseResponse.code = 0;
  json_decref(valueJson);
  // 返回res响应
  return res;
}

BifContractGetInfoResponse *contract_create(BifContractCreateRequest req,
                                            const char *url) {
  BifContractGetInfoResponse *res;
  char contract_create_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res =
      (BifContractGetInfoResponse *)malloc(sizeof(BifContractGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (req.domainid < INIT_ZERO) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (check_addr_prefix(req.sender_address) < INIT_ZERO ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.sender_address) == INIT_ZERO) {
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
  if (req.init_balance <= INIT_ZERO || req.init_balance > LONG_MAX) {
    res->baseResponse = invalid_initbalance_error.res;
    return res;
  }
  if (req.payload == NULL) {
    res->baseResponse = payload_empty_error.res;
    return res;
  }
  if (sdslen(req.payload) == 0) {
    res->baseResponse = payload_empty_error.res;
    return res;
  }
  if (req.fee_limit < INIT_ZERO) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  }
  if (req.gas_price < INIT_ZERO) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.ceil_ledger_seq < INIT_ZERO) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  if (req.contract_type < INIT_ZERO) {
    res->baseResponse = invalid_contracttype_error.res;
    return res;
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
  json_t *create_account_json = json_object();
  json_t *contract_json = json_object();
  json_t *priv_json = json_object();
  json_t *threshold_json = json_object();

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
  json_object_set_new(operation_data, "type", json_integer(1));
  json_object_set_new(create_account_json, "init_balance",
                      json_integer(req.init_balance));
  if (req.init_input) {
    if (sdslen(req.init_input) > 0) {
      json_object_set_new(create_account_json, "init_input",
                          json_string(req.init_input));
    }
  }
  if (req.remarks != NULL) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(create_account_json, "metadata",
                          json_integer(remarks_hex));
    }
  }
  json_object_set_new(contract_json, "payload", json_string(req.payload));
  json_object_set_new(contract_json, "type", json_integer(req.contract_type));
  json_object_set_new(create_account_json, "contract", contract_json);

  json_object_set_new(priv_json, "master_weight", json_integer(0));
  json_object_set_new(threshold_json, "tx_threshold", json_integer(1));
  json_object_set_new(priv_json, "thresholds", threshold_json);
  json_object_set_new(create_account_json, "priv", priv_json);
  json_object_set_new(operation_data, "create_account", create_account_json);
  json_array_append_new(array_operations, operation_data);
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, contract_create_url);
  ret = http_post(contract_create_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = system_error.res;
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
BifContractGetInfoResponse *contract_query(BifContractCallRequest req,
                                           const char *url) {
  BifContractGetInfoResponse *res;
  char contract_query_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res =
      (BifContractGetInfoResponse *)malloc(sizeof(BifContractGetInfoResponse));
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
  if ((strlen(req.source_address) > 0 &&
       check_addr_prefix(req.source_address) < INIT_ZERO) ||
      strlen(req.source_address) > ADDRESS_MAX_LENGTH) {
    res->baseResponse = invalid_srcaddress_error.res;
    return res;
  }
  if (!req.contract_address) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (check_addr_prefix(req.contract_address) < INIT_ZERO ||
      strlen(req.contract_address) > ADDRESS_MAX_LENGTH) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (!strcmp(req.contract_address, req.source_address)) {
    res->baseResponse = srcaddress_nocontracaddr_error.res;
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
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  json_t *root = json_object();
  json_t *items_json = json_object();

  json_object_set_new(root, "contract_address",
                      json_string(req.contract_address));
  if (req.input) {
    if (strlen(req.input) > 0) {
      json_object_set_new(root, "input", json_string(req.input));
    }
  }
  json_object_set_new(root, "fee_limit", json_integer(req.fee_limit));
  json_object_set_new(root, "gas_price", json_integer(req.gas_price));
  json_object_set_new(root, "opt_type", json_integer(2));
  json_object_set_new(root, "domain_id", json_integer(req.domainid));
  if (req.source_address) {
    if (strlen(req.source_address) > 0) {
      json_object_set_new(root, "source_address",
                          json_string(req.source_address));
    }
  }
  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = contract_call_query_url(url, contract_query_url);
  ret = http_post(contract_query_url, post_data, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = system_error.res;
    if (post_data)
      free(post_data);
    return res;
  }
  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);
  return res;
}
BifContractGetInfoResponse *contract_invoke(BifContractInvokeRequest req,
                                            const char *url) {
  BifContractGetInfoResponse *res;
  char contract_invoke_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res =
      (BifContractGetInfoResponse *)malloc(sizeof(BifContractGetInfoResponse));
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
  if (!req.contract_address) {
    res->baseResponse = invalid_contractaddress_error.res;
    return res;
  }
  if (check_addr_prefix(req.contract_address) < INIT_ZERO ||
      strlen(req.contract_address) > ADDRESS_MAX_LENGTH) {
    res->baseResponse = invalid_contractaddress_error.res;
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
  if (req.amount < INIT_ZERO || req.amount > LONG_MAX) {
    res->baseResponse = invalid_amount_error.res;
    return res;
  }
  if (req.gas_price < INIT_ZERO || req.gas_price > LONG_MAX) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.fee_limit < INIT_ZERO || req.fee_limit > LONG_MAX) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
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
  json_t *pay_coin_json = json_object();

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
  json_object_set_new(operation_data, "type", json_integer(7));
  json_object_set_new(pay_coin_json, "dest_address",
                      json_string(req.contract_address));
  json_object_set_new(pay_coin_json, "amount", json_integer(req.amount));
  if (req.input) {
    if (sdslen(req.input)) {
      json_object_set_new(pay_coin_json, "input", json_string(req.input));
    }
  }
  json_object_set_new(operation_data, "pay_coin", pay_coin_json);
  json_array_append_new(array_operations, operation_data);
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, contract_invoke_url);
  ret = http_post(contract_invoke_url, post_data, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = system_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);
  return res;
}
BifContractGetInfoResponse *
contract_batch_invoke(BifBatchContractInvokeRequest req, const char *url) {
  BifContractGetInfoResponse *res;
  char contract_invoke_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res =
      (BifContractGetInfoResponse *)malloc(sizeof(BifContractGetInfoResponse));
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
  if (req.operation_batch_num <= 0 || req.operation_batch_num > 100) {
    res->baseResponse = operations_length_error.res;
    res->value = "";
    return res;
  }
  for (i = 0; i < req.operation_batch_num; i++) {
    if (!req.operation_batch_data[i].contract_address) {
      res->baseResponse = invalid_contractaddress_error.res;
      return res;
    }
    if (check_addr_prefix(req.operation_batch_data[i].contract_address) <
            INIT_ZERO ||
        strlen(req.operation_batch_data[i].contract_address) >
            ADDRESS_MAX_LENGTH) {
      res->baseResponse = invalid_contractaddress_error.res;
      return res;
    }
    if (req.operation_batch_data[i].amount < 0 ||
        req.operation_batch_data[i].amount > LONG_MAX) {
      res->baseResponse = invalid_amount_error.res;
      return res;
    }
  }
  if (!req.private_key) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (strlen(req.private_key) == INIT_ZERO) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (req.ceil_ledger_seq < INIT_ZERO) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  if (req.gas_price < INIT_ZERO || req.gas_price > LONG_MAX) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.fee_limit < INIT_ZERO || req.fee_limit > LONG_MAX) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
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
  for (i = 0; i < req.operation_batch_num; i++) {
    json_t *operation_data = json_object();
    json_t *pay_coin_json = json_object();
    json_object_set_new(operation_data, "type", json_integer(7));
    json_object_set_new(
        pay_coin_json, "dest_address",
        json_string(req.operation_batch_data[i].contract_address));
    json_object_set_new(pay_coin_json, "amount",
                        json_integer(req.operation_batch_data[i].amount));
    if (req.operation_batch_data[i].input) {
      json_object_set_new(pay_coin_json, "input",
                          json_string(req.operation_batch_data[i].input));
    }
    json_object_set_new(operation_data, "pay_coin", pay_coin_json);
    json_array_append_new(array_operations, operation_data);
  }

  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_array_append_new(array_items, items_json);
  json_object_set_new(root, "items", array_items);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  int ret = transaction_submit_url(url, contract_invoke_url);
  ret = http_post(contract_invoke_url, post_data, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = system_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);
  return res;
}

void input_sds_initialize(sds *input, char *buf) {
  *input = sdsempty();
  *input = sdscpy(*input, buf);
}

void contract_info_response_release(
    BifContractGetInfoResponse *contract_response) {
  sdk_free(contract_response->value);
  sdk_free(contract_response);
}
void contract_valid_response_release(
    BifContractCheckValidResponse *contract_valid_response) {
  sdk_free(contract_valid_response->value);
  sdk_free(contract_valid_response);
}
void contract_sds_request_release(sds contract_sds_request) {
  sdsfree(contract_sds_request);
}
