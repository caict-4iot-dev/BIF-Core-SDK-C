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
 * @file: transaction_service.c
 */
#include "transaction_service.h"
#include "constant.h"
#include "curl/curl.h"
#include "general.h"
#include "http.h"
#include "jansson.h"
#include "public_key_manager.h"
#include "sdk_error.h"

extern SdkError invalid_ceilledgerseq_error;
extern SdkError system_error;
extern SdkError connectnetwork_error;
extern SdkError invalid_domainid_error;
extern SdkError request_empty_error;
extern SdkError invalid_blocknumber_error;
extern SdkError invalid_address_error;
extern SdkError invalid_datakey_error;
extern SdkError invalid_hash_error;
extern SdkError url_empty_error;
extern SdkError invalid_serialization_error;
extern SdkError publickey_empty_error;
extern SdkError signdata_empty_error;
extern SdkError privatekey_empty_error;
extern SdkError invalid_dstaddress_error;
extern SdkError invalid_signaturenumber_error;
extern SdkError invalid_gasamount_error;
extern SdkError operation_empty_error;
extern SdkError operations_one_error;
extern SdkError invalid_feelimit_error;
extern SdkError invalid_gasprice_error;
extern SdkError operations_length_error;
BifTransactionGetTxCacheSizeResponse *get_tx_cache_size(int domainid,
                                                        const char *url) {
  BifTransactionGetTxCacheSizeResponse *res;
  char tx_cache_size_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionGetTxCacheSizeResponse *)malloc(
      sizeof(BifTransactionGetTxCacheSizeResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }

  int ret = get_tx_cache_size_url(domainid, url, tx_cache_size_url);
  ret = http_get(tx_cache_size_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  int len = 256;
  res->value = (char *)malloc(len);
  memset(res->value, 0, len);
  json_error_t error;
  json_t *valueJson = json_loads(value, 0, &error);
  uint64_t queue_size =
      json_integer_value(json_object_get(valueJson, "queue_size"));

  json_t *root = json_object();
  json_t *result = json_object();
  json_object_set_new(root, "error_code", json_integer(0));
  json_object_set_new(root, "error_desc", json_string("Success"));

  json_object_set_new(result, "queue_size", json_integer(queue_size));
  json_object_set_new(root, "result", result);
  char *json_str = json_dumps(root, JSON_ENCODE_ANY);
  memcpy(res->value, json_str, len);
  json_decref(valueJson);
  if (value)
    free(value);
  if (json_str)
    free(json_str);
  res->baseResponse.code = 0;

  // 返回res响应
  return res;
}

BifTransactionGetInfoResponse *
get_transaction_info(BifTransactionGetInfoRequest req, const char *url) {
  BifTransactionGetInfoResponse *res;
  char transaction_info_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionGetInfoResponse *)malloc(
      sizeof(BifTransactionGetInfoResponse));
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
    res->baseResponse = invalid_hash_error.res;
    return res;
  }
  if (strlen(req.hash) != HASH_HEX_LENGTH) {
    res->baseResponse = invalid_hash_error.res;
    return res;
  }

  int ret = transaction_get_info_url(url, &req, transaction_info_url);
  ret = http_get(transaction_info_url, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifTransactionGetInfoResponse *parse_blob(BifParseBlobRequest req,
                                          const char *url) {
  BifTransactionGetInfoResponse *res;
  char *blob_url = NULL;
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionGetInfoResponse *)malloc(
      sizeof(BifTransactionGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = request_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = request_empty_error.res;
    return res;
  }
  if (!req.blob) {
    res->baseResponse = invalid_serialization_error.res;
    return res;
  }
  if (!strlen(req.blob)) {
    res->baseResponse = invalid_serialization_error.res;
    return res;
  }
  int blob_len = strlen(req.blob) + 512;
  blob_url = (char *)malloc(blob_len);
  memset(blob_url, 0, blob_len);
  int ret = parse_blob_url(url, &req, blob_url);

  ret = http_get(blob_url, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    sdk_free(blob_url);
    res->baseResponse = connectnetwork_error.res;
    return res;
  }
  sdk_free(blob_url);
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifTransactionGetInfoResponse *
get_tx_cache_data(BifTransactionGetInfoRequest req, const char *url) {
  BifTransactionGetInfoResponse *res;
  char get_cache_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionGetInfoResponse *)malloc(
      sizeof(BifTransactionGetInfoResponse));
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
  if (req.hash == NULL) {
    res->baseResponse = invalid_hash_error.res;
    return res;
  }
  if ((strlen(req.hash) != 0) && (strlen(req.hash) != HASH_HEX_LENGTH)) {
    printf("hash->>:%s\n", req.hash);
    res->baseResponse = invalid_hash_error.res;
    return res;
  }
  int ret = get_tx_cache_url(url, &req, get_cache_url);
  ret = http_get(get_cache_url, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;
  // 返回res响应
  return res;
}

BifTransactionSubmitResponse *bif_submit(BifTransactionSubmitRequest req,
                                         const char *url) {
  BifTransactionSubmitResponse *res;
  char submit_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionSubmitResponse *)malloc(
      sizeof(BifTransactionSubmitResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = url_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = url_empty_error.res;
    return res;
  }
  if (!req.serialization) {
    res->baseResponse = invalid_serialization_error.res;
    return res;
  }
  if (strlen(req.serialization) == 0) {
    res->baseResponse = invalid_serialization_error.res;
    return res;
  }
  if (!req.public_key) {
    res->baseResponse = publickey_empty_error.res;
    return res;
  }
  if (strlen(req.public_key) == 0) {
    res->baseResponse = publickey_empty_error.res;
    return res;
  }
  if (!req.sign_data) {
    res->baseResponse = signdata_empty_error.res;
    return res;
  }
  if (strlen(req.sign_data) == 0) {
    res->baseResponse = signdata_empty_error.res;
    return res;
  }
  json_t *root = json_object();
  json_t *items_data = json_object();
  json_t *signatures_data = json_object();

  json_object_set_new(items_data, "transaction_blob",
                      json_string(req.serialization));
  json_object_set_new(signatures_data, "sign_data", json_string(req.sign_data));
  json_object_set_new(signatures_data, "public_key",
                      json_string(req.public_key));

  json_t *array_signature = json_array();
  json_t *array_items = json_array();

  json_array_append_new(array_signature, signatures_data);
  json_object_set_new(items_data, "signatures", array_signature);
  json_array_append_new(array_items, items_data);

  json_object_set_new(root, "items", array_items);
  char *post_data = json_dumps(root, JSON_ENCODE_ANY);

  int ret = transaction_submit_url(url, submit_url);
  ret = http_post(submit_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    return res;
  }

  res->value = value;
  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);

  // 返回res响应
  return res;
}

char *serializable_transaction(BifTransactionSerializeRequest req,
                               const char *url) {
  char seria_url[512] = {0};
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  json_t *root = json_object();
  json_t *operation_data = json_object();
  json_t *paycoin_data = json_object();

  json_object_set_new(root, "source_address", json_string(req.source_address));
  json_object_set_new(root, "nonce", json_integer(req.nonce));
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
    json_object_set_new(root, "ceil_ledger_seq",
                        json_integer(req.ceil_ledger_seq));
  }
  json_object_set_new(root, "fee_limit", json_integer(req.fee_limit));
  json_object_set_new(root, "domain_id", json_integer(req.domainid));
  json_object_set_new(root, "gas_price", json_integer(req.gas_price));
  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(root, "metadata", json_string(remarks_hex));
    }
  }
  json_object_set_new(operation_data, "type", json_integer(7));
  json_object_set_new(paycoin_data, "dest_address",
                      json_string(req.dest_address));
  json_object_set_new(paycoin_data, "amount", json_integer(req.amount));
  json_object_set_new(operation_data, "pay_coin", paycoin_data);

  json_t *array_operations = json_array();
  json_array_append_new(array_operations, operation_data);
  json_object_set_new(root, "operations", array_operations);

  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  void *value = NULL;
  size_t valueLen;
  int ret = transaction_blob_url(url, seria_url);

  ret = http_post(seria_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    printf("http post error <0\n");
    if (value)
      free(value);
    if (post_data)
      free(post_data);
    return NULL;
  }

  json_error_t error;
  int blob_value_len = strlen(value) + 1;
  char *transaction_blob = (char *)malloc(blob_value_len);
  memset(transaction_blob, 0, blob_value_len);
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code =
      json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *data = json_object_get(valueJson, "result");
    strcpy(transaction_blob,
           json_string_value(json_object_get(data, "transaction_blob")));
  } else {
    printf("transaction blob is error\n");
    if (value)
      free(value);
    if (post_data)
      free(post_data);
    json_decref(valueJson);
    return NULL;
  }
  if (value)
    free(value);
  if (post_data)
    free(post_data);
  json_decref(valueJson);

  return transaction_blob;
}

char *batch_serializable_transaction(BifBatchSerializeRequest req,
                                     const char *url) {
  char seria_url[512] = {0};
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  json_t *root = json_object();
  json_t *array_operations = json_array();

  json_object_set_new(root, "source_address", json_string(req.source_address));
  json_object_set_new(root, "nonce", json_integer(req.nonce));
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
    json_object_set_new(root, "ceil_ledger_seq",
                        json_integer(req.ceil_ledger_seq));
  }
  json_object_set_new(root, "fee_limit", json_integer(req.fee_limit));
  json_object_set_new(root, "domain_id", json_integer(req.domainid));
  json_object_set_new(root, "gas_price", json_integer(req.gas_price));
  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      char remarks_hex[1024] = {0};
      byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
      json_object_set_new(root, "metadata", json_string(remarks_hex));
    }
  }
  for (int i = 0; i < req.batch_gas_send_num; i++) {
    json_t *operation_data = json_object();
    json_t *paycoin_data = json_object();
    json_object_set_new(operation_data, "type", json_integer(7));
    json_object_set_new(
        paycoin_data, "dest_address",
        json_string(req.batch_gas_send_operation[i].dest_address));
    json_object_set_new(paycoin_data, "amount",
                        json_integer(req.batch_gas_send_operation[i].amount));
    json_object_set_new(operation_data, "pay_coin", paycoin_data);
    json_array_append_new(array_operations, operation_data);
  }
  json_object_set_new(root, "operations", array_operations);
  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  void *value = NULL;
  size_t valueLen;
  int ret = transaction_blob_url(url, seria_url);

  ret = http_post(seria_url, post_data, 5, &value, &valueLen);
  if (ret < 0) {
    printf("http post error <0\n");
    if (value)
      free(value);
    if (post_data)
      free(post_data);
    return NULL;
  }

  json_error_t error;
  int blob_value_len = strlen(value) + 1;
  char *transaction_blob = (char *)malloc(blob_value_len);
  memset(transaction_blob, 0, blob_value_len);
  json_t *valueJson = json_loads(value, 0, &error);
  uint16_t error_code = -1;
  error_code = json_integer_value(json_object_get(valueJson, "error_code"));
  if (error_code == 0) {
    json_t *data = json_object_get(valueJson, "result");
    if (!json_string_value(json_object_get(data, "transaction_blob"))) {
      printf("json_object_get(data, transaction_blob) null\n");
      if (value)
        free(value);
      if (post_data)
        free(post_data);
      sdk_free(transaction_blob);
      json_decref(valueJson);
      return NULL;
    }
    strcpy(transaction_blob,
           json_string_value(json_object_get(data, "transaction_blob")));
  } else {
    printf("transaction blob is error\n");
    if (value)
      free(value);
    if (post_data)
      free(post_data);
    sdk_free(transaction_blob);
    json_decref(valueJson);
    return NULL;
  }
  if (value)
    free(value);
  if (post_data)
    free(post_data);
  json_decref(valueJson);

  return transaction_blob;
}

BifTransactionSubmitResponse *gas_send(BifTransactionGasSendRequest req,
                                       const char *url) {
  BifTransactionSubmitResponse *res;
  res = (BifTransactionSubmitResponse *)malloc(
      sizeof(BifTransactionSubmitResponse));
  res->value = NULL;

  // 获取nonce 为序列化赋值
  BifAccountGetInfoRequest req_nonce;
  BifTransactionSerializeRequest req_serialize;
  memset(&req_serialize, 0, sizeof(BifTransactionSerializeRequest));
  memset(&req_nonce, 0, sizeof(BifAccountGetInfoRequest));
  // char blob[2048] = {0};
  if (!url) {
    res->baseResponse = url_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = url_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (!req.private_key) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (strlen(req.private_key) == 0) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (!is_address_valid(req.dest_address) ||
      strlen(req.dest_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.dest_address) == 0) {
    res->baseResponse = invalid_dstaddress_error.res;
    return res;
  }
  if (!is_address_valid(req.sender_address) ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.sender_address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (req.amount < 0 || req.amount > LONG_MAX) {
    res->baseResponse = invalid_gasamount_error.res;
    return res;
  }
  if (req.fee_limit < 0 || req.fee_limit > LONG_MAX) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  }
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price < 0 || req.gas_price > LONG_MAX) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  if (req.ceil_ledger_seq < 0) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    req_serialize.nonce = 1;
  } else {
    req_serialize.nonce = nonce + 1;
  }

  // 构建序列化
  req_serialize.amount = req.amount;
  req_serialize.ceil_ledger_seq = req.ceil_ledger_seq;
  req_serialize.domainid = req.domainid;
  req_serialize.fee_limit = req.fee_limit;
  req_serialize.gas_price = req.gas_price;
  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      strcpy(req_serialize.remarks, req.remarks);
    }
  }
  // strcpy(req_serialize.sender_private_key, req.private_key);
  strcpy(req_serialize.source_address, req.sender_address);
  strcpy(req_serialize.dest_address, req.dest_address);
  req_serialize.operation_type = 7;

  char *blob_temp = serializable_transaction(req_serialize, url);
  if (!blob_temp) {
    res->baseResponse = system_error.res;
    return res;
  }

  // sign签名blob
  BifTransactionSubmitRequest req_submit;
  char out_sign[1024] = {0};
  char signature[1024] = {0};
  memset(&req_submit, 0, sizeof(BifTransactionSubmitRequest));
  int blob_temp_len = strlen(blob_temp) + 1;
  int tx_blob_ori_len = 0;
  int sign_len = 0;

  req_submit.serialization = (char *)malloc(blob_temp_len);
  memset(req_submit.serialization, 0, blob_temp_len);
  strcpy(req_submit.serialization, blob_temp);

  char *tx_blob_ori = (char *)malloc(blob_temp_len);
  memset(tx_blob_ori, 0, blob_temp_len);
  hex_string_to_byte(blob_temp, (unsigned char *)tx_blob_ori, &tx_blob_ori_len);
  tx_blob_ori[tx_blob_ori_len] = '\0';
  char *sign_temp =
      sign(req.private_key, tx_blob_ori, tx_blob_ori_len, &sign_len);
  if (!sign_temp) {
    sdk_free(tx_blob_ori);
    sdk_free(blob_temp);
    sdk_free(req_submit.serialization);
    res->baseResponse = system_error.res;
    return res;
  }
  memcpy(signature, sign_temp, sign_len);
  signature[sign_len] = '\0';
  sdk_free(blob_temp);
  sdk_free(tx_blob_ori);

  byte_to_hex_string((unsigned char *)signature, sign_len, out_sign);
  strcpy(req_submit.sign_data, out_sign);
  char *publickey_by_private = get_enc_public_key(req.private_key);
  if (!publickey_by_private) {
    sdk_free(publickey_by_private);
    sdk_free(req_submit.serialization);
    res->baseResponse = system_error.res;
    return res;
  }
  strcpy(req_submit.public_key, publickey_by_private);
  sdk_free(publickey_by_private);

  // submit发送交易
  BifTransactionSubmitResponse *res_temp = bif_submit(req_submit, url);
  res->value = (char *)malloc(strlen(res_temp->value) + 1);
  memset(res->value, 0, strlen(res_temp->value) + 1);
  if (res_temp->baseResponse.code != 0) {
    sdk_free(req_submit.serialization);
    sdk_free(res);
    return res_temp;
  }
  sdk_free(req_submit.serialization);
  res->baseResponse = res_temp->baseResponse;
  res->baseResponse.code = 0;
  strcpy(res->value, res_temp->value);
  if (res_temp->value) {
    sdk_free(res_temp->value);
    sdk_free(res_temp);
  }
  return res;
}

BifTransactionSubmitResponse *batch_gas_send(BifBatchGasSendRequest req,
                                             const char *url) {
  BifTransactionSubmitResponse *res;
  res = (BifTransactionSubmitResponse *)malloc(
      sizeof(BifTransactionSubmitResponse));
  res->value = NULL;

  // 获取nonce 为序列化赋值
  BifAccountGetInfoRequest req_nonce;
  BifBatchSerializeRequest req_serialize;
  memset(&req_serialize, 0, sizeof(BifBatchSerializeRequest));
  memset(&req_nonce, 0, sizeof(BifAccountGetInfoRequest));
  // char blob[2048] = {0};
  if (!url) {
    res->baseResponse = url_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = url_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (!req.private_key) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (strlen(req.private_key) == 0) {
    res->baseResponse = privatekey_empty_error.res;
    return res;
  }
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!is_address_valid(req.sender_address) ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      strlen(req.sender_address) == 0) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (req.batch_gas_send_num <= 0 || req.batch_gas_send_num > 100) {
    res->baseResponse = operations_length_error.res;
    return res;
  }
  for (int i = 0; i < req.batch_gas_send_num; i++) {
    if (!req.batch_gas_send_operation[i].dest_address) {
      res->baseResponse = invalid_dstaddress_error.res;
      return res;
    }
    if (!is_address_valid(req.batch_gas_send_operation[i].dest_address) ||
        strlen(req.batch_gas_send_operation[i].dest_address) >
            ADDRESS_MAX_LENGTH ||
        strlen(req.batch_gas_send_operation[i].dest_address) == 0) {
      res->baseResponse = invalid_dstaddress_error.res;
      return res;
    }
    if (req.batch_gas_send_operation[i].amount < 0 ||
        req.batch_gas_send_operation[i].amount > LONG_MAX) {
      res->baseResponse = invalid_gasamount_error.res;
      return res;
    }
    req_serialize.batch_gas_send_operation[i].amount =
        req.batch_gas_send_operation[i].amount;
    memset(req_serialize.batch_gas_send_operation[i].dest_address, 0,
           sizeof(req_serialize.batch_gas_send_operation[i].dest_address));
    strcpy(req_serialize.batch_gas_send_operation[i].dest_address,
           req.batch_gas_send_operation[i].dest_address);
  }
  if (req.fee_limit < 0 || req.fee_limit > LONG_MAX) {
    res->baseResponse = invalid_feelimit_error.res;
    return res;
  }
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price < 0 || req.gas_price > LONG_MAX) {
    res->baseResponse = invalid_gasprice_error.res;
    return res;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  if (req.ceil_ledger_seq < 0) {
    res->baseResponse = invalid_ceilledgerseq_error.res;
    return res;
  }
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    req_serialize.nonce = 1;
  } else {
    req_serialize.nonce = nonce + 1;
  }
  // 构建序列化
  req_serialize.batch_gas_send_num = req.batch_gas_send_num;
  req_serialize.ceil_ledger_seq = req.ceil_ledger_seq;
  req_serialize.domainid = req.domainid;
  req_serialize.fee_limit = req.fee_limit;
  req_serialize.gas_price = req.gas_price;
  if (req.remarks) {
    if (strlen(req.remarks) > 0) {
      strcpy(req_serialize.remarks, req.remarks);
    }
  }
  strcpy(req_serialize.source_address, req.sender_address);
  req_serialize.operation_type = 7;

  char *blob_temp = batch_serializable_transaction(req_serialize, url);
  if (!blob_temp) {
    res->baseResponse = system_error.res;
    return res;
  }

  // sign签名blob
  BifTransactionSubmitRequest req_submit;
  memset(&req_submit, 0, sizeof(BifTransactionSubmitRequest));
  char out_sign[1024] = {0};
  char signature[1024] = {0};

  int blob_temp_len = strlen(blob_temp) + 1;
  int tx_blob_ori_len = 0;
  int sign_len = 0;

  req_submit.serialization = (char *)malloc(blob_temp_len);
  memset(req_submit.serialization, 0, blob_temp_len);
  strcpy(req_submit.serialization, blob_temp);

  char *tx_blob_ori = (char *)malloc(blob_temp_len);
  memset(tx_blob_ori, 0, blob_temp_len);
  hex_string_to_byte(blob_temp, (unsigned char *)tx_blob_ori, &tx_blob_ori_len);
  tx_blob_ori[tx_blob_ori_len] = '\0';
  char *sign_temp =
      sign(req.private_key, tx_blob_ori, tx_blob_ori_len, &sign_len);
  if (!sign_temp) {
    sdk_free(tx_blob_ori);
    sdk_free(blob_temp);
    sdk_free(req_submit.serialization);
    res->baseResponse = system_error.res;
    return res;
  }
  memcpy(signature, sign_temp, sign_len);
  signature[sign_len] = '\0';
  sdk_free(blob_temp);
  sdk_free(tx_blob_ori);

  byte_to_hex_string((unsigned char *)signature, sign_len, out_sign);
  strcpy(req_submit.sign_data, out_sign);
  char *publickey_by_private = get_enc_public_key(req.private_key);
  if (!publickey_by_private) {
    sdk_free(publickey_by_private);
    sdk_free(req_submit.serialization);
    res->baseResponse = system_error.res;
    return res;
  }
  strcpy(req_submit.public_key, publickey_by_private);
  sdk_free(publickey_by_private);

  // submit发送交易
  BifTransactionSubmitResponse *res_temp = bif_submit(req_submit, url);
  res->value = (char *)malloc(strlen(res_temp->value) + 1);
  memset(res->value, 0, strlen(res_temp->value) + 1);
  if (res_temp->baseResponse.code != 0) {
    sdk_free(req_submit.serialization);
    sdk_free(res);
    return res_temp;
  }
  sdk_free(req_submit.serialization);
  res->baseResponse = res_temp->baseResponse;
  res->baseResponse.code = 0;
  strcpy(res->value, res_temp->value);
  if (res_temp->value) {
    sdk_free(res_temp->value);
    sdk_free(res_temp);
  }
  return res;
}

BifTransactionGetInfoResponse *evaluate_fee(BifEvaluateFeeRequest req,
                                            const char *url) {
  BifTransactionGetInfoResponse *res;
  char evaluate_url[512] = {0};
  void *value = NULL;
  size_t valueLen;

  res = (BifTransactionGetInfoResponse *)malloc(
      sizeof(BifTransactionGetInfoResponse));
  memset(res, 0, sizeof(BifTransactionGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = url_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = url_empty_error.res;
    return res;
  }
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!is_address_valid(req.sender_address) ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      !strlen(req.sender_address)) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (req.signature_number != 0 && req.signature_number < 1) {
    res->baseResponse = invalid_signaturenumber_error.res;
    return res;
  }
  if (strlen(req.call_operation.dest_address) == 0 &&
      strlen(req.pay_coin_operation.dest_address) == 0 &&
      req.create_contract_operation.init_balance < 1) {
    res->baseResponse = operation_empty_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  int ret = evaluation_fee_url(url, evaluate_url);

  BifAccountGetInfoRequest req_nonce;
  // 1.获取指定地址的nonce
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    nonce = 1;
  } else {
    nonce = nonce + 1;
  }
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }
  if (req.operation_type == 0) {
    req.operation_type = 6;
  }
  json_t *root = json_object();
  json_t *items_json = json_object();
  json_t *transaction_json = json_object();
  json_t *operation_data = json_object();
  json_t *paycoin_data = json_object();
  json_t *create_contract = json_object();
  json_t *priv_data = json_object();
  json_t *thresholds_data = json_object();
  json_t *contract_data = json_object();
  json_t *array_private = json_array();
  json_t *array_operations = json_array();

  json_array_append_new(array_private, json_string(req.private_key));
  json_object_set_new(items_json, "private_keys", array_private);

  json_object_set_new(transaction_json, "fee_limit",
                      json_integer(req.fee_limit));
  json_object_set_new(transaction_json, "gas_price",
                      json_integer(req.gas_price));
  json_object_set_new(transaction_json, "nonce", json_integer(nonce));
  json_object_set_new(transaction_json, "domain_id",
                      json_integer(req.domainid));
  json_object_set_new(transaction_json, "source_address",
                      json_string(req.sender_address));
  if (req.signature_number >= 1) {
    json_object_set_new(transaction_json, "signature_number",
                        json_integer(req.signature_number));
  }
  // json_object_set_new(operation_data, "type",
  // json_integer(req.operation_type));

  if (req.create_contract_operation.payload) {
    json_object_set_new(contract_data, "payload",
                        json_string(req.create_contract_operation.payload));
    json_object_set_new(contract_data, "type",
                        json_integer(req.create_contract_operation.type));
    json_object_set_new(create_contract, "contract", contract_data);
    json_object_set_new(
        create_contract, "init_balance",
        json_integer(req.create_contract_operation.init_balance));
    if (req.create_contract_operation.init_input) {
      json_object_set_new(
          create_contract, "init_input",
          json_string(req.create_contract_operation.init_input));
    }
    json_object_set_new(priv_data, "master_weight", json_integer(0));
    json_object_set_new(thresholds_data, "tx_threshold", json_integer(1));
    json_object_set_new(priv_data, "thresholds", thresholds_data);
    json_object_set_new(create_contract, "priv", priv_data);
    if (req.remarks) {
      if (strlen(req.remarks) > 0) {
        char remarks_hex[1024] = {0};
        byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
        json_object_set_new(create_contract, "metadata",
                            json_string(remarks_hex));
      }
    }
    json_object_set_new(operation_data, "create_account", create_contract);
    json_object_set_new(operation_data, "type", json_integer(1));
  } else if (strlen(req.pay_coin_operation.dest_address) != 0) {
    json_object_set_new(paycoin_data, "dest_address",
                        json_string(req.pay_coin_operation.dest_address));
    json_object_set_new(paycoin_data, "amount",
                        json_integer(req.pay_coin_operation.amount));
    if (req.call_operation.input) {
      json_object_set_new(paycoin_data, "input",
                          json_string(req.pay_coin_operation.input));
    }
    json_object_set_new(operation_data, "pay_coin", paycoin_data);
    json_object_set_new(operation_data, "type", json_integer(7));
  } else {
    json_object_set_new(paycoin_data, "dest_address",
                        json_string(req.call_operation.dest_address));
    json_object_set_new(paycoin_data, "amount",
                        json_integer(req.call_operation.amount));
    if (req.call_operation.input) {
      json_object_set_new(paycoin_data, "input",
                          json_string(req.call_operation.input));
    }
    json_object_set_new(operation_data, "pay_coin", paycoin_data);
    json_object_set_new(operation_data, "type", json_integer(7));
  }

  json_array_append_new(array_operations, operation_data);
  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_t *array_items = json_array();
  json_array_append_new(array_items, items_json);

  json_object_set_new(root, "items", array_items);
  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  if (!post_data) {
    printf("json_dumps:null \n");
  }
  ret = http_post(evaluate_url, post_data, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);
  return res;
}

BifTransactionGetInfoResponse *
evaluate_batch_fee(BifEvaluateFeeBatchRequest req, const char *url) {
  BifTransactionGetInfoResponse *res;
  char evaluate_url[512] = {0};
  void *value = NULL;
  size_t valueLen;
  int i = 0;

  res = (BifTransactionGetInfoResponse *)malloc(
      sizeof(BifTransactionGetInfoResponse));
  memset(res, 0, sizeof(BifTransactionGetInfoResponse));
  res->value = NULL;
  if (!url) {
    res->baseResponse = url_empty_error.res;
    return res;
  } else if (!strlen(url)) {
    res->baseResponse = url_empty_error.res;
    return res;
  }
  if (!req.sender_address) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (!is_address_valid(req.sender_address) ||
      strlen(req.sender_address) > ADDRESS_MAX_LENGTH ||
      !strlen(req.sender_address)) {
    res->baseResponse = invalid_address_error.res;
    return res;
  }
  if (req.signature_number != 0 && req.signature_number < 1) {
    res->baseResponse = invalid_signaturenumber_error.res;
    return res;
  }
  if (req.domainid < 0) {
    res->baseResponse = invalid_domainid_error.res;
    return res;
  }
  if (req.operation_num == 0) {
    res->baseResponse = operation_empty_error.res;
    return res;
  }
  if (req.operation_num == 1) {
    res->baseResponse = operations_one_error.res;
    return res;
  }
  if (req.operation_num > 100) {
    res->baseResponse = operations_length_error.res;
    return res;
  }
  if (req.fee_limit == 0) {
    req.fee_limit = FEE_LIMIT;
  }
  if (req.gas_price == 0) {
    req.gas_price = GAS_PRICE;
  }

  int ret = evaluation_fee_url(url, evaluate_url);
  BifAccountGetInfoRequest req_nonce;
  // 1.获取指定的nonce
  req_nonce.domainid = req.domainid;
  strcpy(req_nonce.address, req.sender_address);
  int nonce = get_nonce_parse_json(req_nonce, url);
  if (nonce <= 0) {
    nonce = 1;
  } else {
    nonce = nonce + 1;
  }
  json_t *root = json_object();
  json_t *items_json = json_object();
  json_t *transaction_json = json_object();
  json_t *array_private = json_array();
  json_t *array_operations = json_array();

  json_array_append_new(array_private, json_string(req.private_key));
  json_object_set_new(items_json, "private_keys", array_private);
  // json_object_set_new(items_json, "signature_number", json_integer(1));

  json_object_set_new(transaction_json, "fee_limit",
                      json_integer(req.fee_limit));
  json_object_set_new(transaction_json, "gas_price",
                      json_integer(req.gas_price));
  json_object_set_new(transaction_json, "nonce", json_integer(nonce));
  json_object_set_new(transaction_json, "domain_id",
                      json_integer(req.domainid));
  if (req.signature_number >= 1) {
    json_object_set_new(transaction_json, "signature_number",
                        json_integer(req.signature_number));
  }
  json_object_set_new(transaction_json, "source_address",
                      json_string(req.sender_address));
  for (i = 0; i < req.operation_num; i++) {
    json_t *operation_data = json_object();
    if (req.operation_datas[i].create_contract_operation.payload) {
      json_t *create_contract = json_object();
      json_t *contract_data = json_object();
      json_t *priv_data = json_object();
      json_t *thresholds_data = json_object();

      json_object_set_new(
          contract_data, "payload",
          json_string(
              req.operation_datas[i].create_contract_operation.payload));
      json_object_set_new(
          contract_data, "type",
          json_integer(req.operation_datas[i].create_contract_operation.type));
      json_object_set_new(create_contract, "contract", contract_data);
      json_object_set_new(
          create_contract, "init_balance",
          json_integer(
              req.operation_datas[i].create_contract_operation.init_balance));
      if (req.operation_datas[i].create_contract_operation.init_input) {
        json_object_set_new(
            create_contract, "init_input",
            json_string(
                req.operation_datas[i].create_contract_operation.init_input));
      }
      json_object_set_new(priv_data, "master_weight", json_integer(0));
      json_object_set_new(thresholds_data, "tx_threshold", json_integer(1));
      json_object_set_new(priv_data, "thresholds", thresholds_data);
      json_object_set_new(create_contract, "priv", priv_data);
      if (req.remarks) {
        if (strlen(req.remarks) > 0) {
          char remarks_hex[1024] = {0};
          byte_to_hex_string(req.remarks, strlen(req.remarks), remarks_hex);
          json_object_set_new(create_contract, "metadata",
                              json_string(remarks_hex));
        }
      }
      json_object_set_new(operation_data, "create_account", create_contract);
      json_object_set_new(operation_data, "type", json_integer(1));
    } else if (strlen(req.operation_datas[i].pay_coin_operation.dest_address) !=
               0) {
      json_t *paycoin_data = json_object();
      json_object_set_new(
          paycoin_data, "dest_address",
          json_string(req.operation_datas[i].pay_coin_operation.dest_address));
      json_object_set_new(
          paycoin_data, "amount",
          json_integer(req.operation_datas[i].pay_coin_operation.amount));
      if (req.operation_datas[i].pay_coin_operation.input) {
        json_object_set_new(
            paycoin_data, "input",
            json_string(req.operation_datas[i].pay_coin_operation.input));
      }
      json_object_set_new(operation_data, "pay_coin", paycoin_data);
      json_object_set_new(operation_data, "type", json_integer(7));
    } else {
      json_t *paycoin_data = json_object();
      json_object_set_new(
          paycoin_data, "dest_address",
          json_string(req.operation_datas[i].call_operation.dest_address));
      json_object_set_new(
          paycoin_data, "amount",
          json_integer(req.operation_datas[i].call_operation.amount));
      if (req.operation_datas[i].call_operation.input) {
        json_object_set_new(
            paycoin_data, "input",
            json_string(req.operation_datas[i].call_operation.input));
      }
      json_object_set_new(operation_data, "pay_coin", paycoin_data);
      json_object_set_new(operation_data, "type", json_integer(7));
    }
    json_array_append_new(array_operations, operation_data);
  }

  json_object_set_new(transaction_json, "operations", array_operations);
  json_object_set_new(items_json, "transaction_json", transaction_json);
  json_t *array_items = json_array();
  json_array_append_new(array_items, items_json);

  json_object_set_new(root, "items", array_items);
  char *post_data = json_dumps(root, JSON_ENCODE_ANY);
  ret = http_post(evaluate_url, post_data, 5, &value, &valueLen);
  res->value = value;
  if (ret < 0) {
    res->baseResponse = connectnetwork_error.res;
    if (post_data)
      free(post_data);
    return res;
  }

  res->baseResponse.code = 0;
  if (post_data)
    free(post_data);
  return res;
}

void transaction_info_response_release(
    BifTransactionGetInfoResponse *transaction_info_response) {
  sdk_free(transaction_info_response->value);
  sdk_free(transaction_info_response);
}
void transaction_submit_response_release(
    BifTransactionSubmitResponse *transaction_submit_response) {
  sdk_free(transaction_submit_response->value);
  sdk_free(transaction_submit_response);
}
void transaction_cachesize_response_release(
    BifTransactionGetTxCacheSizeResponse *transaction_cachesize_response) {
  sdk_free(transaction_cachesize_response->value);
  sdk_free(transaction_cachesize_response);
}