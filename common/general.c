
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
 * @file: general.c
 */
#include "general.h"
#include "crypto.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/sha.h"
// sprintf < 0 failed
int account_get_info_url(const char *url, BifAccountGetInfoRequest *req,
                         char *account_url) {
  if (req->domainid == 0) {
    return sprintf(account_url, "%s/getAccountBase?address=%s", url,
                   req->address);
  }
  return sprintf(account_url, "%s/getAccountBase?address=%s&domainid=%d", url,
                 req->address, req->domainid);
}

int contract_getInfo_url(const char *url, BifContractCheckValidRequest *req,
                         char *contract_url) {
  if (req->domainid == 0) {
    return sprintf(contract_url, "%s/getAccountBase?address=%s", url,
                   req->contract_address);
  }
  return sprintf(contract_url, "%s/getAccountBase?address=%s&domainid=%d", url,
                 req->contract_address, req->domainid);
}

int account_get_metadata_url(const char *url,
                             BifAccountGetMetadatasRequest *req,
                             char *metaUrl) {

  if (req->domainid == 0) {
    if (!strlen(req->key)) {
      return sprintf(metaUrl, "%s/getAccount?address=%s", url, req->address);
    } else if (strlen(req->key) < 1 || strlen(req->key) > 1024) {
      return -1;
    }
    return sprintf(metaUrl, "%s/getAccount?address=%s&key=%s", url,
                   req->address, req->key);
  } else {
    if (!strlen(req->key)) {
      return sprintf(metaUrl, "%s/getAccount?address=%s&domainid=%d", url,
                     req->address, req->domainid);
    } else if (strlen(req->key) < 1 || strlen(req->key) > 1024) {
      return -1;
    }
    return sprintf(metaUrl, "%s/getAccount?address=%s&key=%s&domainid=%d", url,
                   req->address, req->key, req->domainid);
  }
}

int evaluation_fee_url(const char *url, char *transaction_evaluation_url) {
  return sprintf(transaction_evaluation_url, "%s/testTransaction", url);
}

int transaction_blob_url(const char *url, char *blob_url) {
  return sprintf(blob_url, "%s/getTransactionBlob", url);
}

int parse_blob_url(const char *url, BifParseBlobRequest *req, char *blob_url) {
  if (!strcmp(req->env, "true")) {
    return sprintf(blob_url, "%s/getTransactionFromBlob?blob=%s&env=%s", url,
                   req->blob, req->env);
  }
  return sprintf(blob_url, "%s/getTransactionFromBlob?blob=%s", url, req->blob);
}

int transaction_submit_url(const char *url, char *submitUrl) {
  return sprintf(submitUrl, "%s/submitTransaction", url);
}

int contract_call_query_url(const char *url, char *contract_query_url) {
  return sprintf(contract_query_url, "%s/callContract", url);
}

int transaction_get_info_url(const char *url, BifTransactionGetInfoRequest *req,
                             char *transaction_by_hash_url) {
  if (req->domainid == 0) {
    return sprintf(transaction_by_hash_url, "%s/getTransactionHistory?hash=%s",
                   url, req->hash);
  }
  return sprintf(transaction_by_hash_url,
                 "%s/getTransactionHistory?hash=%s&domainid=%d", url, req->hash,
                 req->domainid);
}

int get_transactions_url(const char *url, BifBlockGetTransactionsRequest *req,
                         char *get_number_url) {
  if (req->domainid == 0) {
    return sprintf(get_number_url, "%s/getTransactionHistory?ledger_seq=%d",
                   url, req->block_number);
  }
  return sprintf(get_number_url,
                 "%s/getTransactionHistory?ledger_seq=%d&domainid=%d", url,
                 req->block_number, req->domainid);
}

int block_get_number_url(const char *url, const int domainid,
                         char *get_number_url) {
  if (domainid == 0) {
    return sprintf(get_number_url, "%s/getLedger?with_leader=true", url);
  }
  return sprintf(get_number_url, "%s/getLedger?with_leader=true&domainid=%d",
                 url, domainid);
}

int block_get_info_url(const char *url, BifBlockGetInfoRequest *req,
                       char *block_info_url) {
  if (req->domainid == 0) {
    if (req->block_number > 0) {
      return sprintf(block_info_url, "%s/getLedger?with_leader=true&seq=%d",
                     url, req->block_number);
    }
    return sprintf(block_info_url, "%s/getLedger?with_leader=true", url);
  } else {
    if (req->block_number > 0) {
      return sprintf(block_info_url,
                     "%s/getLedger?with_leader=true&seq=%d&domainid=%d", url,
                     req->block_number, req->domainid);
    }
    return sprintf(block_info_url, "%s/getLedger?with_leader=true&domainid=%d",
                   url, req->domainid);
  }
}

int block_latest_info_url(const char *url, BifBlockGetLatestInfoRequest *req,
                          char *block_latest_url) {
  if (req->domainid == 0) {
    return sprintf(block_latest_url, "%s/getLedger?with_leader=true", url);
  }
  return sprintf(block_latest_url, "%s/getLedger?with_leader=true&domainid=%d",
                 url, req->domainid);
}

int get_validators_url(const char *url, BifBlockGetValidatorsRequest *req,
                       char *validators_url) {
  if (req->domainid == 0) {
    if (req->block_number > 0) {
      return sprintf(validators_url,
                     "%s/getLedger?with_leader=true&with_validator=true&seq=%d",
                     url, req->block_number);
    }
    return sprintf(validators_url,
                   "%s/getLedger?with_leader=true&with_validator=true", url);
  } else {
    if (req->block_number > 0) {
      return sprintf(
          validators_url,
          "%s/"
          "getLedger?with_leader=true&with_validator=true&seq=%d&domainid=%d",
          url, req->block_number, req->domainid);
    }
    return sprintf(
        validators_url,
        "%s/getLedger?with_leader=true&with_validator=true&domainid=%d", url,
        req->domainid);
  }
}

int get_latest_validators_url(const char *url,
                              BifBlockGetValidatorsRequest *req,
                              char *validators_url) {
  if (req->domainid == 0) {
    return sprintf(validators_url,
                   "%s/getLedger?with_leader=true&with_validator=true", url);
  }
  return sprintf(
      validators_url,
      "%s/getLedger?with_leader=true&with_validator=true&domainid=%d", url,
      req->domainid);
}

int get_tx_cache_size_url(int domainid, const char *url,
                          char *tx_cache_size_url) {
  if (domainid != 0) {
    return sprintf(tx_cache_size_url, "%s/getTxCacheSize?domainid=%d", url,
                   domainid);
  }
  return sprintf(tx_cache_size_url, "%s/getTxCacheSize", url);
}

int get_tx_cache_url(const char *url, BifTransactionGetInfoRequest *req,
                     char *cache_data_url) {
  if (req->domainid == 0) {
    if (!strlen(req->hash)) {
      return sprintf(cache_data_url, "%s/getTransactionCache", url);
    }
    return sprintf(cache_data_url, "%s/getTransactionCache?hash=%s", url,
                   req->hash);
  } else {
    if (!strlen(req->hash)) {
      return sprintf(cache_data_url, "%s/getTransactionCache?domainid=%d", url,
                     req->domainid);
    }
    return sprintf(cache_data_url, "%s/getTransactionCache?hash=%s&domainid=%d",
                   url, req->hash, req->domainid);
  }
}

void sdk_free(void *p) {
  if (p) {
    free(p);
    p = NULL;
  }
}
void *sdk_malloc(size_t size) {
  void *ptr = malloc(size);
  if (ptr == NULL) {
    printf("malloc memory null\n");
    exit(-1);
  }
  memset(ptr, 0, size);
  return ptr;
}

int check_addr_prefix(const char *address) {
  char temp_enc_address[128] = {0};
  char *items[5] = {NULL};
  char *enc_split_address = NULL;
  if (address == NULL)
    return -1;
  if (!strlen(address)) {
    return -1;
  }
  strcpy(temp_enc_address, address);
  int item_len = spit_words(':', temp_enc_address, items);
  if (item_len != 3 && item_len != 4) {
    return -1;
  }
  if (item_len == 3) {
    enc_split_address = items[2];
  } else {
    enc_split_address = items[3];
  }
  if (!strstr(enc_split_address, "ef") && !strstr(enc_split_address, "zf")) {
    printf("invalid address\n");
    return -1;
  }
  int decode_len = 0;
  char *base58_decode_data = base58_decode(enc_split_address + 2, &decode_len);
  if (decode_len != 22) {
    printf("enc_split_address:%s\n", enc_split_address + 2);
    printf("invalid address decode58_data:%s != 22\n", base58_decode_data);
    sdk_free(base58_decode_data);
    return -1;
  }
  sdk_free(base58_decode_data);
  return 0;
}