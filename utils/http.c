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
 * @file: http.c
 */
#include "http.h"
#include "curl/curl.h"

size_t saveRespData(void *data, size_t size, size_t nmemb, void *args) {
  // 回调函数实现：一次请求可能多次调回调函数
  // 当前一次回调段数据量长度, size：一块数据的长度， nmemb：当前多少块
  uint32_t len = size * nmemb;
  void *ptr = NULL;

  buf_t *buf = (buf_t *)args;
  // 检查数据是否超过了缓冲区的大小。如果是，则设置用户定义的上下文值并返回0以表示curl存在问题
  if (buf->len + len > 1024000) {
    return 0;
  }

  // 重新分配长度
  if ((ptr = realloc(buf->data, buf->len + len + 1)) == NULL) {
    // printf("Failed to realloc for buf->data");
    return 0;
  }
  buf->data = ptr;

  // 拷贝
  memcpy(buf->data + buf->len, data, len);
  // 防止内存中有脏数据
  ((char *)buf->data)[len] = '\0';
  buf->len += len;

  return len;
}

int http_get(const char *url, int timeout, void **value, size_t *valueLen) {
  CURL *curl = NULL; // curl上下文
  CURLcode rCode;    // curl返回码
  memset(&rCode, 0, sizeof(rCode));

  // 是实例化curl以及设置回调
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url); // 设置uri
  curl_easy_setopt(curl, CURLOPT_TIMEOUT,
                   timeout); // 设置传输等待超时 默认设置5s

  buf_t buf;
  memset(&buf, 0, sizeof(buf));

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf); // 设置接收响应data的数据
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                   saveRespData); // 设置保存响应数据的回调函数
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  // 执行操作
  if ((rCode = curl_easy_perform(curl)) != CURLE_OK) {
    curl_easy_cleanup(curl);
    if (buf.data) {
      free(buf.data);
    }
    return -1;
  }

  *value = buf.data;
  *valueLen = buf.len;

  // printf(" value: [%lu][%s]\n", buf.len, buf.data);
  // 清除curl
  curl_easy_cleanup(curl);
  return 0;
}

int http_post(const char *url, const char *data, int timeout, void **value,
              size_t *valueLen) {
  CURL *curl = NULL; // curl上下文
  CURLcode rCode;    // curl返回码
  memset(&rCode, 0, sizeof(rCode));

  // 是实例化curl以及设置回调
  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, url); // 设置uri
  curl_easy_setopt(curl, CURLOPT_TIMEOUT,
                   timeout); // 设置传输等待超时 默认设置5s

  buf_t buf;
  memset(&buf, 0, sizeof(buf));

  curl_easy_setopt(curl, CURLOPT_POST, 1);         // post请求
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf); // 设置接收响应的数据
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                   saveRespData); // 设置保存响应数据的回调函数
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data); // post数据

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  // 执行操作
  if ((rCode = curl_easy_perform(curl)) != CURLE_OK) {
    curl_easy_cleanup(curl);
    if (buf.data) {
      free(buf.data);
    }
    return -1;
  }

  *value = buf.data;
  *valueLen = buf.len;

  // printf(" value: [%lu][%s]\n", buf.len, buf.data);
  // 清除curl
  curl_easy_cleanup(curl);
  return 0;
}
