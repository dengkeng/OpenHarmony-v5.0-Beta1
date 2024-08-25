/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstdio>
#include <string>
#include "curl/curl.h"
#include "http.h"
#include <securec.h>
#define CURLEASYGETINFO 200
static size_t HttpCurlWriteStrData(void *buffer, size_t size, size_t nmemb, void *userp)
{
    if (userp == nullptr || buffer == nullptr || size == 0) {
        return 0;
    }
        
    size_t realSize = size * nmemb;
    std::string *pstr = (std::string *)userp;
    if (pstr != nullptr) {
        pstr->append((const char *)buffer, realSize);
    }

    return realSize;
}

int HttpPost(std::string url, unsigned char *request, uint32_t requestLen, unsigned char *response,
    int32_t *responseLen, uint32_t timeout)
{
    int ret = -1;
    CURL *curl = curl_easy_init();
    if (curl == nullptr) {
        printf("curl_easy_init failed\n");
        return -1;
    }
    // url
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    // headers
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    // request raw data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, requestLen);
    // response raw data
    std::string tempStr;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&tempStr);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpCurlWriteStrData);
    // timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    // http post
#ifndef SUPPORT_FUZZ
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("[error] curl_easy_perform failed\n");
        ret = -1;
    }
#endif
    long resCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resCode);
    if (resCode != CURLEASYGETINFO) {
        printf("[error] curl_easy_getinfo failed");
        ret = -1;
    }
    ret = memcpy_s(response, tempStr.size(), tempStr.c_str(), tempStr.size());
    if (ret != 0) {
        printf("[error] memcpy_s faild!\n");
        return ret;
    }
    *responseLen = tempStr.size();
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return 0;
}
