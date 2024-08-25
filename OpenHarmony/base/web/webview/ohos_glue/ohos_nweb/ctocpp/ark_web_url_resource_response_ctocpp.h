/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ARK_WEB_URL_RESOURCE_RESPONSE_CTOCPP_H_
#define ARK_WEB_URL_RESOURCE_RESPONSE_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_url_resource_response_capi.h"
#include "ohos_nweb/include/ark_web_url_resource_response.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebUrlResourceResponseCToCpp : public ArkWebCToCppRefCounted<ArkWebUrlResourceResponseCToCpp,
                                            ArkWebUrlResourceResponse, ark_web_url_resource_response_t> {
public:
    ArkWebUrlResourceResponseCToCpp();
    virtual ~ArkWebUrlResourceResponseCToCpp();

    // ArkWebUrlResourceResponse methods.
    ArkWebString ResponseData() override;

    void PutResponseData(const ArkWebString& input_stream) override;

    ArkWebString ResponseStatus() override;

    const ArkWebStringMap ResponseHeaders() override;

    void PutResponseHeaders(const ArkWebStringMap& response_headers) override;

    int32_t ResponseDataType() override;

    ArkWebString ResponseMimeType() override;

    void PutResponseMimeType(const ArkWebString& mime_type) override;

    ArkWebString ResponseEncoding() override;

    void PutResponseEncoding(const ArkWebString& encoding) override;

    bool ResponseDataStatus() override;

    void PutResponseDataStatus(bool is_data_ready) override;

    int ResponseStatusCode() override;

    ArkWebString ResponseResourceUrl() override;

    void PutResponseResourceUrl(const ArkWebString& url) override;

    int ResponseFileHandle() override;

    void PutResponseFileHandle(int fd) override;

    bool ResponseIsFileHandle() override;

    void PutResponseStateAndStatuscode(int status_code, const ArkWebString& reason_phrase) override;

    void PutResponseReadyCallback(ArkWebRefPtr<ArkWebResourceReadyCallback> callback) override;

    void PutResponseDataBuffer(char* buffer, size_t bufferSize) override;

    char* GetResponseDataBuffer() override;

    size_t GetResponseDataBufferSize() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_URL_RESOURCE_RESPONSE_CTOCPP_H_
