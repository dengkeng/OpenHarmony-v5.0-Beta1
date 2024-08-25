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

#include "ohos_nweb/ctocpp/ark_web_url_resource_response_ctocpp.h"

#include "ohos_nweb/cpptoc/ark_web_resource_ready_callback_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceResponseCToCpp::ResponseData()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_data, ark_web_string_default);

    // Execute
    return _struct->response_data(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseData(const ArkWebString& input_stream)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_data, );

    // Execute
    _struct->put_response_data(_struct, &input_stream);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceResponseCToCpp::ResponseStatus()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_status, ark_web_string_default);

    // Execute
    return _struct->response_status(_struct);
}

ARK_WEB_NO_SANITIZE
const ArkWebStringMap ArkWebUrlResourceResponseCToCpp::ResponseHeaders()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_map_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_headers, ark_web_string_map_default);

    // Execute
    return _struct->response_headers(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseHeaders(const ArkWebStringMap& response_headers)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_headers, );

    // Execute
    _struct->put_response_headers(_struct, &response_headers);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebUrlResourceResponseCToCpp::ResponseDataType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_data_type, 0);

    // Execute
    return _struct->response_data_type(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceResponseCToCpp::ResponseMimeType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_mime_type, ark_web_string_default);

    // Execute
    return _struct->response_mime_type(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseMimeType(const ArkWebString& mime_type)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_mime_type, );

    // Execute
    _struct->put_response_mime_type(_struct, &mime_type);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceResponseCToCpp::ResponseEncoding()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_encoding, ark_web_string_default);

    // Execute
    return _struct->response_encoding(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseEncoding(const ArkWebString& encoding)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_encoding, );

    // Execute
    _struct->put_response_encoding(_struct, &encoding);
}

ARK_WEB_NO_SANITIZE
bool ArkWebUrlResourceResponseCToCpp::ResponseDataStatus()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_data_status, false);

    // Execute
    return _struct->response_data_status(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseDataStatus(bool is_data_ready)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_data_status, );

    // Execute
    _struct->put_response_data_status(_struct, is_data_ready);
}

ARK_WEB_NO_SANITIZE
int ArkWebUrlResourceResponseCToCpp::ResponseStatusCode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_status_code, 0);

    // Execute
    return _struct->response_status_code(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebUrlResourceResponseCToCpp::ResponseResourceUrl()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_resource_url, ark_web_string_default);

    // Execute
    return _struct->response_resource_url(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseResourceUrl(const ArkWebString& url)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_resource_url, );

    // Execute
    _struct->put_response_resource_url(_struct, &url);
}

ARK_WEB_NO_SANITIZE
int ArkWebUrlResourceResponseCToCpp::ResponseFileHandle()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_file_handle, 0);

    // Execute
    return _struct->response_file_handle(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseFileHandle(int fd)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_file_handle, );

    // Execute
    _struct->put_response_file_handle(_struct, fd);
}

ARK_WEB_NO_SANITIZE
bool ArkWebUrlResourceResponseCToCpp::ResponseIsFileHandle()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, response_is_file_handle, false);

    // Execute
    return _struct->response_is_file_handle(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseStateAndStatuscode(int status_code, const ArkWebString& reason_phrase)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_state_and_statuscode, );

    // Execute
    _struct->put_response_state_and_statuscode(_struct, status_code, &reason_phrase);
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseReadyCallback(ArkWebRefPtr<ArkWebResourceReadyCallback> callback)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_ready_callback, );

    // Execute
    _struct->put_response_ready_callback(_struct, ArkWebResourceReadyCallbackCppToC::Invert(callback));
}

ARK_WEB_NO_SANITIZE
void ArkWebUrlResourceResponseCToCpp::PutResponseDataBuffer(char* buffer, size_t bufferSize)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, put_response_data_buffer, );

    // Execute
    _struct->put_response_data_buffer(_struct, buffer, bufferSize);
}

ARK_WEB_NO_SANITIZE
char* ArkWebUrlResourceResponseCToCpp::GetResponseDataBuffer()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, NULL);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_response_data_buffer, NULL);

    // Execute
    return _struct->get_response_data_buffer(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkWebUrlResourceResponseCToCpp::GetResponseDataBufferSize()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_url_resource_response_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_response_data_buffer_size, 0);

    // Execute
    return _struct->get_response_data_buffer_size(_struct);
}

ArkWebUrlResourceResponseCToCpp::ArkWebUrlResourceResponseCToCpp() {}

ArkWebUrlResourceResponseCToCpp::~ArkWebUrlResourceResponseCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebUrlResourceResponseCToCpp, ArkWebUrlResourceResponse,
    ark_web_url_resource_response_t>::kBridgeType = ARK_WEB_URL_RESOURCE_RESPONSE;

} // namespace OHOS::ArkWeb
