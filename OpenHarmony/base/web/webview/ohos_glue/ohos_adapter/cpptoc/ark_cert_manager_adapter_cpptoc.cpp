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

#include "ohos_adapter/cpptoc/ark_cert_manager_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

uint32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_cert_max_size(struct _ark_cert_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetCertMaxSize();
}

uint32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_app_cert_max_size(struct _ark_cert_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetAppCertMaxSize();
}

int32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_sytem_root_cert_data(
    struct _ark_cert_manager_adapter_t* self, uint32_t certCount, uint8_t* certData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetSytemRootCertData(certCount, certData);
}

uint32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_sytem_root_cert_sum(struct _ark_cert_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetSytemRootCertSum();
}

int32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_user_root_cert_data(
    struct _ark_cert_manager_adapter_t* self, uint32_t certCount, uint8_t* certData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetUserRootCertData(certCount, certData);
}

uint32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_user_root_cert_sum(struct _ark_cert_manager_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetUserRootCertSum();
}

int32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_app_cert(
    struct _ark_cert_manager_adapter_t* self, uint8_t* uriData, uint8_t* certData, uint32_t* len)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(uriData, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(len, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetAppCert(uriData, certData, len);
}

int32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_sign(struct _ark_cert_manager_adapter_t* self, const uint8_t* uri,
    const uint8_t* certData, uint32_t certDataLen, uint8_t* signData, uint32_t signDataLen)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(uri, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(signData, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->Sign(uri, certData, certDataLen, signData, signDataLen);
}

int32_t ARK_WEB_CALLBACK ark_cert_manager_adapter_get_cert_data_by_subject(
    struct _ark_cert_manager_adapter_t* self, const char* subjectName, uint8_t* certData, int32_t certType)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(subjectName, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetCertDataBySubject(subjectName, certData, certType);
}

int ARK_WEB_CALLBACK ark_cert_manager_adapter_verify_cert_from_net_ssl(
    struct _ark_cert_manager_adapter_t* self, uint8_t* certData, uint32_t certSize)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(certData, 0);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->VerifyCertFromNetSsl(certData, certSize);
}

bool ARK_WEB_CALLBACK ark_cert_manager_adapter_get_trust_anchors_for_host_name(
    struct _ark_cert_manager_adapter_t* self, const ArkWebString* hostname, ArkWebStringVector* certs)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(hostname, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(certs, false);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetTrustAnchorsForHostName(*hostname, *certs);
}

bool ARK_WEB_CALLBACK ark_cert_manager_adapter_get_pin_set_for_host_name(
    struct _ark_cert_manager_adapter_t* self, const ArkWebString* hostname, ArkWebStringVector* pins)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(hostname, false);

    ARK_WEB_CPPTOC_CHECK_PARAM(pins, false);

    // Execute
    return ArkCertManagerAdapterCppToC::Get(self)->GetPinSetForHostName(*hostname, *pins);
}

} // namespace

ArkCertManagerAdapterCppToC::ArkCertManagerAdapterCppToC()
{
    GetStruct()->get_cert_max_size = ark_cert_manager_adapter_get_cert_max_size;
    GetStruct()->get_app_cert_max_size = ark_cert_manager_adapter_get_app_cert_max_size;
    GetStruct()->get_sytem_root_cert_data = ark_cert_manager_adapter_get_sytem_root_cert_data;
    GetStruct()->get_sytem_root_cert_sum = ark_cert_manager_adapter_get_sytem_root_cert_sum;
    GetStruct()->get_user_root_cert_data = ark_cert_manager_adapter_get_user_root_cert_data;
    GetStruct()->get_user_root_cert_sum = ark_cert_manager_adapter_get_user_root_cert_sum;
    GetStruct()->get_app_cert = ark_cert_manager_adapter_get_app_cert;
    GetStruct()->sign = ark_cert_manager_adapter_sign;
    GetStruct()->get_cert_data_by_subject = ark_cert_manager_adapter_get_cert_data_by_subject;
    GetStruct()->verify_cert_from_net_ssl = ark_cert_manager_adapter_verify_cert_from_net_ssl;
    GetStruct()->get_trust_anchors_for_host_name = ark_cert_manager_adapter_get_trust_anchors_for_host_name;
    GetStruct()->get_pin_set_for_host_name = ark_cert_manager_adapter_get_pin_set_for_host_name;
}

ArkCertManagerAdapterCppToC::~ArkCertManagerAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkCertManagerAdapterCppToC, ArkCertManagerAdapter,
    ark_cert_manager_adapter_t>::kBridgeType = ARK_CERT_MANAGER_ADAPTER;

} // namespace OHOS::ArkWeb
