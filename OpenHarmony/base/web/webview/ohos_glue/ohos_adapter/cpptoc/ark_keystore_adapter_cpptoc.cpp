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

#include "ohos_adapter/cpptoc/ark_keystore_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

ArkWebString ARK_WEB_CALLBACK ark_keystore_adapter_encrypt_key(
    struct _ark_keystore_adapter_t* self, const ArkWebString* alias, const ArkWebString* plainData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(alias, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(plainData, ark_web_string_default);

    // Execute
    return ArkKeystoreAdapterCppToC::Get(self)->EncryptKey(*alias, *plainData);
}

ArkWebString ARK_WEB_CALLBACK ark_keystore_adapter_decrypt_key(
    struct _ark_keystore_adapter_t* self, const ArkWebString* alis, const ArkWebString* encryptedData)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(alis, ark_web_string_default);

    ARK_WEB_CPPTOC_CHECK_PARAM(encryptedData, ark_web_string_default);

    // Execute
    return ArkKeystoreAdapterCppToC::Get(self)->DecryptKey(*alis, *encryptedData);
}

} // namespace

ArkKeystoreAdapterCppToC::ArkKeystoreAdapterCppToC()
{
    GetStruct()->encrypt_key = ark_keystore_adapter_encrypt_key;
    GetStruct()->decrypt_key = ark_keystore_adapter_decrypt_key;
}

ArkKeystoreAdapterCppToC::~ArkKeystoreAdapterCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkKeystoreAdapterCppToC, ArkKeystoreAdapter, ark_keystore_adapter_t>::kBridgeType =
        ARK_KEYSTORE_ADAPTER;

} // namespace OHOS::ArkWeb
