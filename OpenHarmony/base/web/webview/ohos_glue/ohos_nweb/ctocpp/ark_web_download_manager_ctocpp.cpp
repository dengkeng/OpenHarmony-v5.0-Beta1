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

#include "ohos_nweb/ctocpp/ark_web_download_manager_ctocpp.h"

#include "ohos_nweb/cpptoc/ark_web_doh_config_cpptoc.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
void ArkWebDownloadManagerCToCpp::SetHttpDns(ArkWebRefPtr<ArkWebDohConfig> config)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_download_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_http_dns, );

    // Execute
    _struct->set_http_dns(_struct, ArkWebDohConfigCppToC::Invert(config));
}

ARK_WEB_NO_SANITIZE
void ArkWebDownloadManagerCToCpp::SetConnectionTimeout(const int& timeout)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_download_manager_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_connection_timeout, );

    // Execute
    _struct->set_connection_timeout(_struct, &timeout);
}

ArkWebDownloadManagerCToCpp::ArkWebDownloadManagerCToCpp() {}

ArkWebDownloadManagerCToCpp::~ArkWebDownloadManagerCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebDownloadManagerCToCpp, ArkWebDownloadManager,
    ark_web_download_manager_t>::kBridgeType = ARK_WEB_DOWNLOAD_MANAGER;

} // namespace OHOS::ArkWeb
