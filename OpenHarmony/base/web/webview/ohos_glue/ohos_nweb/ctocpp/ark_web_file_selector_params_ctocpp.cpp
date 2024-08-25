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

#include "ohos_nweb/ctocpp/ark_web_file_selector_params_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int ArkWebFileSelectorParamsCToCpp::Mode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_file_selector_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, mode, 0);

    // Execute
    return _struct->mode(_struct);
}

ARK_WEB_NO_SANITIZE
const ArkWebString ArkWebFileSelectorParamsCToCpp::Title()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_file_selector_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, title, ark_web_string_default);

    // Execute
    return _struct->title(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebFileSelectorParamsCToCpp::IsCapture()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_file_selector_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, is_capture, false);

    // Execute
    return _struct->is_capture(_struct);
}

ARK_WEB_NO_SANITIZE
const ArkWebStringVector ArkWebFileSelectorParamsCToCpp::AcceptType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_file_selector_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_vector_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, accept_type, ark_web_string_vector_default);

    // Execute
    return _struct->accept_type(_struct);
}

ARK_WEB_NO_SANITIZE
const ArkWebString ArkWebFileSelectorParamsCToCpp::DefaultFilename()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_file_selector_params_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, default_filename, ark_web_string_default);

    // Execute
    return _struct->default_filename(_struct);
}

ArkWebFileSelectorParamsCToCpp::ArkWebFileSelectorParamsCToCpp() {}

ArkWebFileSelectorParamsCToCpp::~ArkWebFileSelectorParamsCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebFileSelectorParamsCToCpp, ArkWebFileSelectorParams,
    ark_web_file_selector_params_t>::kBridgeType = ARK_WEB_FILE_SELECTOR_PARAMS;

} // namespace OHOS::ArkWeb
