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

#include "ohos_nweb/ctocpp/ark_web_console_log_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebConsoleLogCToCpp::Log()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_console_log_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, log, ark_web_string_default);

    // Execute
    return _struct->log(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebString ArkWebConsoleLogCToCpp::SourceId()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_console_log_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_string_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, source_id, ark_web_string_default);

    // Execute
    return _struct->source_id(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebConsoleLogCToCpp::LogLevel()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_console_log_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, log_level, 0);

    // Execute
    return _struct->log_level(_struct);
}

ARK_WEB_NO_SANITIZE
int ArkWebConsoleLogCToCpp::LineNumer()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_console_log_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, line_numer, 0);

    // Execute
    return _struct->line_numer(_struct);
}

ArkWebConsoleLogCToCpp::ArkWebConsoleLogCToCpp() {}

ArkWebConsoleLogCToCpp::~ArkWebConsoleLogCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebConsoleLogCToCpp, ArkWebConsoleLog, ark_web_console_log_t>::kBridgeType =
    ARK_WEB_CONSOLE_LOG;

} // namespace OHOS::ArkWeb
