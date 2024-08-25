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

#ifndef ARK_WEB_CONSOLE_LOG_CTOCPP_H_
#define ARK_WEB_CONSOLE_LOG_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_console_log_capi.h"
#include "ohos_nweb/include/ark_web_console_log.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebConsoleLogCToCpp
    : public ArkWebCToCppRefCounted<ArkWebConsoleLogCToCpp, ArkWebConsoleLog, ark_web_console_log_t> {
public:
    ArkWebConsoleLogCToCpp();
    virtual ~ArkWebConsoleLogCToCpp();

    // ArkWebConsoleLog methods.
    ArkWebString Log() override;

    ArkWebString SourceId() override;

    int LogLevel() override;

    int LineNumer() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_CONSOLE_LOG_CTOCPP_H_
