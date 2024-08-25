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

#ifndef ARK_WEB_CONTEXT_MENU_CALLBACK_CTOCPP_H_
#define ARK_WEB_CONTEXT_MENU_CALLBACK_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_context_menu_callback_capi.h"
#include "ohos_nweb/include/ark_web_context_menu_callback.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebContextMenuCallbackCToCpp : public ArkWebCToCppRefCounted<ArkWebContextMenuCallbackCToCpp,
                                            ArkWebContextMenuCallback, ark_web_context_menu_callback_t> {
public:
    ArkWebContextMenuCallbackCToCpp();
    virtual ~ArkWebContextMenuCallbackCToCpp();

    // ArkWebContextMenuCallback methods.
    void Cancel() override;

    void Continue(int32_t command_id, int flag) override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_CONTEXT_MENU_CALLBACK_CTOCPP_H_
