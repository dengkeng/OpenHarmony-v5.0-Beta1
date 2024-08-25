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

#ifndef ARK_WEB_SELECT_POPUP_MENU_ITEM_CTOCPP_H_
#define ARK_WEB_SELECT_POPUP_MENU_ITEM_CTOCPP_H_
#pragma once

#include "ohos_nweb/capi/ark_web_select_popup_menu_item_capi.h"
#include "ohos_nweb/include/ark_web_select_popup_menu_item.h"

#include "base/ctocpp/ark_web_ctocpp_ref_counted.h"

namespace OHOS::ArkWeb {

// Wrap a C structure with a C++ class.
// This class may be instantiated and accessed wrapper-side only.
class ArkWebSelectPopupMenuItemCToCpp : public ArkWebCToCppRefCounted<ArkWebSelectPopupMenuItemCToCpp,
                                            ArkWebSelectPopupMenuItem, ark_web_select_popup_menu_item_t> {
public:
    ArkWebSelectPopupMenuItemCToCpp();
    virtual ~ArkWebSelectPopupMenuItemCToCpp();

    // ArkWebSelectPopupMenuItem methods.
    int GetType() override;

    ArkWebString GetLabel() override;

    uint32_t GetAction() override;

    ArkWebString GetToolTip() override;

    bool GetIsChecked() override;

    bool GetIsEnabled() override;

    int GetTextDirection() override;

    bool GetHasTextDirectionOverride() override;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_SELECT_POPUP_MENU_ITEM_CTOCPP_H_
