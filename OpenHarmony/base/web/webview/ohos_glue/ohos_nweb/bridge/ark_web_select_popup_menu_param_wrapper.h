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

#ifndef ARK_WEB_SELECT_POPUP_MENU_PARAM_WRAPPER_H_
#define ARK_WEB_SELECT_POPUP_MENU_PARAM_WRAPPER_H_
#pragma once

#include "include/nweb_select_popup_menu.h"
#include "ohos_nweb/include/ark_web_select_popup_menu_param.h"

namespace OHOS::ArkWeb {

class ArkWebSelectPopupMenuParamWrapper : public OHOS::NWeb::NWebSelectPopupMenuParam {
public:
    ArkWebSelectPopupMenuParamWrapper(ArkWebRefPtr<ArkWebSelectPopupMenuParam> ark_web_select_popup_menu_param);
    ~ArkWebSelectPopupMenuParamWrapper() = default;

    std::vector<std::shared_ptr<OHOS::NWeb::NWebSelectPopupMenuItem>> GetMenuItems() override;

    int GetItemHeight() override;

    int GetSelectedItem() override;

    double GetItemFontSize() override;

    bool GetIsRightAligned() override;

    std::shared_ptr<OHOS::NWeb::NWebSelectMenuBound> GetSelectMenuBound() override;

    bool GetIsAllowMultipleSelection() override;

private:
    ArkWebRefPtr<ArkWebSelectPopupMenuParam> ark_web_select_popup_menu_param_;
};

} // namespace OHOS::ArkWeb

#endif // ARK_WEB_SELECT_POPUP_MENU_PARAM_WRAPPER_H_
