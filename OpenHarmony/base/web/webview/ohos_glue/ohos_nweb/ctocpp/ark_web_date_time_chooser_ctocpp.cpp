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

#include "ohos_nweb/ctocpp/ark_web_date_time_chooser_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

ARK_WEB_NO_SANITIZE
int ArkWebDateTimeChooserCToCpp::GetType()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_type, 0);

    // Execute
    return _struct->get_type(_struct);
}

ARK_WEB_NO_SANITIZE
double ArkWebDateTimeChooserCToCpp::GetStep()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_step, 0);

    // Execute
    return _struct->get_step(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebDateTime ArkWebDateTimeChooserCToCpp::GetMinimum()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_date_time_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_minimum, ark_web_date_time_default);

    // Execute
    return _struct->get_minimum(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebDateTime ArkWebDateTimeChooserCToCpp::GetMaximum()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_date_time_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_maximum, ark_web_date_time_default);

    // Execute
    return _struct->get_maximum(_struct);
}

ARK_WEB_NO_SANITIZE
ArkWebDateTime ArkWebDateTimeChooserCToCpp::GetDialogValue()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, ark_web_date_time_default);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_dialog_value, ark_web_date_time_default);

    // Execute
    return _struct->get_dialog_value(_struct);
}

ARK_WEB_NO_SANITIZE
bool ArkWebDateTimeChooserCToCpp::GetHasSelected()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, false);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_has_selected, false);

    // Execute
    return _struct->get_has_selected(_struct);
}

ARK_WEB_NO_SANITIZE
size_t ArkWebDateTimeChooserCToCpp::GetSuggestionIndex()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_date_time_chooser_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_suggestion_index, 0);

    // Execute
    return _struct->get_suggestion_index(_struct);
}

ArkWebDateTimeChooserCToCpp::ArkWebDateTimeChooserCToCpp() {}

ArkWebDateTimeChooserCToCpp::~ArkWebDateTimeChooserCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebDateTimeChooserCToCpp, ArkWebDateTimeChooser,
    ark_web_date_time_chooser_t>::kBridgeType = ARK_WEB_DATE_TIME_CHOOSER;

} // namespace OHOS::ArkWeb
