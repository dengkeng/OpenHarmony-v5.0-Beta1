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

#include "ohos_adapter/cpptoc/ark_battery_mgr_client_adapter_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_battery_info_cpptoc.h"
#include "ohos_adapter/ctocpp/ark_battery_event_callback_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

void ARK_WEB_CALLBACK ark_battery_mgr_client_adapter_reg_battery_event(
    struct _ark_battery_mgr_client_adapter_t* self, ark_battery_event_callback_t* eventCallback)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkBatteryMgrClientAdapterCppToC::Get(self)->RegBatteryEvent(ArkBatteryEventCallbackCToCpp::Invert(eventCallback));
}

bool ARK_WEB_CALLBACK ark_battery_mgr_client_adapter_start_listen(struct _ark_battery_mgr_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkBatteryMgrClientAdapterCppToC::Get(self)->StartListen();
}

void ARK_WEB_CALLBACK ark_battery_mgr_client_adapter_stop_listen(struct _ark_battery_mgr_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkBatteryMgrClientAdapterCppToC::Get(self)->StopListen();
}

ark_battery_info_t* ARK_WEB_CALLBACK ark_battery_mgr_client_adapter_request_battery_info(
    struct _ark_battery_mgr_client_adapter_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkBatteryInfo> _retval = ArkBatteryMgrClientAdapterCppToC::Get(self)->RequestBatteryInfo();

    // Return type: refptr_same
    return ArkBatteryInfoCppToC::Invert(_retval);
}

} // namespace

ArkBatteryMgrClientAdapterCppToC::ArkBatteryMgrClientAdapterCppToC()
{
    GetStruct()->reg_battery_event = ark_battery_mgr_client_adapter_reg_battery_event;
    GetStruct()->start_listen = ark_battery_mgr_client_adapter_start_listen;
    GetStruct()->stop_listen = ark_battery_mgr_client_adapter_stop_listen;
    GetStruct()->request_battery_info = ark_battery_mgr_client_adapter_request_battery_info;
}

ArkBatteryMgrClientAdapterCppToC::~ArkBatteryMgrClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkBatteryMgrClientAdapterCppToC, ArkBatteryMgrClientAdapter,
    ark_battery_mgr_client_adapter_t>::kBridgeType = ARK_BATTERY_MGR_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb
