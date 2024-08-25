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

#include "ohos_adapter/cpptoc/ark_aafwk_app_mgr_client_adapter_cpptoc.h"

#include "ohos_adapter/ctocpp/ark_aafwk_render_scheduler_host_adapter_ctocpp.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

int ARK_WEB_CALLBACK ark_aafwk_app_mgr_client_adapter_start_render_process(
    struct _ark_aafwk_app_mgr_client_adapter_t* self, const ArkWebString* renderParam, int32_t ipcFd, int32_t sharedFd,
    int32_t crashFd, pid_t* renderPid)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(renderParam, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(renderPid, 0);

    // Execute
    return ArkAafwkAppMgrClientAdapterCppToC::Get(self)->StartRenderProcess(
        *renderParam, ipcFd, sharedFd, crashFd, *renderPid);
}

void ARK_WEB_CALLBACK ark_aafwk_app_mgr_client_adapter_attach_render_process(
    struct _ark_aafwk_app_mgr_client_adapter_t* self, ark_aafwk_render_scheduler_host_adapter_t* adapter)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, );

    // Execute
    ArkAafwkAppMgrClientAdapterCppToC::Get(self)->AttachRenderProcess(
        ArkAafwkRenderSchedulerHostAdapterCToCpp::Invert(adapter));
}

int ARK_WEB_CALLBACK ark_aafwk_app_mgr_client_adapter_get_render_process_termination_status(
    struct _ark_aafwk_app_mgr_client_adapter_t* self, pid_t renderPid, int* status)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, 0);

    ARK_WEB_CPPTOC_CHECK_PARAM(status, 0);

    // Execute
    return ArkAafwkAppMgrClientAdapterCppToC::Get(self)->GetRenderProcessTerminationStatus(renderPid, *status);
}

} // namespace

ArkAafwkAppMgrClientAdapterCppToC::ArkAafwkAppMgrClientAdapterCppToC()
{
    GetStruct()->start_render_process = ark_aafwk_app_mgr_client_adapter_start_render_process;
    GetStruct()->attach_render_process = ark_aafwk_app_mgr_client_adapter_attach_render_process;
    GetStruct()->get_render_process_termination_status =
        ark_aafwk_app_mgr_client_adapter_get_render_process_termination_status;
}

ArkAafwkAppMgrClientAdapterCppToC::~ArkAafwkAppMgrClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkAafwkAppMgrClientAdapterCppToC, ArkAafwkAppMgrClientAdapter,
    ark_aafwk_app_mgr_client_adapter_t>::kBridgeType = ARK_AAFWK_APP_MGR_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb
