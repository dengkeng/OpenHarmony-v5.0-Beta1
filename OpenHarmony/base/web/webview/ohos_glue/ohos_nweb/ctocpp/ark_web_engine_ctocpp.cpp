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

#include "ohos_nweb/ctocpp/ark_web_engine_ctocpp.h"

#include "ohos_nweb/bridge/ark_web_nweb_bridge_helper.h"
#include "ohos_nweb/cpptoc/ark_web_engine_init_args_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_engine_prefetch_args_cpptoc.h"
#include "ohos_nweb/cpptoc/ark_web_nweb_create_info_cpptoc.h"
#include "ohos_nweb/ctocpp/ark_web_cookie_manager_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_data_base_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_download_manager_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_nweb_ctocpp.h"
#include "ohos_nweb/ctocpp/ark_web_web_storage_ctocpp.h"

#include "base/ctocpp/ark_web_ctocpp_macros.h"

namespace OHOS::ArkWeb {

using ArkWebEngineGetInstanceFunc = ark_web_engine_t* (*)(void);
static ArkWebEngineGetInstanceFunc ark_web_engine_get_instance = nullptr;

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebEngine> ArkWebEngine::GetInstance()
{
    ARK_WEB_CTOCPP_DV_LOG();

    if (!ark_web_engine_get_instance) {
        ark_web_engine_get_instance = reinterpret_cast<ArkWebEngineGetInstanceFunc>(
            ArkWebNWebBridgeHelper::GetInstance().LoadFuncSymbol("ark_web_engine_get_instance_static"));
        if (!ark_web_engine_get_instance) {
            ARK_WEB_CTOCPP_WRAN_LOG("failed to get static function symbol");
            return nullptr;
        }
    }

    // Execute
    ark_web_engine_t* _retval = ark_web_engine_get_instance();

    // Return type: refptr_same
    return ArkWebEngineCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebNWeb> ArkWebEngineCToCpp::CreateNWeb(ArkWebRefPtr<ArkWebNWebCreateInfo> create_info)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, create_nweb, nullptr);

    // Execute
    ark_web_nweb_t* _retval = _struct->create_nweb(_struct, ArkWebNWebCreateInfoCppToC::Invert(create_info));

    // Return type: refptr_same
    return ArkWebNWebCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebNWeb> ArkWebEngineCToCpp::GetNWeb(int32_t nweb_id)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_nweb, nullptr);

    // Execute
    ark_web_nweb_t* _retval = _struct->get_nweb(_struct, nweb_id);

    // Return type: refptr_same
    return ArkWebNWebCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebDataBase> ArkWebEngineCToCpp::GetDataBase()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_data_base, nullptr);

    // Execute
    ark_web_data_base_t* _retval = _struct->get_data_base(_struct);

    // Return type: refptr_same
    return ArkWebDataBaseCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebWebStorage> ArkWebEngineCToCpp::GetWebStorage()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_web_storage, nullptr);

    // Execute
    ark_web_web_storage_t* _retval = _struct->get_web_storage(_struct);

    // Return type: refptr_same
    return ArkWebWebStorageCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebCookieManager> ArkWebEngineCToCpp::GetCookieManager()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_cookie_manager, nullptr);

    // Execute
    ark_web_cookie_manager_t* _retval = _struct->get_cookie_manager(_struct);

    // Return type: refptr_same
    return ArkWebCookieManagerCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
ArkWebRefPtr<ArkWebDownloadManager> ArkWebEngineCToCpp::GetDownloadManager()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, nullptr);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_download_manager, nullptr);

    // Execute
    ark_web_download_manager_t* _retval = _struct->get_download_manager(_struct);

    // Return type: refptr_same
    return ArkWebDownloadManagerCToCpp::Invert(_retval);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetWebTag(int32_t nweb_id, const char* web_tag)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_web_tag, );

    // Execute
    _struct->set_web_tag(_struct, nweb_id, web_tag);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::InitializeWebEngine(ArkWebRefPtr<ArkWebEngineInitArgs> init_args)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, initialize_web_engine, );

    // Execute
    _struct->initialize_web_engine(_struct, ArkWebEngineInitArgsCppToC::Invert(init_args));
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::PrepareForPageLoad(const ArkWebString& url, bool preconnectable, int32_t num_sockets)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, prepare_for_page_load, );

    // Execute
    _struct->prepare_for_page_load(_struct, &url, preconnectable, num_sockets);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetWebDebuggingAccess(bool isEnableDebug)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_web_debugging_access, );

    // Execute
    _struct->set_web_debugging_access(_struct, isEnableDebug);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::AddIntelligentTrackingPreventionBypassingList(const ArkWebStringVector& hosts)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, add_intelligent_tracking_prevention_bypassing_list, );

    // Execute
    _struct->add_intelligent_tracking_prevention_bypassing_list(_struct, &hosts);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::RemoveIntelligentTrackingPreventionBypassingList(const ArkWebStringVector& hosts)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, remove_intelligent_tracking_prevention_bypassing_list, );

    // Execute
    _struct->remove_intelligent_tracking_prevention_bypassing_list(_struct, &hosts);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::ClearIntelligentTrackingPreventionBypassingList()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_intelligent_tracking_prevention_bypassing_list, );

    // Execute
    _struct->clear_intelligent_tracking_prevention_bypassing_list(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::PauseAllTimers()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, pause_all_timers, );

    // Execute
    _struct->pause_all_timers(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::ResumeAllTimers()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, resume_all_timers, );

    // Execute
    _struct->resume_all_timers(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::PrefetchResource(ArkWebRefPtr<ArkWebEnginePrefetchArgs>& pre_args,
    const ArkWebStringMap& additional_http_headers, const ArkWebString& cache_key, const uint32_t& cache_valid_time)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, prefetch_resource, );

    // Translate param: pre_args; type: refptr_diff_byref
    ark_web_engine_prefetch_args_t* pre_argsStruct = NULL;
    if (pre_args.get()) {
        pre_argsStruct = ArkWebEnginePrefetchArgsCppToC::Invert(pre_args);
    }
    ark_web_engine_prefetch_args_t* pre_argsOrig = pre_argsStruct;

    // Execute
    _struct->prefetch_resource(_struct, &pre_argsStruct, &additional_http_headers, &cache_key, &cache_valid_time);

    // Restore param:pre_args; type: refptr_diff_byref
    if (pre_argsStruct) {
        if (pre_argsStruct != pre_argsOrig) {
            pre_args = ArkWebEnginePrefetchArgsCppToC::Revert(pre_argsStruct);
        }
    } else {
        pre_args = nullptr;
    }
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetRenderProcessMode(int32_t mode)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_render_process_mode, );

    // Execute
    _struct->set_render_process_mode(_struct, mode);
}

ARK_WEB_NO_SANITIZE
int32_t ArkWebEngineCToCpp::GetRenderProcessMode()
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, 0);

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, get_render_process_mode, 0);

    // Execute
    return _struct->get_render_process_mode(_struct);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::ClearPrefetchedResource(const ArkWebStringVector& cache_key_list)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_prefetched_resource, );

    // Execute
    _struct->clear_prefetched_resource(_struct, &cache_key_list);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::WarmupServiceWorker(const ArkWebString& url)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, warmup_service_worker, );

    // Execute
    _struct->warmup_service_worker(_struct, &url);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::SetHostIP(const ArkWebString& hostName, const ArkWebString& address, int32_t aliveTime)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, set_host_ip, );

    // Execute
    _struct->set_host_ip(_struct, &hostName, &address, aliveTime);
}

ARK_WEB_NO_SANITIZE
void ArkWebEngineCToCpp::ClearHostIP(const ArkWebString& hostName)
{
    ARK_WEB_CTOCPP_DV_LOG("capi struct is %{public}ld", (long)this);

    ark_web_engine_t* _struct = GetStruct();
    ARK_WEB_CTOCPP_CHECK_PARAM(_struct, );

    ARK_WEB_CTOCPP_CHECK_FUNC_MEMBER(_struct, clear_host_ip, );

    // Execute
    _struct->clear_host_ip(_struct, &hostName);
}

ArkWebEngineCToCpp::ArkWebEngineCToCpp() {}

ArkWebEngineCToCpp::~ArkWebEngineCToCpp() {}

template<>
ArkWebBridgeType ArkWebCToCppRefCounted<ArkWebEngineCToCpp, ArkWebEngine, ark_web_engine_t>::kBridgeType =
    ARK_WEB_ENGINE;

} // namespace OHOS::ArkWeb
