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

#include "ohos_adapter/cpptoc/ark_res_sched_client_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

bool ark_res_sched_client_adapter_report_key_thread(int32_t statusAdapter, pid_t pid, pid_t tid, int32_t roleAdapter)
{
    // Execute
    return ArkResSchedClientAdapter::ReportKeyThread(statusAdapter, pid, tid, roleAdapter);
}

bool ark_res_sched_client_adapter_report_window_status(
    int32_t statusAdapter, pid_t pid, uint32_t windowId, int32_t nwebId)
{
    // Execute
    return ArkResSchedClientAdapter::ReportWindowStatus(statusAdapter, pid, windowId, nwebId);
}

bool ark_res_sched_client_adapter_report_scene(int32_t statusAdapter, int32_t sceneAdapter, int32_t nwebId)
{
    // Execute
    return ArkResSchedClientAdapter::ReportScene(statusAdapter, sceneAdapter, nwebId);
}

bool ark_res_sched_client_adapter_report_audio_data(int32_t statusAdapter, pid_t pid, pid_t tid)
{
    // Execute
    return ArkResSchedClientAdapter::ReportAudioData(statusAdapter, pid, tid);
}

void ark_res_sched_client_adapter_report_window_id(int32_t windowId, int32_t nwebId)
{
    // Execute
    ArkResSchedClientAdapter::ReportWindowId(windowId, nwebId);
}

void ark_res_sched_client_adapter_report_nweb_init(int32_t statusAdapter, int32_t nweb_id)
{
    // Execute
    ArkResSchedClientAdapter::ReportNWebInit(statusAdapter, nweb_id);
}

void ark_res_sched_client_adapter_report_render_process_status(int32_t statusAdapter, pid_t pid)
{
    // Execute
    ArkResSchedClientAdapter::ReportRenderProcessStatus(statusAdapter, pid);
}

bool ark_res_sched_client_adapter_report_screen_capture(int32_t statusAdapter, pid_t pid)
{
    // Execute
    return ArkResSchedClientAdapter::ReportScreenCapture(statusAdapter, pid);
}

bool ark_res_sched_client_adapter_report_video_playing(int32_t statusAdapter, pid_t pid)
{
    // Execute
    return ArkResSchedClientAdapter::ReportVideoPlaying(statusAdapter, pid);
}

void ark_res_sched_client_adapter_report_process_in_use(pid_t pid)
{
    // Execute
    ArkResSchedClientAdapter::ReportProcessInUse(pid);
}

void ark_res_sched_client_adapter_report_site_isolation_mode(bool mode)
{
    // Execute
    ArkResSchedClientAdapter::ReportSiteIsolationMode(mode);
}

ArkResSchedClientAdapterCppToC::ArkResSchedClientAdapterCppToC() {}

ArkResSchedClientAdapterCppToC::~ArkResSchedClientAdapterCppToC() {}

template<>
ArkWebBridgeType ArkWebCppToCRefCounted<ArkResSchedClientAdapterCppToC, ArkResSchedClientAdapter,
    ark_res_sched_client_adapter_t>::kBridgeType = ARK_RES_SCHED_CLIENT_ADAPTER;

} // namespace OHOS::ArkWeb

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_key_thread_static(
    int32_t statusAdapter, pid_t pid, pid_t tid, int32_t roleAdapter)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_key_thread(statusAdapter, pid, tid, roleAdapter);
}

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_window_status_static(
    int32_t statusAdapter, pid_t pid, uint32_t windowId, int32_t nwebId)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_window_status(statusAdapter, pid, windowId, nwebId);
}

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_scene_static(
    int32_t statusAdapter, int32_t sceneAdapter, int32_t nwebId)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_scene(statusAdapter, sceneAdapter, nwebId);
}

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_audio_data_static(int32_t statusAdapter, pid_t pid, pid_t tid)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_audio_data(statusAdapter, pid, tid);
}

ARK_WEB_EXPORT void ark_res_sched_client_adapter_report_window_id_static(int32_t windowId, int32_t nwebId)
{
    ARK_WEB_CPPTOC_DV_LOG();

    OHOS::ArkWeb::ark_res_sched_client_adapter_report_window_id(windowId, nwebId);
}

ARK_WEB_EXPORT void ark_res_sched_client_adapter_report_nweb_init_static(int32_t statusAdapter, int32_t nweb_id)
{
    ARK_WEB_CPPTOC_DV_LOG();

    OHOS::ArkWeb::ark_res_sched_client_adapter_report_nweb_init(statusAdapter, nweb_id);
}

ARK_WEB_EXPORT void ark_res_sched_client_adapter_report_render_process_status_static(int32_t statusAdapter, pid_t pid)
{
    ARK_WEB_CPPTOC_DV_LOG();

    OHOS::ArkWeb::ark_res_sched_client_adapter_report_render_process_status(statusAdapter, pid);
}

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_screen_capture_static(int32_t statusAdapter, pid_t pid)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_screen_capture(statusAdapter, pid);
}

ARK_WEB_EXPORT bool ark_res_sched_client_adapter_report_video_playing_static(int32_t statusAdapter, pid_t pid)
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_res_sched_client_adapter_report_video_playing(statusAdapter, pid);
}

ARK_WEB_EXPORT void ark_res_sched_client_adapter_report_process_in_use_static(pid_t pid)
{
    ARK_WEB_CPPTOC_DV_LOG();

    OHOS::ArkWeb::ark_res_sched_client_adapter_report_process_in_use(pid);
}

ARK_WEB_EXPORT void ark_res_sched_client_adapter_report_site_isolation_mode_static(bool mode)
{
    ARK_WEB_CPPTOC_DV_LOG();

    OHOS::ArkWeb::ark_res_sched_client_adapter_report_site_isolation_mode(mode);
}
#ifdef __cplusplus
}
#endif // __cplusplus
