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

#include "ohos_adapter/cpptoc/ark_ohos_adapter_helper_cpptoc.h"

#include "ohos_adapter/cpptoc/ark_aafwk_app_mgr_client_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_access_token_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_audio_capturer_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_audio_renderer_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_audio_system_manager_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_battery_mgr_client_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_camera_manager_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_cert_manager_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_datashare_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_date_time_format_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_display_manager_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_enterprise_device_management_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_event_handler_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_flowbuffer_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_hi_sys_event_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_hi_trace_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_iconsumer_surface_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_imfadapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_keystore_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_media_avsession_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_media_codec_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_media_codec_decoder_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_media_codec_list_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_mmiadapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_native_image_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_net_connect_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_net_proxy_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_ohos_init_web_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_ohos_resource_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_ohos_web_data_base_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_ohos_web_permission_data_base_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_paste_board_client_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_player_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_power_mgr_client_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_print_manager_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_screen_capture_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_soc_perf_client_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_system_properties_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_vsync_adapter_cpptoc.h"
#include "ohos_adapter/cpptoc/ark_window_adapter_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

ark_ohos_adapter_helper_t* ark_ohos_adapter_helper_get_instance()
{
    // Execute
    ArkWebRefPtr<ArkOhosAdapterHelper> _retval = ArkOhosAdapterHelper::GetInstance();

    // Return type: refptr_same
    return ArkOhosAdapterHelperCppToC::Invert(_retval);
}

namespace {

ark_aafwk_app_mgr_client_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_aafwk_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkAafwkAppMgrClientAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateAafwkAdapter();

    // Return type: refptr_same
    return ArkAafwkAppMgrClientAdapterCppToC::Invert(_retval);
}

ark_power_mgr_client_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_power_mgr_client_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkPowerMgrClientAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreatePowerMgrClientAdapter();

    // Return type: refptr_same
    return ArkPowerMgrClientAdapterCppToC::Invert(_retval);
}

ark_display_manager_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_display_mgr_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkDisplayManagerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateDisplayMgrAdapter();

    // Return type: refptr_same
    return ArkDisplayManagerAdapterCppToC::Invert(_retval);
}

ark_battery_mgr_client_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_battery_client_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkBatteryMgrClientAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateBatteryClientAdapter();

    // Return type: refptr_same
    return ArkBatteryMgrClientAdapterCppToC::Invert(_retval);
}

ark_net_connect_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_net_connect_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkNetConnectAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateNetConnectAdapter();

    // Return type: refptr_same
    return ArkNetConnectAdapterCppToC::Invert(_retval);
}

ark_ohos_web_data_base_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_ohos_web_data_base_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkOhosWebDataBaseAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->GetOhosWebDataBaseAdapterInstance();

    // Return type: refptr_same
    return ArkOhosWebDataBaseAdapterCppToC::Invert(_retval);
}

ark_paste_board_client_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_paste_board(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkPasteBoardClientAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetPasteBoard();

    // Return type: refptr_same
    return ArkPasteBoardClientAdapterCppToC::Invert(_retval);
}

ark_audio_renderer_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_audio_renderer_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkAudioRendererAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateAudioRendererAdapter();

    // Return type: refptr_same
    return ArkAudioRendererAdapterCppToC::Invert(_retval);
}

ark_audio_capturer_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_audio_capturer_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkAudioCapturerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateAudioCapturerAdapter();

    // Return type: refptr_same
    return ArkAudioCapturerAdapterCppToC::Invert(_retval);
}

ark_audio_system_manager_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_audio_system_manager(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkAudioSystemManagerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetAudioSystemManager();

    // Return type: refptr_same
    return ArkAudioSystemManagerAdapterCppToC::Invert(_retval);
}

ark_ohos_web_permission_data_base_adapter_t* ARK_WEB_CALLBACK
ark_ohos_adapter_helper_get_web_permission_data_base_instance(struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkOhosWebPermissionDataBaseAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->GetWebPermissionDataBaseInstance();

    // Return type: refptr_same
    return ArkOhosWebPermissionDataBaseAdapterCppToC::Invert(_retval);
}

ark_mmiadapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_mmiadapter(struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkMMIAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateMMIAdapter();

    // Return type: refptr_same
    return ArkMMIAdapterCppToC::Invert(_retval);
}

ark_soc_perf_client_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_soc_perf_client_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkSocPerfClientAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateSocPerfClientAdapter();

    // Return type: refptr_same
    return ArkSocPerfClientAdapterCppToC::Invert(_retval);
}

ark_ohos_resource_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_resource_adapter(
    struct _ark_ohos_adapter_helper_t* self, const ArkWebString* hapPath)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    ARK_WEB_CPPTOC_CHECK_PARAM(hapPath, NULL);

    // Execute
    ArkWebRefPtr<ArkOhosResourceAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetResourceAdapter(*hapPath);

    // Return type: refptr_same
    return ArkOhosResourceAdapterCppToC::Invert(_retval);
}

ark_system_properties_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_system_properties_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkSystemPropertiesAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->GetSystemPropertiesInstance();

    // Return type: refptr_same
    return ArkSystemPropertiesAdapterCppToC::Invert(_retval);
}

ark_vsync_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_vsync_adapter(struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkVSyncAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetVSyncAdapter();

    // Return type: refptr_same
    return ArkVSyncAdapterCppToC::Invert(_retval);
}

ark_ohos_init_web_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_init_web_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkOhosInitWebAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetInitWebAdapter();

    // Return type: refptr_same
    return ArkOhosInitWebAdapterCppToC::Invert(_retval);
}

ark_keystore_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_keystore_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkKeystoreAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetKeystoreAdapterInstance();

    // Return type: refptr_same
    return ArkKeystoreAdapterCppToC::Invert(_retval);
}

ark_enterprise_device_management_adapter_t* ARK_WEB_CALLBACK
ark_ohos_adapter_helper_get_enterprise_device_management_instance(struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkEnterpriseDeviceManagementAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->GetEnterpriseDeviceManagementInstance();

    // Return type: refptr_same
    return ArkEnterpriseDeviceManagementAdapterCppToC::Invert(_retval);
}

ark_datashare_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_datashare_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkDatashareAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetDatashareInstance();

    // Return type: refptr_same
    return ArkDatashareAdapterCppToC::Invert(_retval);
}

ark_imfadapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_imfadapter(struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkIMFAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateIMFAdapter();

    // Return type: refptr_same
    return ArkIMFAdapterCppToC::Invert(_retval);
}

ark_cert_manager_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_root_cert_data_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkCertManagerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetRootCertDataAdapter();

    // Return type: refptr_same
    return ArkCertManagerAdapterCppToC::Invert(_retval);
}

ark_access_token_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_access_token_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkAccessTokenAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->GetAccessTokenAdapterInstance();

    // Return type: refptr_same
    return ArkAccessTokenAdapterCppToC::Invert(_retval);
}

ark_event_handler_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_event_handler_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkEventHandlerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetEventHandlerAdapter();

    // Return type: refptr_same
    return ArkEventHandlerAdapterCppToC::Invert(_retval);
}

ark_print_manager_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_print_manager_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkPrintManagerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetPrintManagerInstance();

    // Return type: refptr_same
    return ArkPrintManagerAdapterCppToC::Invert(_retval);
}

ark_iconsumer_surface_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_consumer_surface_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkIConsumerSurfaceAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateConsumerSurfaceAdapter();

    // Return type: refptr_same
    return ArkIConsumerSurfaceAdapterCppToC::Invert(_retval);
}

ark_player_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_player_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkPlayerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreatePlayerAdapter();

    // Return type: refptr_same
    return ArkPlayerAdapterCppToC::Invert(_retval);
}

ark_window_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_window_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkWindowAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetWindowAdapterInstance();

    // Return type: refptr_same
    return ArkWindowAdapterCppToC::Invert(_retval);
}

ark_hi_sys_event_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_hi_sys_event_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkHiSysEventAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetHiSysEventAdapterInstance();

    // Return type: refptr_same
    return ArkHiSysEventAdapterCppToC::Invert(_retval);
}

ark_hi_trace_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_hi_trace_adapter_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkHiTraceAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetHiTraceAdapterInstance();

    // Return type: refptr_same
    return ArkHiTraceAdapterCppToC::Invert(_retval);
}

ark_net_proxy_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_net_proxy_instance(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkNetProxyAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetNetProxyInstance();

    // Return type: refptr_same
    return ArkNetProxyAdapterCppToC::Invert(_retval);
}

ark_camera_manager_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_camera_manager_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkCameraManagerAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetCameraManagerAdapter();

    // Return type: refptr_same
    return ArkCameraManagerAdapterCppToC::Invert(_retval);
}

ark_screen_capture_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_screen_capture_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkScreenCaptureAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateScreenCaptureAdapter();

    // Return type: refptr_same
    return ArkScreenCaptureAdapterCppToC::Invert(_retval);
}

ark_date_time_format_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_date_time_format_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkDateTimeFormatAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateDateTimeFormatAdapter();

    // Return type: refptr_same
    return ArkDateTimeFormatAdapterCppToC::Invert(_retval);
}

ark_media_codec_decoder_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_media_codec_decoder_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkMediaCodecDecoderAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateMediaCodecDecoderAdapter();

    // Return type: refptr_same
    return ArkMediaCodecDecoderAdapterCppToC::Invert(_retval);
}

ark_native_image_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_native_image_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkNativeImageAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateNativeImageAdapter();

    // Return type: refptr_same
    return ArkNativeImageAdapterCppToC::Invert(_retval);
}

ark_media_codec_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_media_codec_encoder_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkMediaCodecAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateMediaCodecEncoderAdapter();

    // Return type: refptr_same
    return ArkMediaCodecAdapterCppToC::Invert(_retval);
}

ark_media_codec_list_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_get_media_codec_list_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkMediaCodecListAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->GetMediaCodecListAdapter();

    // Return type: refptr_same
    return ArkMediaCodecListAdapterCppToC::Invert(_retval);
}

ark_flowbuffer_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_flowbuffer_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkFlowbufferAdapter> _retval = ArkOhosAdapterHelperCppToC::Get(self)->CreateFlowbufferAdapter();

    // Return type: refptr_same
    return ArkFlowbufferAdapterCppToC::Invert(_retval);
}

ark_media_avsession_adapter_t* ARK_WEB_CALLBACK ark_ohos_adapter_helper_create_media_avsession_adapter(
    struct _ark_ohos_adapter_helper_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, NULL);

    // Execute
    ArkWebRefPtr<ArkMediaAVSessionAdapter> _retval =
        ArkOhosAdapterHelperCppToC::Get(self)->CreateMediaAVSessionAdapter();

    // Return type: refptr_same
    return ArkMediaAVSessionAdapterCppToC::Invert(_retval);
}

} // namespace

ArkOhosAdapterHelperCppToC::ArkOhosAdapterHelperCppToC()
{
    GetStruct()->create_aafwk_adapter = ark_ohos_adapter_helper_create_aafwk_adapter;
    GetStruct()->create_power_mgr_client_adapter = ark_ohos_adapter_helper_create_power_mgr_client_adapter;
    GetStruct()->create_display_mgr_adapter = ark_ohos_adapter_helper_create_display_mgr_adapter;
    GetStruct()->create_battery_client_adapter = ark_ohos_adapter_helper_create_battery_client_adapter;
    GetStruct()->create_net_connect_adapter = ark_ohos_adapter_helper_create_net_connect_adapter;
    GetStruct()->get_ohos_web_data_base_adapter_instance =
        ark_ohos_adapter_helper_get_ohos_web_data_base_adapter_instance;
    GetStruct()->get_paste_board = ark_ohos_adapter_helper_get_paste_board;
    GetStruct()->create_audio_renderer_adapter = ark_ohos_adapter_helper_create_audio_renderer_adapter;
    GetStruct()->create_audio_capturer_adapter = ark_ohos_adapter_helper_create_audio_capturer_adapter;
    GetStruct()->get_audio_system_manager = ark_ohos_adapter_helper_get_audio_system_manager;
    GetStruct()->get_web_permission_data_base_instance = ark_ohos_adapter_helper_get_web_permission_data_base_instance;
    GetStruct()->create_mmiadapter = ark_ohos_adapter_helper_create_mmiadapter;
    GetStruct()->create_soc_perf_client_adapter = ark_ohos_adapter_helper_create_soc_perf_client_adapter;
    GetStruct()->get_resource_adapter = ark_ohos_adapter_helper_get_resource_adapter;
    GetStruct()->get_system_properties_instance = ark_ohos_adapter_helper_get_system_properties_instance;
    GetStruct()->get_vsync_adapter = ark_ohos_adapter_helper_get_vsync_adapter;
    GetStruct()->get_init_web_adapter = ark_ohos_adapter_helper_get_init_web_adapter;
    GetStruct()->get_keystore_adapter_instance = ark_ohos_adapter_helper_get_keystore_adapter_instance;
    GetStruct()->get_enterprise_device_management_instance =
        ark_ohos_adapter_helper_get_enterprise_device_management_instance;
    GetStruct()->get_datashare_instance = ark_ohos_adapter_helper_get_datashare_instance;
    GetStruct()->create_imfadapter = ark_ohos_adapter_helper_create_imfadapter;
    GetStruct()->get_root_cert_data_adapter = ark_ohos_adapter_helper_get_root_cert_data_adapter;
    GetStruct()->get_access_token_adapter_instance = ark_ohos_adapter_helper_get_access_token_adapter_instance;
    GetStruct()->get_event_handler_adapter = ark_ohos_adapter_helper_get_event_handler_adapter;
    GetStruct()->get_print_manager_instance = ark_ohos_adapter_helper_get_print_manager_instance;
    GetStruct()->create_consumer_surface_adapter = ark_ohos_adapter_helper_create_consumer_surface_adapter;
    GetStruct()->create_player_adapter = ark_ohos_adapter_helper_create_player_adapter;
    GetStruct()->get_window_adapter_instance = ark_ohos_adapter_helper_get_window_adapter_instance;
    GetStruct()->get_hi_sys_event_adapter_instance = ark_ohos_adapter_helper_get_hi_sys_event_adapter_instance;
    GetStruct()->get_hi_trace_adapter_instance = ark_ohos_adapter_helper_get_hi_trace_adapter_instance;
    GetStruct()->get_net_proxy_instance = ark_ohos_adapter_helper_get_net_proxy_instance;
    GetStruct()->get_camera_manager_adapter = ark_ohos_adapter_helper_get_camera_manager_adapter;
    GetStruct()->create_screen_capture_adapter = ark_ohos_adapter_helper_create_screen_capture_adapter;
    GetStruct()->create_date_time_format_adapter = ark_ohos_adapter_helper_create_date_time_format_adapter;
    GetStruct()->create_media_codec_decoder_adapter = ark_ohos_adapter_helper_create_media_codec_decoder_adapter;
    GetStruct()->create_native_image_adapter = ark_ohos_adapter_helper_create_native_image_adapter;
    GetStruct()->create_media_codec_encoder_adapter = ark_ohos_adapter_helper_create_media_codec_encoder_adapter;
    GetStruct()->get_media_codec_list_adapter = ark_ohos_adapter_helper_get_media_codec_list_adapter;
    GetStruct()->create_flowbuffer_adapter = ark_ohos_adapter_helper_create_flowbuffer_adapter;
    GetStruct()->create_media_avsession_adapter = ark_ohos_adapter_helper_create_media_avsession_adapter;
}

ArkOhosAdapterHelperCppToC::~ArkOhosAdapterHelperCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkOhosAdapterHelperCppToC, ArkOhosAdapterHelper, ark_ohos_adapter_helper_t>::kBridgeType =
        ARK_OHOS_ADAPTER_HELPER;

} // namespace OHOS::ArkWeb

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

ARK_WEB_EXPORT ark_ohos_adapter_helper_t* ark_ohos_adapter_helper_get_instance_static()
{
    ARK_WEB_CPPTOC_DV_LOG();

    return OHOS::ArkWeb::ark_ohos_adapter_helper_get_instance();
}

#ifdef __cplusplus
}
#endif // __cplusplus
