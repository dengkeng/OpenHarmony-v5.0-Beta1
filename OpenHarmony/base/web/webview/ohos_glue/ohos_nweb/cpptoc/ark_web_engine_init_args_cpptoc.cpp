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

#include "ohos_nweb/cpptoc/ark_web_engine_init_args_cpptoc.h"

#include "base/cpptoc/ark_web_cpptoc_macros.h"

namespace OHOS::ArkWeb {

namespace {

bool ARK_WEB_CALLBACK ark_web_engine_init_args_get_is_popup(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetIsPopup();
}

ArkWebString ARK_WEB_CALLBACK ark_web_engine_init_args_get_dump_path(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_default);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetDumpPath();
}

ArkWebStringList ARK_WEB_CALLBACK ark_web_engine_init_args_get_args_to_add(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_list_default);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetArgsToAdd();
}

ArkWebStringList ARK_WEB_CALLBACK ark_web_engine_init_args_get_args_to_delete(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, ark_web_string_list_default);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetArgsToDelete();
}

bool ARK_WEB_CALLBACK ark_web_engine_init_args_get_is_frame_info_dump(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetIsFrameInfoDump();
}

bool ARK_WEB_CALLBACK ark_web_engine_init_args_get_is_enhance_surface(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetIsEnhanceSurface();
}

bool ARK_WEB_CALLBACK ark_web_engine_init_args_get_is_multi_renderer_process(struct _ark_web_engine_init_args_t* self)
{
    ARK_WEB_CPPTOC_DV_LOG("capi struct is %{public}ld", (long)self);

    ARK_WEB_CPPTOC_CHECK_PARAM(self, false);

    // Execute
    return ArkWebEngineInitArgsCppToC::Get(self)->GetIsMultiRendererProcess();
}

} // namespace

ArkWebEngineInitArgsCppToC::ArkWebEngineInitArgsCppToC()
{
    GetStruct()->get_is_popup = ark_web_engine_init_args_get_is_popup;
    GetStruct()->get_dump_path = ark_web_engine_init_args_get_dump_path;
    GetStruct()->get_args_to_add = ark_web_engine_init_args_get_args_to_add;
    GetStruct()->get_args_to_delete = ark_web_engine_init_args_get_args_to_delete;
    GetStruct()->get_is_frame_info_dump = ark_web_engine_init_args_get_is_frame_info_dump;
    GetStruct()->get_is_enhance_surface = ark_web_engine_init_args_get_is_enhance_surface;
    GetStruct()->get_is_multi_renderer_process = ark_web_engine_init_args_get_is_multi_renderer_process;
}

ArkWebEngineInitArgsCppToC::~ArkWebEngineInitArgsCppToC() {}

template<>
ArkWebBridgeType
    ArkWebCppToCRefCounted<ArkWebEngineInitArgsCppToC, ArkWebEngineInitArgs, ark_web_engine_init_args_t>::kBridgeType =
        ARK_WEB_ENGINE_INIT_ARGS;

} // namespace OHOS::ArkWeb
