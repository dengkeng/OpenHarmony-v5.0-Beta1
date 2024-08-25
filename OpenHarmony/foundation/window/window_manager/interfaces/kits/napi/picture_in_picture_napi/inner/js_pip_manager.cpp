/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "js_pip_manager.h"
#include "window_manager_hilog.h"
#include "picture_in_picture_manager.h"
#include "xcomponent_controller.h"

namespace OHOS {
namespace Rosen {
using namespace AbilityRuntime;
using namespace Ace;
namespace {
    constexpr int32_t NUMBER_ONE = 1;
}

napi_value NapiGetUndefined(napi_env env)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value NapiThrowInvalidParam(napi_env env, std::string msg = "")
{
    napi_throw(env, AbilityRuntime::CreateJsError(env, static_cast<int32_t>(WmErrorCode::WM_ERROR_INVALID_PARAM), msg));
    return NapiGetUndefined(env);
}

JsPipManager::JsPipManager()
{
}

JsPipManager::~JsPipManager()
{
}

void JsPipManager::Finalizer(napi_env env, void* data, void* hint)
{
    TLOGD(WmsLogTag::WMS_PIP, "[NAPI]JsPipManager::Finalizer");
    std::unique_ptr<JsPipManager>(static_cast<JsPipManager*>(data));
}

napi_value JsPipManager::InitXComponentController(napi_env env, napi_callback_info info)
{
    JsPipManager* me = CheckParamsAndGetThis<JsPipManager>(env, info);
    return (me != nullptr) ? me->OnInitXComponentController(env, info) : nullptr;
}

napi_value JsPipManager::OnInitXComponentController(napi_env env, napi_callback_info info)
{
    TLOGD(WmsLogTag::WMS_PIP, "[NAPI]JsPipManager::OnInitXComponentController");
    size_t argc = 4;
    napi_value argv[4] = {nullptr};
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < NUMBER_ONE) {
        TLOGE(WmsLogTag::WMS_PIP, "[NAPI]Argc count is invalid: %{public}zu", argc);
        return NapiThrowInvalidParam(env);
    }
    napi_value xComponentController = argv[0];
    std::shared_ptr<XComponentController> xComponentControllerResult =
        XComponentController::GetXComponentControllerFromNapiValue(xComponentController);
    sptr<Window> pipWindow = Window::Find(PIP_WINDOW_NAME);
    if (!pipWindow) {
        TLOGE(WmsLogTag::WMS_PIP, "[NAPI]Failed to find pip window");
        return NapiGetUndefined(env);
    }
    int32_t windowId = static_cast<int32_t>(pipWindow->GetWindowId());
    sptr<PictureInPictureController> pipController = PictureInPictureManager::GetPipControllerInfo(windowId);
    if (pipController == nullptr) {
        TLOGE(WmsLogTag::WMS_PIP, "[NAPI]Failed to get pictureInPictureController");
        return NapiGetUndefined(env);
    }
    TLOGI(WmsLogTag::WMS_PIP, "[NAPI]set xComponentController to window: %{public}u", windowId);
    WMError errCode = pipController->SetXComponentController(xComponentControllerResult);
    if (errCode != WMError::WM_OK) {
        TLOGE(WmsLogTag::WMS_PIP, "[NAPI]Failed to set xComponentController");
    }
    return NapiGetUndefined(env);
}

napi_value JsPipManagerInit(napi_env env, napi_value exportObj)
{
    TLOGD(WmsLogTag::WMS_PIP, "[NAPI]JsPipManager::JsPipManagerInit");
    if (env == nullptr || exportObj == nullptr) {
        TLOGE(WmsLogTag::WMS_PIP, "JsPipManagerInit failed, env or exportObj is null");
        return nullptr;
    }
    std::unique_ptr<JsPipManager> jsPipManager = std::make_unique<JsPipManager>();
    napi_wrap(env, exportObj, jsPipManager.release(), JsPipManager::Finalizer, nullptr, nullptr);
    const char* moduleName = "JsPipManager";
    BindNativeFunction(env, exportObj, "initXComponentController", moduleName, JsPipManager::InitXComponentController);
    return NapiGetUndefined(env);
}
} // namespace Rosen
} // namespace OHOS

