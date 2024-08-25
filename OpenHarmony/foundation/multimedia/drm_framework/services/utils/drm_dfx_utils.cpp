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

#include "drm_dfx_utils.h"
#include "drm_log.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DrmStandard {
std::string __attribute__((visibility("default"))) GetClientBundleName(int32_t uid)
{
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        DRM_ERR_LOG("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        DRM_ERR_LOG("object is NULL.");
        return bundleName;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        DRM_ERR_LOG("bundle manager service is NULL.");
        return bundleName;
    }

    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK) {
        DRM_ERR_LOG("GetBundleNameForUid fail");
        return "";
    }

    DRM_INFO_LOG("BundleName:%{public}s", bundleName.c_str());

    return bundleName;
}
}  // namespace DrmStandard
}  // namespace OHOS