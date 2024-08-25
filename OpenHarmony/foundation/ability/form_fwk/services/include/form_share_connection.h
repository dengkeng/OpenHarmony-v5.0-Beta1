/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H

#include "event_handler.h"
#include "form_ability_connection.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using WantParams = OHOS::AAFwk::WantParams;
using Want = OHOS::AAFwk::Want;

/**
 * @class FormShareConnection
 * Form share connection stub.
 */
class FormShareConnection : public FormAbilityConnection {
public:
    FormShareConnection(int64_t formId, const std::string &bundleName, const std::string &abilityName,
        const std::string &deviceId, int64_t formShareRequestCode);

    virtual ~FormShareConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     * @param element service ability's ElementName.
     * @param remoteObject The session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;

private:
    int64_t formId_ {-1};
    std::string remoteDeviceId_ {""};
    int64_t formShareRequestCode_ {0};
    DISALLOW_COPY_AND_MOVE(FormShareConnection);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H
