/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef IMS_CORE_SERVICE_STUB_H
#define IMS_CORE_SERVICE_STUB_H

#include <map>

#include "ims_core_service_interface.h"
#include "ims_core_service_ipc_interface_code.h"
#include "iremote_stub.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsCoreServiceStub : public IRemoteStub<ImsCoreServiceInterface> {
public:
    /**
     * ImsCoreServiceStub Constructor
     */
    ImsCoreServiceStub();

    /**
     * ImsCoreServiceStub Deconstructor
     */
    virtual ~ImsCoreServiceStub();

    /**
     * OnRemoteRequest
     *
     * @param code
     * @param data
     * @param reply
     * @param option
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    using ImsServiceFunc = int32_t (ImsCoreServiceStub::*)(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetImsRegistrationStatus(MessageParcel &data, MessageParcel &reply);
    int32_t OnRegisterImsCoreServiceCallback(MessageParcel &data, MessageParcel &reply);
    int32_t OnGetProxyObjectPtr(MessageParcel &data, MessageParcel &reply);
    void InitMemberFuncMap();

private:
    std::unordered_map<uint32_t, ImsServiceFunc> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_CORE_SERVICE_STUB_H
