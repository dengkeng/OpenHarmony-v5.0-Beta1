/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef IMS_SMS_STUB_H
#define IMS_SMS_STUB_H

#include <unordered_map>

#include "ims_sms_interface.h"
#include "ims_sms_ipc_interface_code.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Telephony {
class ImsSmsStub : public IRemoteStub<ImsSmsInterface> {
public:
    /**
     * ImsCoreServiceStub Constructor
     */
    ImsSmsStub();

    /**
     * ImsCoreServiceStub Deconstructor
     */
    virtual ~ImsSmsStub();

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
    using ImsSmsFunc = int32_t (ImsSmsStub::*)(MessageParcel &data, MessageParcel &reply);
    int32_t OnImsSendMessage(MessageParcel &data, MessageParcel &reply);
    int32_t OnImsSetSmsConfig(MessageParcel &data, MessageParcel &reply);
    int32_t OnImsGetSmsConfig(MessageParcel &data, MessageParcel &reply);
    int32_t OnRegisterSmsCallCallback(MessageParcel &data, MessageParcel &reply);
    void InitFuncMap();

private:
    std::unordered_map<uint32_t, ImsSmsFunc> memberFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_SMS_STUB_H
