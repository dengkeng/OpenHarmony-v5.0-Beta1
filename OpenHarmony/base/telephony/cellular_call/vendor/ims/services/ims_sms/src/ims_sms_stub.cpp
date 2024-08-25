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
#include "ims_sms_stub.h"

#include "telephony_errors.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
ImsSmsStub::ImsSmsStub()
{
    InitFuncMap();
}

ImsSmsStub::~ImsSmsStub() {}

void ImsSmsStub::InitFuncMap()
{
    memberFuncMap_[static_cast<uint32_t>(ImsSmsInterfaceCode::IMS_SEND_MESSAGE)] = &ImsSmsStub::OnImsSendMessage;
    memberFuncMap_[static_cast<uint32_t>(ImsSmsInterfaceCode::IMS_SET_SMS_CONFIG)] = &ImsSmsStub::OnImsSetSmsConfig;
    memberFuncMap_[static_cast<uint32_t>(ImsSmsInterfaceCode::IMS_GET_SMS_CONFIG)] = &ImsSmsStub::OnImsGetSmsConfig;
    memberFuncMap_[static_cast<uint32_t>(ImsSmsInterfaceCode::IMS_SMS_REGISTER_CALLBACK)] =
        &ImsSmsStub::OnRegisterSmsCallCallback;
}

int32_t ImsSmsStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    std::u16string descriptor = ImsSmsStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TELEPHONY_LOGE("descriptor checking fail!");
        return TELEPHONY_ERR_DESCRIPTOR_MISMATCH;
    }
    TELEPHONY_LOGI("OnReceived, cmd = %{public}u", code);
    auto itFunction = memberFuncMap_.find(code);
    if (itFunction != memberFuncMap_.end()) {
        auto memberFunc = itFunction->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t ImsSmsStub::OnImsSendMessage(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    ImsMessageInfo sendMessageInfo;
    sendMessageInfo.refId = data.ReadInt64();
    sendMessageInfo.smscPdu = data.ReadString();
    sendMessageInfo.pdu = data.ReadString();
    sendMessageInfo.tech = static_cast<const SmsRadioTechnologyFamily>(data.ReadInt32());
    reply.WriteInt32(ImsSendMessage(slotId, sendMessageInfo));

    return TELEPHONY_SUCCESS;
}

int32_t ImsSmsStub::OnImsSetSmsConfig(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    int32_t imsSmsConfig = data.ReadInt32();
    reply.WriteInt32(ImsSetSmsConfig(slotId, imsSmsConfig));

    return TELEPHONY_SUCCESS;
}

int32_t ImsSmsStub::OnImsGetSmsConfig(MessageParcel &data, MessageParcel &reply)
{
    int32_t slotId = data.ReadInt32();
    reply.WriteInt32(ImsGetSmsConfig(slotId));

    return TELEPHONY_SUCCESS;
}

int32_t ImsSmsStub::OnRegisterSmsCallCallback(MessageParcel &data, MessageParcel &reply)
{
    auto remote = data.ReadRemoteObject();
    int32_t result = TELEPHONY_ERR_LOCAL_PTR_NULL;
    if (remote == nullptr) {
        TELEPHONY_LOGE("ImsSmsCallback is nullptr");
        reply.WriteInt32(result);
        return result;
    }
    result = RegisterImsSmsCallback(iface_cast<ImsSmsCallbackInterface>(remote));
    reply.WriteInt32(result);
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
