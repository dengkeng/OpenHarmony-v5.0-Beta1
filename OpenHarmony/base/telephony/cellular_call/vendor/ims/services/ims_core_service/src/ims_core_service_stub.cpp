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
#include "ims_core_service_stub.h"

#include "telephony_errors.h"
#include "telephony_permission.h"

namespace OHOS {
namespace Telephony {
ImsCoreServiceStub::ImsCoreServiceStub()
{
    InitMemberFuncMap();
}

ImsCoreServiceStub::~ImsCoreServiceStub() {}

void ImsCoreServiceStub::InitMemberFuncMap()
{
    memberFuncMap_[ImsCoreServiceInterfaceCode::IMS_GET_REGISTRATION_STATUS] =
        &ImsCoreServiceStub::OnGetImsRegistrationStatus;

    /* ------------ callback ------------- */
    memberFuncMap_[ImsCoreServiceInterfaceCode::IMS_REGISTER_CALLBACK] =
        &ImsCoreServiceStub::OnRegisterImsCoreServiceCallback;
    memberFuncMap_[ImsCoreServiceInterfaceCode::IMS_GET_PROXY_OBJECT_PTR] = &ImsCoreServiceStub::OnGetProxyObjectPtr;
}

int32_t ImsCoreServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!TelephonyPermission::CheckPermission(Permission::CONNECT_IMS_SERVICE)) {
        TELEPHONY_LOGE("Permission denied!");
        return TELEPHONY_ERR_PERMISSION_ERR;
    }
    std::u16string serviceDescriptor = ImsCoreServiceStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (serviceDescriptor != remoteDescriptor) {
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

int32_t ImsCoreServiceStub::OnGetImsRegistrationStatus(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceStub::OnGetImsRegistrationStatus enter");
    int32_t slotId = data.ReadInt32();
    reply.WriteInt32(GetImsRegistrationStatus(slotId));
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceStub::OnRegisterImsCoreServiceCallback(MessageParcel &data, MessageParcel &reply)
{
    TELEPHONY_LOGI("ImsCoreServiceStub::OnRegisterImsCoreServiceCallback enter");

    int32_t result = TELEPHONY_ERR_LOCAL_PTR_NULL;
    auto remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        TELEPHONY_LOGE("ImsCoreServiceStub::OnRegisterImsCoreServiceCallback return remote is nullptr");
        reply.WriteInt32(result);
        return result;
    }
    result = RegisterImsCoreServiceCallback(iface_cast<ImsCoreServiceCallbackInterface>(remote));
    reply.WriteInt32(result);
    return TELEPHONY_SUCCESS;
}

int32_t ImsCoreServiceStub::OnGetProxyObjectPtr(MessageParcel &data, MessageParcel &reply)
{
    ImsServiceProxyType proxyType = static_cast<ImsServiceProxyType>(data.ReadInt32());
    sptr<IRemoteObject> object = GetProxyObjectPtr(proxyType);
    if (!reply.WriteRemoteObject(object)) {
        TELEPHONY_LOGE("OnGetProxyObjectPtr fail to write parcel");
        return TELEPHONY_ERR_WRITE_REPLY_FAIL;
    }
    return TELEPHONY_SUCCESS;
}
} // namespace Telephony
} // namespace OHOS
