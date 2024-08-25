/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef TELEPHONY_IMS_UNIT_TEST_H
#define TELEPHONY_IMS_UNIT_TEST_H

#include <map>

#include "ims_call_interface.h"
#include "ims_call_ipc_interface_code.h"
#include "ims_core_service_interface.h"
#include "ims_sms_interface.h"
#include "ims_sms_ipc_interface_code.h"

#include "singleton.h"

namespace OHOS {
namespace Telephony {
class ImsUnitTest {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    /****************** basic ******************/
    int32_t Dial(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t HangUp(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t RejectWithReason(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t Answer(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t HoldCall(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t UnHoldCall(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SwitchCall(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t CombineConference(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t InviteToConference(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t KickOutFromConference(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t UpdateImsCallMode(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetImsCallsDataRequest(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetLastCallFailReason(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t StartDtmf(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SendDtmf(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t StopDtmf(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t StartRtt(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t StopRtt(const sptr<ImsCallInterface> &imsCallSerivce) const;

    /****************** ims config ******************/
    int32_t SetDomainPreferenceMode(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetDomainPreferenceMode(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetImsSwitchStatus(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetImsSwitchStatus(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetImsConfigString(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetImsConfigInt(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetImsConfig(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetImsFeatureValue(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetImsFeatureValue(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetMute(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetMute(const sptr<ImsCallInterface> &imsCallSerivce) const;

    /****************** video call ******************/
    int32_t CtrlCamera(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetPreviewWindow(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetDisplayWindow(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetCameraZoom(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetPauseImage(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetDeviceDirection(const sptr<ImsCallInterface> &imsCallSerivce) const;

    /****************** supplement ******************/
    int32_t GetClip(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetClir(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetClir(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetCallTransfer(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetCallTransfer(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetCallRestriction(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetCallRestriction(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t SetCallWaiting(const sptr<ImsCallInterface> &imsCallSerivce) const;
    int32_t GetCallWaiting(const sptr<ImsCallInterface> &imsCallSerivce) const;

    // sms & core_service
    int32_t SetSmsConfig(const sptr<ImsSmsInterface> &imsSmsSerivce) const;
    int32_t GetSmsConfig(const sptr<ImsSmsInterface> &imsSmsSerivce) const;
    int32_t SendMessage(const sptr<ImsSmsInterface> &imsSmsSerivce) const;
    int32_t GetImsRegistrationStatus(const sptr<ImsCoreServiceInterface> &imsCoreSerivce) const;

    int32_t ImsCallTest() const;
    int32_t ImsSmsTest() const;
    int32_t ImsCoreServiceTest() const;

private:
    /**
     * InitBasicFuncMap
     */
    void InitBasicFuncMap();

    /**
     * InitConfigFuncMap
     */
    void InitConfigFuncMap();

    /**
     * InitVideoCallFuncMap
     */
    void InitVideoCallFuncMap();

    /**
     * InitSupplementFuncMap
     */
    void InitSupplementFuncMap();

    /**
     * InitSmsFuncMap
     */
    void InitSmsFuncMap();

    /**
     * InitCoreServiceFuncMap
     */
    void InitCoreServiceFuncMap();

private:
    using RequestCallFuncType = int32_t (ImsUnitTest::*)(const sptr<ImsCallInterface> &imsCallSerivce) const;
    using RequestSmsFuncType = int32_t (ImsUnitTest::*)(const sptr<ImsSmsInterface> &imsCallSerivce) const;
    using RequestCoreServiceFuncType = int32_t (ImsUnitTest::*)(
        const sptr<ImsCoreServiceInterface> &imsCallSerivce) const;
    std::map<int32_t, RequestCallFuncType> requestCallFuncMap_;
    std::map<int32_t, RequestSmsFuncType> requestSmsFuncMap_;
    std::map<int32_t, RequestCoreServiceFuncType> requestCoreServiceFuncMap_;
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_UNIT_TEST_H
