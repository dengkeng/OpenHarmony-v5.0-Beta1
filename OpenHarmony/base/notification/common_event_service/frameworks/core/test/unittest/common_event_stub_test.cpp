/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "common_event.h"
#include "common_event_death_recipient.h"
#include "common_event_stub.h"
#include "common_event_proxy.h"
#include "common_event_data.h"
#include "common_event_subscriber.h"
#include "event_receive_proxy.h"
#include "common_event_publish_info.h"
#include "matching_skills.h"

#include "event_log_wrapper.h"
#include "string_ex.h"
#include "ces_inner_error_code.h"

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::EventFwk;

namespace {
    const std::string EVENT = "com.ces.test.event";
    const std::string PERMISSION = "com.ces.test.permission";
}

class CommonEventStubTest : public CommonEventSubscriber, public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    virtual void OnReceiveEvent(const CommonEventData &data)
    {}
};

namespace OHOS {
class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject(u"mock_i_remote_object") {}

    ~MockIRemoteObject() {}

    int32_t GetObjectRefCount() override
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    bool IsProxyObject() const override
    {
        return true;
    }

    bool CheckObjectLegality() const override
    {
        return true;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return true;
    }

    bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    sptr<IRemoteBroker> AsInterface() override
    {
        return nullptr;
    }

    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }

    std::u16string GetObjectDescriptor() const
    {
        std::u16string descriptor = std::u16string();
        return descriptor;
    }
};
}

void CommonEventStubTest::SetUpTestCase()
{}

void CommonEventStubTest::TearDownTestCase()
{}

void CommonEventStubTest::SetUp()
{}

void CommonEventStubTest::TearDown()
{}

/*
 * tc.number: OnRemoteRequest_001
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    const uint32_t code = -1;
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_TRANSACTION_FAILED, result);
}

/*
 * tc.number: OnRemoteRequest_002
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventPublishInfo publishInfo;
    CommonEventStub commonEventStub;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    dataParcel.WriteParcelable(&event);
    dataParcel.WriteParcelable(&publishInfo);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_003
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventPublishInfo publishInfo;
    CommonEventStub commonEventStub;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    dataParcel.WriteBool(true);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/*
 * tc.number: OnRemoteRequest_004
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_004, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT2);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventPublishInfo publishInfo;
    CommonEventStub commonEventStub;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    dataParcel.WriteParcelable(&event);
    dataParcel.WriteParcelable(&publishInfo);
    dataParcel.WriteBool(true);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_005
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_005, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_PUBLISH_COMMON_EVENT2);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventPublishInfo publishInfo;
    CommonEventStub commonEventStub;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
}

/*
 * tc.number: OnRemoteRequest_006
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_006, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_FINISH_RECEIVER);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    dataParcel.WriteBool(false);
    
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
}

/*
 * tc.number: OnRemoteRequest_007
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_007, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/*
 * tc.number: OnRemoteRequest_008
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_008, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    dataParcel.WriteParcelable(&publishInfo);
    dataParcel.WriteBool(true);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::Notification::ERR_NOTIFICATION_CES_COMMON_PARAM_INVALID, result);
}

/*
 * tc.number: OnRemoteRequest_009
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_009, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_FREEZE);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    reply.WriteBool(false);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_010
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_010, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_FREEZE);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_011
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_011, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_UNFREEZE);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int32_t uid = -1;
    bool ret = commonEvent.Unfreeze(uid);
    reply.WriteBool(ret);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_012
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_012, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_UNFREEZE);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_0013
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_013, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_UNFREEZE_ALL);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    bool ret = commonEvent.UnfreezeAll();
    reply.WriteBool(ret);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_0014
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_014, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_UNFREEZE_ALL);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEvent commonEvent;

    reply.WriteBool(false);
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_0015
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_015, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_GET_STICKY_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;

    reply.WriteBool(false);
    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::NO_ERROR, result);
}

/*
 * tc.number: OnRemoteRequest_0016
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_016, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_UNSUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;

    dataParcel.WriteInterfaceToken(CommonEventStub::GetDescriptor());
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
}

/*
 * tc.number: OnRemoteRequest_0017
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_017, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    bool value = true;
    dataParcel.WriteBool(value);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_TRANSACTION_FAILED, result);
}

/*
 * tc.number: OnRemoteRequest_0018
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_018, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    dataParcel.WriteRemoteObject(nullptr);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_TRANSACTION_FAILED, result);
}

/*
 * tc.number: OnRemoteRequest_0019
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_019, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    dataParcel.WriteRemoteObject(nullptr);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_TRANSACTION_FAILED, result);
}

/*
 * tc.number: OnRemoteRequest_0020
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_020, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_SUBSCRIBE_COMMON_EVENT);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventData event;
    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    CommonEventSubscribeInfo subscribeInfo;
    OHOS::sptr<OHOS::IRemoteObject> commonEventListener = new OHOS::MockIRemoteObject();
    int32_t ret = commonEventStub.SubscribeCommonEvent(subscribeInfo, commonEventListener);
    reply.WriteInt32(ret);
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_EQ(OHOS::ERR_TRANSACTION_FAILED, result);
}

/*
 * tc.number: OnRemoteRequest_0021
 * tc.name: test OnRemoteRequest
 * tc.type: FUNC
 * tc.require: issueI5NGO7
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, OnRemoteRequest_021, TestSize.Level1)
{
    const uint32_t code = static_cast<uint32_t>(CommonEventInterfaceCode::CES_FINISH_RECEIVER);
    OHOS::MessageParcel dataParcel;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    CommonEventStub commonEventStub;
    CommonEventPublishInfo publishInfo;
    OHOS::sptr<OHOS::IRemoteObject> proxy = new OHOS::MockIRemoteObject();
    proxy = nullptr;
    int result = commonEventStub.OnRemoteRequest(code, dataParcel, reply, option);
    EXPECT_NE(OHOS::ERR_INVALID_VALUE, result);
}

/*
 * tc.number: RemoveStickyCommonEvent_0001
 * tc.name: test RemoveStickyCommonEvent
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, RemoveStickyCommonEvent_0001, TestSize.Level1)
{
    CommonEventStub commonEventStub;
    std::string event = "this is event";
    int32_t result = commonEventStub.RemoveStickyCommonEvent(event);
    EXPECT_EQ(result, OHOS::ERR_OK);
}

/*
 * tc.number: SetStaticSubscriberState_001
 * tc.name: test SetStaticSubscriberState
 * tc.type: FUNC
 * tc.require: issue
 * tc.desc: Invoke CommonEventStub interface verify whether it is normal
 */
HWTEST_F(CommonEventStubTest, SetStaticSubscriberState_001, TestSize.Level1)
{
    CommonEventStub commonEventStub;
    int32_t result = commonEventStub.SetStaticSubscriberState(true);
    EXPECT_EQ(result, OHOS::ERR_OK);
}

/*
 * tc.number: SetStaticSubscriberStateWithTwoParameters_0100
 * tc.name: test SetStaticSubscriberState
 * tc.type: FUNC
 * tc.desc: Successful verification by calling SetStaticSubscriberState API.
 */
HWTEST_F(CommonEventStubTest, SetStaticSubscriberStateWithTwoParameters_0100, TestSize.Level1)
{
    CommonEventStub commonEventStub;
    std::vector<std::string> events;
    events.push_back("StaticCommonEventA");
    int32_t result = commonEventStub.SetStaticSubscriberState(events, true);
    EXPECT_EQ(result, OHOS::ERR_OK);
}