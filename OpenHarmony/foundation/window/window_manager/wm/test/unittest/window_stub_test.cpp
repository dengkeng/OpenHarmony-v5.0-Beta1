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

#include <gtest/gtest.h>
#include "window_stub.h"
#include "window_agent.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {
class WindowStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    sptr<WindowStub> windowStub_;
};

void WindowStubTest::SetUpTestCase()
{
}

void WindowStubTest::TearDownTestCase()
{
}

void WindowStubTest::SetUp()
{
    sptr<WindowOption> option = new WindowOption();
    sptr<WindowImpl> window = new WindowImpl(option);
    windowStub_ = new WindowAgent(window);
}

void WindowStubTest::TearDown()
{
}

namespace {
/**
 * @tc.name: OnRemoteRequest01
 * @tc.desc: test InterfaceToken check failed
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest01, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(u"error.GetDescriptor");

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(100);
    data.WriteUint32(100);

    data.WriteBool(false);

    data.WriteUint32(static_cast<uint32_t>(WindowSizeChangeReason::DRAG_START));

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_RECT);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.name: OnRemoteRequest02
 * @tc.desc: test TRANS_ID_UPDATE_WINDOW_RECT
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest02, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    data.WriteInt32(0);
    data.WriteInt32(0);
    data.WriteUint32(100);
    data.WriteUint32(100);

    data.WriteBool(false);

    data.WriteUint32(static_cast<uint32_t>(WindowSizeChangeReason::DRAG_START));

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_RECT);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: OnRemoteRequest03
 * @tc.desc: test TRANS_ID_UPDATE_AVOID_AREA success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest03, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    sptr<AvoidArea> avoidArea = new AvoidArea();
    data.WriteStrongParcelable(avoidArea);

    data.WriteUint32(static_cast<uint32_t>(AvoidAreaType::TYPE_SYSTEM));

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_AVOID_AREA);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: OnRemoteRequest04
 * @tc.desc: test TRANS_ID_UPDATE_AVOID_AREA success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest04, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    sptr<AvoidArea> avoidArea = new AvoidArea();
    data.WriteStrongParcelable(avoidArea);

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_AVOID_AREA);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.name: OnRemoteRequest05
 * @tc.desc: test TRANS_ID_DUMP_INFO success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest05, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    std::vector<std::string> params;
    params.push_back("-a");
    data.WriteStringVector(params);

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_DUMP_INFO);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: OnRemoteRequest06
 * @tc.desc: test TRANS_ID_DUMP_INFO failed
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest06, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());
    data.WriteRawData(nullptr, 0);

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_DUMP_INFO);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}


/**
 * @tc.name: OnRemoteRequest07
 * @tc.desc: test TRANS_ID_NOTIFY_CLIENT_POINT_UP success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest07, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    std::shared_ptr<MMI::PointerEvent> pointerEvent = MMI::PointerEvent::Create();
    pointerEvent->WriteToParcel(data);

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_CLIENT_POINT_UP);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: OnRemoteRequest08
 * @tc.desc: test TRANS_ID_NOTIFY_CLIENT_POINT_UP success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest08, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_CLIENT_POINT_UP);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.name: OnRemoteRequest09
 * @tc.desc: test TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest09, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    data.WriteInterfaceToken(WindowStub::GetDescriptor());
    data.WriteBool(false);
    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS);
    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, 0);
}

/**
 * @tc.name: OnRemoteRequest10
 * @tc.desc: test TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest10, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code = 0;

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, -1);

    IWindow::WindowMessage msgId = IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_RECT;
    EXPECT_EQ(msgId, IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_RECT);
}

/**
 * @tc.name: OnRemoteRequest11
 * @tc.desc: test TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS success
 * @tc.type: FUNC
 */
HWTEST_F(WindowStubTest, OnRemoteRequest11, Function | SmallTest | Level2)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    uint32_t code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_RECT);
    data.WriteBool(false);
    data.WriteInterfaceToken(WindowStub::GetDescriptor());

    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_MODE);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_MODE_SUPPORT_INFO);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_FOCUS_STATUS);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_AVOID_AREA);
    uint32_t type = 1;
    data.ReadUint32(type);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_WINDOW_STATE);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_DRAG_EVENT);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_DISPLAY_ID);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_OCCUPIED_AREA);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_OCCUPIED_AREA_AND_RECT);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_ACTIVE_STATUS);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_GET_WINDOW_PROPERTY);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_OUTSIDE_PRESSED);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_SCREEN_SHOT);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_DESTROY);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_FOREGROUND);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_BACKGROUND);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_DUMP_INFO);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_CLIENT_POINT_UP);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_UPDATE_ZOOM_TRANSFORM);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_RESTORE_SPLIT_WINDOW_MODE);
    code = static_cast<uint32_t>(IWindow::WindowMessage::TRANS_ID_NOTIFY_FOREGROUND_INTERACTIVE_STATUS);

    int res = windowStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, 10);
}
}
}
}
