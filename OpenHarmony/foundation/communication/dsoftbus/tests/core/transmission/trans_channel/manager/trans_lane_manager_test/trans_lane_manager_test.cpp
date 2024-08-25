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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_trans_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "softbus_adapter_mem.h"
#include "trans_lane_manager.h"
#include "trans_lane_manager.c"
#include "trans_log.h"

using namespace testing::ext;
namespace OHOS {
#define TEST_SESSION_NAME "com.softbus.transmission.test"
#define TEST_CONN_IP "192.168.8.1"
#define TEST_AUTH_PORT 6000
#define TEST_AUTH_DATA "test auth message data"
#define TEST_PKG_NAME "com.test.trans.demo.pkgname"

class TransLaneManagerTest : public testing::Test {
public:
    TransLaneManagerTest()
    {}
    ~TransLaneManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLaneManagerTest::SetUpTestCase(void)
{}

void TransLaneManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: GetTransSessionInfoByLane001
 * @tc.desc: GetTransSessionInfoByLane, use the wrong parameter.
 * @tc.desc: ConvertLaneLinkTypeToDumper, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, GetTransSessionInfoByLane001, TestSize.Level1)
{
    TransLaneInfo *laneItem = (TransLaneInfo *)SoftBusMalloc(sizeof(TransLaneInfo));
    ASSERT_TRUE(laneItem != nullptr);
    memset_s(laneItem, sizeof(TransLaneInfo), 0, sizeof(TransLaneInfo));

    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));

    TransDumpLaneLinkType transDumpLaneLinkType;

    GetTransSessionInfoByLane(laneItem, appInfo);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_BR);
    EXPECT_EQ(DUMPER_LANE_BR, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_BLE);
    EXPECT_EQ(DUMPER_LANE_BLE, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_P2P);
    EXPECT_EQ(DUMPER_LANE_P2P, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_WLAN_2P4G);
    EXPECT_EQ(DUMPER_LANE_WLAN, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_WLAN_5G);
    EXPECT_EQ(DUMPER_LANE_WLAN, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_ETH);
    EXPECT_EQ(DUMPER_LANE_ETH, transDumpLaneLinkType);

    transDumpLaneLinkType = ConvertLaneLinkTypeToDumper(LANE_LINK_TYPE_BUTT);
    EXPECT_EQ(DUMPER_LANE_LINK_TYPE_BUTT, transDumpLaneLinkType);
}

/**
 * @tc.name: TransChannelInit001
 * @tc.desc: TransChannelInit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransChannelInit001, TestSize.Level1)
{
    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();
}

/**
 * @tc.name: TransLaneChannelForEachShowInfo001
 * @tc.desc: TransLaneChannelForEachShowInfo, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneChannelForEachShowInfo001, TestSize.Level1)
{
    int fd = 1;
    TransLaneMgrDeinit();
    TransLaneChannelForEachShowInfo(fd);

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneChannelForEachShowInfo(fd);
}

/**
 * @tc.name: TransLaneMgrAddLane001
 * @tc.desc: TransLaneMgrAddLane001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrAddLane001, TestSize.Level1)
{
    int32_t channelId = 2112;
    int32_t channelType = 2112;
    uint32_t laneHandle = 1;
    bool isQosLane = false;

    AppInfoData *myData = (AppInfoData *)SoftBusCalloc(sizeof(AppInfoData));
    ASSERT_TRUE(myData != nullptr);
    LaneConnInfo *connInfo = (LaneConnInfo *)SoftBusCalloc(sizeof(LaneConnInfo));
    ASSERT_TRUE(connInfo != nullptr);

    TransLaneMgrDeinit();
    int32_t ret = TransLaneMgrAddLane(channelId, channelType, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLaneMgrAddLane(channelId, channelType, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransLaneMgrAddLane(channelId, channelType, NULL, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    channelId = 1;
    channelType = 2;
    ret = TransLaneMgrAddLane(channelId, channelType, connInfo, laneHandle, isQosLane, myData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    if (myData != NULL) {
        SoftBusFree(myData);
    }
    if (connInfo != NULL) {
        SoftBusFree(connInfo);
    }
}

/**
 * @tc.name: TransLaneMgrDelLane001
 * @tc.desc: TransLaneMgrDelLane001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrDelLane001, TestSize.Level1)
{
    int32_t channelId = 12;
    int32_t channelType = 22;
    TRANS_LOGI(TRANS_TEST, "TransLaneMgrDelLane001 start");
    TransLaneMgrDeinit();
    int32_t ret = TransLaneMgrDelLane(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();
    channelId = -1;
    channelType = 9999999;
    ret = TransLaneMgrDelLane(channelId, channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    TRANS_LOGI(TRANS_TEST, "TransLaneMgrDelLane001 end");
}

/**
 * @tc.name: TransLaneMgrDeathCallback001
 * @tc.desc: TransLaneMgrDeathCallback001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransLaneMgrDeathCallback001, TestSize.Level1)
{
    int32_t pid = 2112;
    const char *pkgName = TEST_PKG_NAME;

    TransLaneMgrDeinit();
    TransLaneMgrDeathCallback(pkgName, pid);

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    pid = -1;
    TransLaneMgrDeathCallback(pkgName, pid);
    TransLaneMgrDeinit();
}

/**
 * @tc.name: TransGetLaneReqIdByChannelId001
 * @tc.desc: TransGetLaneReqIdByChannelId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransGetLaneReqIdByChannelId001, TestSize.Level1)
{
    int32_t channelId = 2112;
    uint32_t laneHandle = 22;

    int32_t ret = TransGetLaneHandleByChannelId(channelId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    channelId = -1;
    ret = TransGetLaneHandleByChannelId(channelId, &laneHandle);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransGetChannelInfoByLaneReqId001
 * @tc.desc: TransGetChannelInfoByLaneReqId001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransGetChannelInfoByLaneReqId001, TestSize.Level1)
{
    int32_t channelId = 2112;
    int32_t channelType = 2112;
    uint32_t laneHandle = 0;

    int32_t ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransLaneMgrDeinit();

    ret = TransGetChannelInfoByLaneHandle(laneHandle, NULL, &channelType);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransGetChannelInfoByLaneHandle(laneHandle, &channelId, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = TransLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetChannelInfoByLaneHandle(laneHandle, &channelId, &channelType);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransSocketChannelInfoTest001
 * @tc.desc: TransSocketChannelInfoTest001.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneManagerTest, TransSocketChannelInfoTest001, TestSize.Level1)
{
    int32_t ret = TransSocketLaneMgrInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    char sessionName[SESSION_NAME_SIZE_MAX] = "testSessionName";
    int32_t sessionId = 1;
    ret = TransAddSocketChannelInfo(
        sessionName, sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CoreSessionState state;
    ret = TransGetSocketChannelStateBySession(sessionName, sessionId, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_INIT);
    int32_t channelId = 1;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransUpdateSocketChannelInfoBySession(sessionName, sessionId, channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    uint32_t lanHandele = 1;
    ret = TransUpdateSocketChannelLaneInfoBySession(sessionName, sessionId, lanHandele, false, true);
    EXPECT_EQ(SOFTBUS_OK, ret);
    lanHandele = INVALID_CHANNEL_ID;
    ret = TransGetSocketChannelLaneInfoBySession(sessionName, sessionId, &lanHandele, NULL, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(lanHandele, 1);
    ret = TransGetSocketChannelStateByChannel(channelId, channelType, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_INIT);
    ret = TransSetSocketChannelStateByChannel(channelId, channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetSocketChannelStateBySession(sessionName, sessionId, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_CHANNEL_OPENED);
    ret = TransSetSocketChannelStateBySession(sessionName, sessionId, CORE_SESSION_STATE_CANCELLING);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransGetSocketChannelStateByChannel(channelId, channelType, &state);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(state, CORE_SESSION_STATE_CANCELLING);
    int32_t pid = -1;
    ret = TransGetPidFromSocketChannelInfoBySession(sessionName, sessionId, &pid);
    EXPECT_EQ(pid, 0);
    ret = TransDeleteSocketChannelInfoByChannel(channelId, channelType);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransDeleteSocketChannelInfoBySession(sessionName, sessionId);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    ret = TransDeleteSocketChannelInfoByPid(pid);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
    TransSocketLaneMgrDeinit();
    ret = TransAddSocketChannelInfo(
        sessionName, sessionId, INVALID_CHANNEL_ID, CHANNEL_TYPE_BUTT, CORE_SESSION_STATE_INIT);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}
} // OHOS
