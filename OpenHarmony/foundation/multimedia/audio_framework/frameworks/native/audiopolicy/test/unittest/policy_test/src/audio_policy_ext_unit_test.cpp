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
#undef LOG_TAG
#define LOG_TAG "AudioPolicyUnitTest"

#include <thread>
#include "audio_errors.h"
#include "audio_info.h"
#include "parcel.h"
#include "audio_policy_client.h"
#include "audio_policy_unit_test.h"
#include "audio_system_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "audio_client_tracker_callback_stub.h"
#include "audio_policy_client_stub_impl.h"
#include "audio_adapter_manager.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace AudioStandard {
class AudioPolicyExtUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AudioPolicyExtUnitTest::SetUpTestCase(void)
{
    // input testsuit setup step，setup invoked before all testcases
}

void AudioPolicyExtUnitTest::TearDownTestCase(void)
{
    // input testsuit teardown step，teardown invoked after all testcases
}

void AudioPolicyExtUnitTest::SetUp(void)
{
    // input testcase setup step，setup invoked before each testcases
}

void AudioPolicyExtUnitTest::TearDown(void)
{
    // input testcase teardown step，teardown invoked after each testcases
}

/**
 * @tc.name  : Test UpdateStreamState
 * @tc.number: UpdateStreamState_001
 * @tc.desc  : Test UpdateStreamState interface. Returns ret.
 */
HWTEST(AudioPolicyExtUnitTest, UpdateStreamState_001, TestSize.Level1)
{
    int32_t clientUid = 0;
    int32_t ret = AudioPolicyManager::GetInstance().UpdateStreamState(clientUid,
        StreamSetState::STREAM_PAUSE, StreamUsage::STREAM_USAGE_INVALID);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name  : Test UpdateStreamState
 * @tc.number: UpdateStreamState_002
 * @tc.desc  : Test UpdateStreamState interface. Returns ret.
 */
HWTEST(AudioPolicyExtUnitTest, UpdateStreamState_002, TestSize.Level1)
{
    int32_t clientUid = 1;
    int32_t ret = AudioPolicyManager::GetInstance().UpdateStreamState(clientUid,
        StreamSetState::STREAM_PAUSE, StreamUsage::STREAM_USAGE_UNKNOWN);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name  : Test UpdateStreamState
 * @tc.number: UpdateStreamState_003
 * @tc.desc  : Test UpdateStreamState interface. Returns ret.
 */
HWTEST(AudioPolicyExtUnitTest, UpdateStreamState_003, TestSize.Level1)
{
    int32_t clientUid = 2;
    int32_t ret = AudioPolicyManager::GetInstance().UpdateStreamState(clientUid,
        StreamSetState::STREAM_RESUME, StreamUsage::STREAM_USAGE_MEDIA);
    EXPECT_EQ(SUCCESS, ret);
}

/**
 * @tc.name  : Test UpdateStreamState
 * @tc.number: UpdateStreamState_004
 * @tc.desc  : Test UpdateStreamState interface. Returns ret.
 */
HWTEST(AudioPolicyExtUnitTest, UpdateStreamState_004, TestSize.Level1)
{
    int32_t clientUid = 3;
    int32_t ret = AudioPolicyManager::GetInstance().UpdateStreamState(clientUid,
        StreamSetState::STREAM_RESUME, StreamUsage::STREAM_USAGE_MUSIC);
    EXPECT_EQ(SUCCESS, ret);
}

} // namespace AudioStandard
} // namespace OHOS