/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <mutex>
#include <shared_mutex>
#include <string>
#include <refbase.h>
#include "cstdio"
#include "cstdlib"
#include <securec.h>
#include "native_drm_common.h"
#include "native_drm_err.h"
#include "gmock/gmock.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "i_mediadecryptmodule_service.h"
#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"
#include "cstdbool"
#include "drm_types.h"
#include "drm_framework_unittest.h"
#include "system_ability_definition.h"
#include "drm_log.h"
#include "drm_death_recipient.h"
#include "key_session_impl.h"
#include "i_mediakeysystem_service.h"
#include "mediakeysystem_service_callback_stub.h"
#include "http.h"
#include "ashmem.h"
#include "media_decrypt_module_service_proxy.h"
#include <cstring>
#include <map>
#include <unordered_map>
#include "nocopyable.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "i_keysession_service.h"
#include "i_keysession_service_callback.h"
#include "key_session_service_callback_stub.h"

#define DRM_SAMPLE_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
    do {                                                         \
        if ((cond)) {                                            \
            printf(fmt, ##__VA_ARGS__);                          \
            return ret;                                          \
        }                                                        \
    } while (0)
#define DRM_SAMPLE_INFO_LOG(fmt, ...) fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)
#define DRM_SAMPLE_ERROR_LOG(fmt, ...) fprintf(stdout, "[ERROR] " fmt "\n", ##__VA_ARGS__)
#define OFFRESPONSE                                                                                            \
    {                                                                                                          \
        0x31, 0x64, 0x6E, 0x5A, 0x32, 0x4E, 0x57, 0x74, 0x76, 0x4D, 0x47,                                      \
            0x34, 0x34, 0x4E, 0x6A, 0x42, 0x30, 0x4D, 0x32, 0x77, 0x33,                                        \
            0x4E, 0x67, 0x3D, 0x3D, 0x3A, 0x59, 0x7A, 0x56, 0x78, 0x63,                                        \
            0x48, 0x64, 0x70, 0x61, 0x6D, 0x30, 0x34, 0x59, 0x57, 0x45,                                        \
            0x34, 0x5A, 0x48, 0x6B, 0x79, 0x4D, 0x67, 0x3D, 0x3D                                               \
    }
#define REQUESTINFODATA                                                                                        \
    {                                                                                                          \
        0x00, 0x00, 0x00, 0x8B, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00,                                      \
            0x00, 0x3D, 0x5E, 0x6D, 0x35, 0x9B, 0x9A, 0x41, 0xE8, 0xB8,                                        \
            0x43, 0xDD, 0x3C, 0x6E, 0x72, 0xC4, 0x2C, 0x00, 0x00, 0x00,                                        \
            0x6B, 0x7B, 0x22, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E,                                        \
            0x22, 0x3A, 0x22, 0x56, 0x31, 0x2E, 0x30, 0x22, 0x2C, 0x22,                                        \
            0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x49, 0x44, 0x22,                                        \
            0x3A, 0x22, 0x64, 0x48, 0x4D, 0x74, 0x4D, 0x6A, 0x59, 0x30,                                        \
            0x4C, 0x54, 0x45, 0x77, 0x4F, 0x44, 0x41, 0x74, 0x59, 0x57,                                        \
            0x56, 0x7A, 0x22, 0x2C, 0x22, 0x6B, 0x69, 0x64, 0x73, 0x22,                                        \
            0x3A, 0x5B, 0x22, 0x47, 0x2B, 0x45, 0x6B, 0x2F, 0x2B, 0x58,                                        \
            0x6D, 0x55, 0x6B, 0x70, 0x42, 0x48, 0x51, 0x67, 0x58, 0x59,                                        \
            0x57, 0x51, 0x51, 0x49, 0x67, 0x3D, 0x3D, 0x22, 0x5D, 0x2C,                                        \
            0x22, 0x65, 0x6E, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x22,                                        \
            0x3A, 0x22, 0x63, 0x62, 0x63, 0x31, 0x22, 0x7D                                                     \
    }
#define OFFREQUESTINFODATA                                                                                     \
    {                                                                                                          \
        0x00, 0x00, 0x00, 0xF1, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00,                                \
            0x3D, 0x5E, 0x6D, 0x35, 0x9B, 0x9A, 0x41, 0xE8, 0xB8, 0x43, 0xDD,                                  \
            0x3C, 0x6E, 0x72, 0xC4, 0x2C, 0x00, 0x00, 0x00, 0xD1, 0x7B, 0x22,                                  \
            0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x22, 0x56,                                  \
            0x31, 0x2E, 0x30, 0x22, 0x2C, 0x22, 0x63, 0x6F, 0x6E, 0x74, 0x65,                                  \
            0x6E, 0x74, 0x49, 0x44, 0x22, 0x3A, 0x22, 0x78, 0x75, 0x78, 0x69,                                  \
            0x6E, 0x30, 0x37, 0x31, 0x31, 0x22, 0x2C, 0x22, 0x6B, 0x69, 0x64,                                  \
            0x73, 0x22, 0x3A, 0x5B, 0x22, 0x61, 0x63, 0x61, 0x32, 0x35, 0x35,                                  \
            0x65, 0x35, 0x62, 0x32, 0x64, 0x64, 0x65, 0x32, 0x65, 0x34, 0x63,                                  \
            0x38, 0x62, 0x62, 0x37, 0x63, 0x31, 0x36, 0x36, 0x63, 0x65, 0x61,                                  \
            0x63, 0x31, 0x30, 0x30, 0x22, 0x2C, 0x22, 0x61, 0x63, 0x61, 0x32,                                  \
            0x35, 0x35, 0x65, 0x35, 0x62, 0x32, 0x64, 0x64, 0x65, 0x32, 0x65,                                  \
            0x34, 0x63, 0x38, 0x62, 0x62, 0x37, 0x63, 0x31, 0x36, 0x36, 0x63,                                  \
            0x65, 0x61, 0x63, 0x31, 0x30, 0x31, 0x22, 0x2C, 0x22, 0x61, 0x63,                                  \
            0x61, 0x32, 0x35, 0x35, 0x65, 0x35, 0x62, 0x32, 0x64, 0x64, 0x65,                                  \
            0x32, 0x65, 0x34, 0x63, 0x38, 0x62, 0x62, 0x37, 0x63, 0x31, 0x36,                                  \
            0x36, 0x63, 0x65, 0x61, 0x63, 0x31, 0x30, 0x31, 0x22, 0x2C, 0x22,                                  \
            0x61, 0x63, 0x61, 0x32, 0x35, 0x35, 0x65, 0x35, 0x62, 0x32, 0x64,                                  \
            0x64, 0x65, 0x32, 0x65, 0x34, 0x63, 0x38, 0x62, 0x62, 0x37, 0x63,                                  \
            0x31, 0x36, 0x36, 0x63, 0x65, 0x61, 0x63, 0x31, 0x30, 0x31, 0x22,                                  \
            0x5D, 0x2C, 0x22, 0x65, 0x6E, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61,                                  \
            0x22, 0x3A, 0x22, 0x63, 0x62, 0x63, 0x31, 0x22, 0x7D                                               \
    }
#define ONRESPONSE                                                                                             \
    {                                                                                                          \
        0x30, 0x64, 0x6E, 0x5A, 0x32, 0x4E, 0x57, 0x74, 0x76, 0x4D, 0x47,                                      \
            0x34, 0x34, 0x4E, 0x6A, 0x42, 0x30, 0x4D, 0x32, 0x77, 0x33,                                        \
            0x4E, 0x67, 0x3D, 0x3D, 0x3A, 0x59, 0x7A, 0x56, 0x78, 0x63,                                        \
            0x48, 0x64, 0x70, 0x61, 0x6D, 0x30, 0x34, 0x59, 0x57, 0x45,                                        \
            0x34, 0x5A, 0x48, 0x6B, 0x79, 0x4D, 0x67, 0x3D, 0x3D                                               \
    }


#define LICENSE_URL "http://192.168.50.59:9528/getLicense"
#define PROVISION_URL "http://192.168.50.59:9528/getProvision"
using namespace testing::ext;
using namespace std;

namespace {
const int32_t STEP_ONE = 1;
const int32_t STEP_TWO = 2;
const int32_t STEP_THREE = 3;
const int32_t STEP_FOUR = 4;
}

namespace OHOS {
namespace DrmStandard {

bool g_isWisePlay = false;
void DrmFrameworkUnitTest::SetUpTestCase(void) {}

void DrmFrameworkUnitTest::TearDownTestCase(void) {}

static const char *GetUuid()
{
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        return "com.clearplay.drm";
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        return "com.wiseplay.drm";
    } else {
        return "ERROR";
    }
}

void DrmFrameworkUnitTest::SetUp()
{
    if (strcmp(GetUuid(), "com.wiseplay.drm") == 0) {
        g_isWisePlay = true;
    }
}

void DrmFrameworkUnitTest::TearDown() {}

static const char *GetDrmPlugin()
{
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        return "killall -9 clearplay_host";
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        return "killall -9 wiseplay_host";
    } else {
        return "ERROR";
    }
}

Drm_ErrCode TestSystemEventCallBack(DRM_EventType eventType, unsigned char *info,
    int32_t infoLen, char *extra)
{
    DRM_SAMPLE_INFO_LOG("TestSystemEventCallBack ok");
    return DRM_ERR_OK;
}

Drm_ErrCode TestSessoinEventCallBack(DRM_EventType eventType, unsigned char *info,
    int32_t infoLen, char *extra)
{
    DRM_SAMPLE_INFO_LOG("TestSessoinEventCallBack ok");
    return DRM_ERR_OK;
}

Drm_ErrCode TestSessoinKeyChangeCallBack(DRM_KeysInfo *keysInfo, bool hasNewGoodKeys)
{
    DRM_SAMPLE_INFO_LOG("TestSessoinKeyChangeCallBack ok");
    return DRM_ERR_OK;
}

Drm_ErrCode TestSystemEventCallBackWithObj(MediaKeySystem *mediaKeySystem, DRM_EventType eventType,
    uint8_t *info, int32_t infoLen, char *extra)
{
    DRM_SAMPLE_INFO_LOG("TestSystemEventCallBackWithObj ok");
    if (mediaKeySystem == nullptr) {
        return DRM_ERR_UNKNOWN;
    }
    DRM_SAMPLE_INFO_LOG("Event: event type: %d", eventType);
    DRM_SAMPLE_INFO_LOG("Event: the info body is: ");
    if (info != nullptr) {
        for (int32_t i = 0; i < infoLen; i++) {
            DRM_SAMPLE_INFO_LOG("%x", info[i]);
        }
    }
    if (extra != nullptr) {
        DRM_SAMPLE_INFO_LOG("Event: the extra is: %s", extra);
    }
    return DRM_ERR_OK;
}

Drm_ErrCode TestSessoinEventCallBackWithObj(MediaKeySession *mediaKeySessoin, DRM_EventType eventType,
    uint8_t *info, int32_t infoLen, char *extra)
{
    DRM_SAMPLE_INFO_LOG("TestSessoinEventCallBackWithObj ok");
    if (mediaKeySessoin == nullptr) {
        return DRM_ERR_UNKNOWN;
    }
    DRM_SAMPLE_INFO_LOG("Event: the event type: %d", eventType);
    DRM_SAMPLE_INFO_LOG("Event: the info body is: ");
    if (info != nullptr) {
        for (int32_t i = 0; i < infoLen; i++) {
            DRM_SAMPLE_INFO_LOG("%x", info[i]);
        }
    }
    if (extra != nullptr) {
        DRM_SAMPLE_INFO_LOG("Event: the extra is: %s", extra);
    }
    return DRM_ERR_OK;
}

Drm_ErrCode TestSessoinKeyChangeCallBackWithObj(MediaKeySession *mediaKeySessoin, DRM_KeysInfo *keysInfo,
    bool hasNewGoodKeys)
{
    DRM_SAMPLE_INFO_LOG("TestSessoinKeyChangeCallBackWithObj ok");
    if (mediaKeySessoin == nullptr) {
        return DRM_ERR_UNKNOWN;
    }
    for (uint32_t i = 0; i < keysInfo->keysInfoCount; i++) {
        for (uint32_t j = 0; j < MAX_KEY_ID_LEN; j += STEP_FOUR) {
            DRM_SAMPLE_INFO_LOG("KeyChangedEvent: keyid is: ");
            DRM_SAMPLE_INFO_LOG("%x %x %x %x",
                keysInfo->keyId[i][j], keysInfo->keyId[i][j + STEP_ONE],
                keysInfo->keyId[i][j + STEP_TWO], keysInfo->keyId[i][j + STEP_THREE]);
        }
        DRM_SAMPLE_INFO_LOG("KeyChangedEvent: statusValue %s", keysInfo->statusValue[i]);
    }
    return DRM_ERR_OK;
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupportedNormal_001, TestSize.Level0)
{
    bool supported;
    supported = OH_MediaKeySystem_IsSupported(GetUuid());
    EXPECT_EQ(supported, true);
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupported2Normal_002, TestSize.Level0)
{
    bool supported;
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), "video/mp4");
    EXPECT_EQ(supported, true);
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupported3Normal_003, TestSize.Level0)
{
    bool supported;
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, true);
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupportedAbNormal_004, TestSize.Level0)
{
    bool supported = true;
    supported = OH_MediaKeySystem_IsSupported("com.drm.clearpla");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported("");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported(nullptr);
    EXPECT_EQ(supported, false);
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupported2AbNormal_005, TestSize.Level0)
{
    bool supported = true;
    supported = OH_MediaKeySystem_IsSupported2("com.drm.clearpla", "video/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2("", "video/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(nullptr, "video/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), "ideo/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), "");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), nullptr);
    EXPECT_EQ(supported, false);
}

/*
 * Feature: Framework
 * Function: Test to determine if the creation of this DRM instance is supported
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Test to determine if it supports creating the DRM instance interface OH_MediaKeySystem_IsSupported
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemIsSupported3AbNormal_006, TestSize.Level0)
{
    bool supported = true;
    supported = OH_MediaKeySystem_IsSupported3("com.drm.clearpla", "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3("", "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(nullptr, "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "ideo/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), nullptr, CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "video/mp4",
        (DRM_ContentProtectionLevel)(CONTENT_PROTECTION_LEVEL_UNKNOWN - 1));
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "video/mp4",
        (DRM_ContentProtectionLevel)CONTENT_PROTECTION_LEVEL_MAX);
    EXPECT_EQ(supported, false);
}

/*
 * Feature: Framework
 * Function: Test and create DRM instances
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Test Creating DRM Instance
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySystemNormal_007, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_GT(contentProtectionLevel, 0);
    if (mediaKeySystem != nullptr) {
        OH_MediaKeySystem_Destroy(mediaKeySystem);
    }
}

/*
 * Feature: Framework
 * Function: Test and create DRM instances
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Testing for an incorrect uuid and unsuccessful creation of DRM instance.
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySystemAbNormal_008, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_Create("com.drm.clerpay", &mediaKeySystem);
    EXPECT_EQ(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Test and create DRM instances
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Test passed in an empty uuid and failed to create a DRM instance.
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySystemAbNormal_009, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_Create("", &mediaKeySystem);
    EXPECT_EQ(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Test and create DRM instances
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: After the DRM instance is created, it is destroyed, and then the subsequent interface is called.
 * The interface returns unsuccessful.
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySystemNormal_010, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Test and create sessions
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Test Creating Sessions
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySessionNormal_011, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Test that the RequireSecureDecoderModule interface is functioning properly
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: Testing that the RequireSecureDecoderModule interface is functioning properly
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleNormal_012, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, "video/mp4", &requireSecureDecoder);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: RequireSecureDecoderModule Exception Test Input Error mimtype
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: RequireSecureDecoderModule Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleAbNormal_013, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder = false;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, "asdssadadsa", &requireSecureDecoder);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: RequireSecureDecoderModule Exception Test Input Error mimtype
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: RequireSecureDecoderModule Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleAbNormal_014, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder = false;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, "", &requireSecureDecoder);
    EXPECT_NE(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: RequireSecureDecoderModule Exception Test Input Error mimtype
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: RequireSecureDecoderModule Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleAbNormal_015, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder = false;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, nullptr, &requireSecureDecoder);
    EXPECT_NE(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: RequireSecureDecoderModule Exception Test Input Error mimtype
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: RequireSecureDecoderModule Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleAbNormal_016, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder = false;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, "video/mp4", nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: RequireSecureDecoderModule Exception Test Input Error mimtype
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: RequireSecureDecoderModule Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RequireSecureDecoderModuleAbNormal_017, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    bool requireSecureDecoder = false;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(nullptr, "video/mp4", &requireSecureDecoder);
    EXPECT_NE(errNo, DRM_ERR_OK);
    EXPECT_EQ(requireSecureDecoder, false);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: GenerateKeySystemRequest normal testing to obtain normal requests
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case description: GenerateKeySystemRequest obtained a normal request through normal testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateKeySystemRequestNormal_018, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: GenerateKeySystemRequest parameter exception testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: GenerateKeySystemRequest Parameter Exception Test
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateKeySystemRequestAbNormal_019, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(nullptr, request, &requestLen, defaultUrl, defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, nullptr, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, nullptr, defaultUrl, defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, nullptr, defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseNormal_020, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}


/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_021, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(nullptr, KeySystemResponse, KeySystemResponseLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_022, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, nullptr, KeySystemResponseLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_023, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    KeySystemResponseLen = 0;
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateMediaKeyRequestNormal_024, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateMediaKeyRequestAbNormal_025, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(nullptr, &info, &mediaKeyRequest);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateMediaKeyRequestAbNormal_026, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, nullptr, &mediaKeyRequest);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
  * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateMediaKeyRequestAbNormal_027, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseNormal_028, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_029, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[1] = { 0 };
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(nullptr, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_030, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[1] = { 0 };
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, nullptr, 0,
        onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_031, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeySessionResponse[50] = OFFRESPONSE;
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)(sizeof(testKeySessionResponse)), nullptr, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}


/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_032, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);

    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)(sizeof(testKeySessionResponse)), onlineMediaKeyId, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CheckMediaKeyStatusNormal_033, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    unsigned char testData[139] = REQUESTINFODATA;
    info.type = MEDIA_KEY_TYPE_ONLINE;
    info.initDataLen = sizeof(testData);
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CheckMediaKeyStatusAbNormal_034, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(nullptr, &mediaKeyStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CheckMediaKeyStatusAbNormal_035, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ClearMediaKeysNormal_036, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ClearMediaKeys(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ClearMediaKeysAbNormal_037, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ClearMediaKeys(nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyStatusNormal_038, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyStatusAbNormal_039, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(nullptr, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyStatusAbNormal_040, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, nullptr, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyStatusAbNormal_041, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyIdsNormal_042, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediakeyIdArray offlineMediaKeyIds;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyIds(mediaKeySystem, &offlineMediaKeyIds);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyIdsAbNormal_043, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediakeyIdArray offlineMediaKeyIds;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyIds(nullptr, &offlineMediaKeyIds);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetOfflineMediaKeyIdsAbNormal_044, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyIds(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateOfflineReleaseRequestNormal_045, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GenerateOfflineReleaseRequestAbNormal_046, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(nullptr, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, nullptr, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        nullptr, &releaseRequestLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessOfflineReleaseResponseNormal_047, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessOfflineReleaseResponseAbNormal_048, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(nullptr, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, nullptr, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        nullptr, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetCertificateStatusNormal_049, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_CertificateStatus certStatus = CERT_STATUS_INVALID;
    errNo = OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, &certStatus);
    EXPECT_EQ(certStatus, 0);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetCertificateStatusAbNormal_050, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_CertificateStatus certStatus = CERT_STATUS_INVALID;
    errNo = OH_MediaKeySystem_GetCertificateStatus(nullptr, &certStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, nullptr);
        EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetConfigurationStringNormal_051, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo =
        OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "testConfigurationString");
    EXPECT_EQ(errNo, DRM_ERR_OK);
    char value[32];
    int32_t valueLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, valueLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, 10);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetConfigurationStringAbNormal_052, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(nullptr, "testConfigurationString", "gezhegezhegezhe");
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "", "gezhegezhegezhe");
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, nullptr, "gezhegezhegezhe");
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "");
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetConfigurationStringAbNormal_053, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "gezhegezhegezhe");
    EXPECT_EQ(errNo, DRM_ERR_OK);
    char value[32];
    int32_t valueLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationString(nullptr, "testConfigurationString", value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "", value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, nullptr, value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", nullptr, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetConfigurationByteArrayNormal_054, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char configByteArray[32];
    int32_t byteArrayLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", configByteArray,
        &byteArrayLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetConfigurationByteArrayAbNormal_055, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(nullptr, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "", testArray, sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, nullptr, testArray, sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", nullptr,
        sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetConfigurationByteArrayAbNormal_056, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char configByteArray[32];
    int32_t byteArrayLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(nullptr, "testConfigurationByteArray", configByteArray,
        &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "", configByteArray, &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, nullptr, configByteArray, &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", nullptr,
        &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", configByteArray,
        nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetStatisticsNormal_057, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_Statistics statistics;
    errNo = OH_MediaKeySystem_GetStatistics(mediaKeySystem, &statistics);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetStatisticsAbNormal_058, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_Statistics statistics;
    errNo = OH_MediaKeySystem_GetStatistics(nullptr, &statistics);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetStatistics(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Test and create DRM instances
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Test Creating DRM Instance
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetMaxContentProtectionLevelAbNormal_059, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(nullptr, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    if (mediaKeySystem != nullptr) {
        OH_MediaKeySystem_Destroy(mediaKeySystem);
    }
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ClearOfflineMediaKeysNormal_060, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 0);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ClearOfflineMediaKeysAbNormal_061, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(nullptr, onlineMediaKeyId, onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, nullptr, onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RestoreOfflineMediaKeysNormal_062, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}
/*
 * Feature: Framework
 * Function: Processing device certificate response testing
 * Sub function: NA
 * Function point: NA
 * Environmental conditions: NA
 * Case Description: Processing Device Certificate Response Testing
 */
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RestoreOfflineMediaKeysAbNormal_063, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[241] = OFFREQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(nullptr, onlineMediaKeyId, onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, nullptr, onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, onlineMediaKeyId, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

#define MAX_BUFF 139
static void filldata(DRM_MediaKeyRequestInfo *info)
{
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info->initDataLen = sizeof(testData);
    info->type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info->mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info->initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info->optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info->optionData[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    info->optionsCount = 1;
}

const unsigned char TESTKEYRELEASERESPONSE[50] = {0x31, 0x64, 0x6E, 0x5A, 0x32, 0x4E, 0x57, 0x74, 0x76, 0x4D, 0x47,
                                                  0x34, 0x34, 0x4E, 0x6A, 0x42, 0x30, 0x4D, 0x32, 0x77, 0x33, 0x4E,
                                                  0x67, 0x3D, 0x3D, 0x3A, 0x59, 0x7A, 0x56, 0x78, 0x63, 0x48, 0x64,
                                                  0x70, 0x61, 0x6D, 0x30, 0x34, 0x59, 0x57, 0x45, 0x34, 0x5A, 0x48,
                                                  0x6B, 0x79, 0x4D, 0x67, 0x3D, 0x3D};
const unsigned char TESTKEYSESSIONRESPONSE[50] = {0x31, 0x64, 0x6E, 0x5A, 0x32, 0x4E, 0x57, 0x74, 0x76, 0x4D, 0x47,
                                                  0x34, 0x34, 0x4E, 0x6A, 0x42, 0x30, 0x4D, 0x32, 0x77, 0x33, 0x4E,
                                                  0x67, 0x3D, 0x3D, 0x3A, 0x59, 0x7A, 0x56, 0x78, 0x63, 0x48, 0x64,
                                                  0x70, 0x61, 0x6D, 0x30, 0x34, 0x59, 0x57, 0x45, 0x34, 0x5A, 0x48,
                                                  0x6B, 0x79, 0x4D, 0x67, 0x3D, 0x3D};

static void filltest3(MediaKeySystem *mediaKeySystem,
    MediaKeySession *mediaKeySession, unsigned char *keySystemResponse, int32_t KeySystemResponseLen)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, keySystemResponse,
        KeySystemResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, onlineMediaKeyId, onlineMediaKeyIdLen,
        &OfflineMediaKeyStatus);
    EXPECT_EQ(OfflineMediaKeyStatus, 1);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        (uint8_t *)(TESTKEYRELEASERESPONSE), (int32_t)(sizeof(TESTKEYRELEASERESPONSE)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_ContentProtectionLevel sessionContentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySession_GetContentProtectionLevel(mediaKeySession, &sessionContentProtectionLevel);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_GetContentProtectionLevel(nullptr, &sessionContentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_GetContentProtectionLevel(mediaKeySession, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
}
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetContentProtectionLevelNormal_064, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    EXPECT_EQ(errNo, DRM_ERR_OK);
    filltest3(mediaKeySystem, mediaKeySession, KeySystemResponse, KeySystemResponseLen);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_GetContentProtectionLevelNormal_065, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_DecryptModuleNormal_066, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        sptr<IMediaKeySessionService> SessionServiceProxy =
            sessionObject->sessionImpl_->GetMediaKeySessionServiceProxy();
        sptr<IMediaDecryptModuleService> decryptModule;
        SessionServiceProxy->CreateMediaDecryptModule(decryptModule);
        MessageParcel data;
        IMediaDecryptModuleService::DrmBuffer srcBuffer;
        IMediaDecryptModuleService::DrmBuffer dstBuffer;
        bool secureDecodrtState = false;
        IMediaDecryptModuleService::CryptInfo cryptInfo;
        decryptModule->DecryptMediaData(secureDecodrtState, cryptInfo, srcBuffer, dstBuffer);
        decryptModule->Release();
        sptr<MediaKeySessionImplCallback> callback = sessionObject->sessionImpl_->GetApplicationCallback();
        callback->~MediaKeySessionImplCallback();
    }
    if (mediaKeySystem) {
        MediaKeySystemObject *systemObject = reinterpret_cast<MediaKeySystemObject *>(mediaKeySystem);
        sptr<IMeidaKeySystemServiceCallback> serviceCallback =
            new (std::nothrow) MediaKeySystemCallback(systemObject->systemImpl_);
        sptr<MediaKeySystemCallback> Callback = new (std::nothrow) MediaKeySystemCallback(systemObject->systemImpl_);
        const std::vector<uint8_t> data = { 0x01 };
        MessageParcel data1;
        MessageParcel reply;
        MessageOption option;
        Callback->OnRemoteRequest(MEDIA_KEY_SYSTEM_SERVICE_CALLBACK_SEND_EVENT,  data1, reply, option);
        serviceCallback->SendEvent(OHOS::DrmStandard::DrmEventType::DRM_EVENT_PROVISION_REQUIRED,  1, data);
        OHOS::sptr<OHOS::DrmStandard::MediaKeySystemCallbackCapi> SystemCallbackCapi =
            new (std::nothrow) MediaKeySystemCallbackCapi();
        SystemCallbackCapi->SetCallbackReference(&TestSystemEventCallBack);
        SystemCallbackCapi->SendEvent("1",  1, data);
        sptr<MediaKeySystemImplCallback> SystemImplCallba = systemObject->systemImpl_->GetApplicationCallback();
        SystemImplCallba->~MediaKeySystemImplCallback();
    }
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_DecryptModuleNormal_067, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    int32_t releaseRequestLen = 8192; // 8192:request len
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    uint8_t mediaKeyIdToRelease;
    MediaKeySession *mediaKeySession = (MediaKeySession *)&mediaKeyIdToRelease;
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, nullptr, 11, releaseRequest, // 11:len
        &releaseRequestLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, (uint8_t *)&releaseRequestLen, 0,
        releaseRequest, &releaseRequestLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, (uint8_t *)&releaseRequestLen, 0,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, nullptr, 11, // 11:len
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, (uint8_t *)&releaseRequestLen,
        11, nullptr, (int32_t)(sizeof(testKeyReleaseResponse))); // 11:len
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, (uint8_t *)&releaseRequestLen,
        11, testKeyReleaseResponse, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_RestoreOfflineMediaKeysAbNormal_068, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    unsigned char onlineMediaKeyId[88]; // 88:keyId len
    uint32_t onlineMediaKeyIdLen = 88; // 88:keyId len
    MediaKeySession *mediaKeySession = (MediaKeySession *)&onlineMediaKeyId;
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, onlineMediaKeyId, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, nullptr, onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetMediaKeySessionCallbackNormal_069, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // test 3: system callback
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(nullptr, &TestSystemEventCallBack);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(nullptr, &sessionCallback);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySessionAbNormal_070, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(nullptr, &mediaKeySystem);
    EXPECT_EQ(mediaKeySystem, nullptr);
    errNo = OH_MediaKeySystem_Create(GetUuid(), nullptr);
    EXPECT_EQ(mediaKeySystem, nullptr);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(nullptr, &contentProtectionLevel, &mediaKeySession);
    EXPECT_EQ(mediaKeySession, nullptr);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, nullptr, &mediaKeySession);
        EXPECT_EQ(mediaKeySession, nullptr);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, nullptr);
    EXPECT_EQ(mediaKeySession, nullptr);
    uint8_t mediaKeyIdToClear;
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, (uint8_t *)&mediaKeyIdToClear, 0);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, nullptr, 11); // 11:len
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
}


HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySystemDestroyAbNormal_071, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    int32_t valueLen = 32;
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySystem) {
        MediaKeySystemObject *systemObject = reinterpret_cast<MediaKeySystemObject *>(mediaKeySystem);
        systemObject->systemImpl_->~MediaKeySystemImpl();
    }
    errNo =
        OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "testConfigurationString");
    EXPECT_NE(errNo, DRM_ERR_OK);
    char value[32];
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char configByteArray[32];
    int32_t byteArrayLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", configByteArray,
        &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_Statistics statistics;
    errNo = OH_MediaKeySystem_GetStatistics(mediaKeySystem, &statistics);
    EXPECT_NE(errNo, DRM_ERR_OK);
    contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_OH_MediaKeySystemDestroyAbNormal2_072, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySystem) {
        MediaKeySystemObject *systemObject = reinterpret_cast<MediaKeySystemObject *>(mediaKeySystem);
        systemObject->systemImpl_->~MediaKeySystemImpl();
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    DRM_CertificateStatus certStatus = CERT_STATUS_INVALID;
    errNo = OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, &certStatus);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    MediaKeySession *OH_MediaKeySession2 = nullptr;
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &OH_MediaKeySession2);
    EXPECT_EQ(OH_MediaKeySession2, nullptr);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_OfflineMediakeyIdArray offlineMediaKeyIds;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyIds(mediaKeySystem, &offlineMediaKeyIds);
    DRM_OfflineMediaKeyStatus OfflineMediaKeyStatus = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    errNo = OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, (uint8_t *)&OfflineMediaKeyStatus, 1,
        &OfflineMediaKeyStatus);
    errNo = OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, (uint8_t *)&OfflineMediaKeyStatus, 1);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySessionDestroyAbNormal_073, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        sessionObject->sessionImpl_->~MediaKeySessionImpl();
    }
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_ONLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), (char *)"video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    memcpy_s(info.optionName[0], sizeof("optionalDataName"), (char *)"optionalDataName", sizeof("optionalDataName"));
    memcpy_s(info.optionData[0], sizeof("optionalDataValue"), (char *)"optionalDataValue", sizeof("optionalDataValue"));
    info.optionsCount = 1;
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySessionDestroyAbNormal2_074, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        sessionObject->sessionImpl_->~MediaKeySessionImpl();
    }
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = { 0 };
    int32_t testKeySessionResponseLen = 12288;
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySession_DestroyAbNormal3_075, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        sessionObject->sessionImpl_->~MediaKeySessionImpl();
    }
    DRM_MediaKeyStatus mediaKeyStatus;
    errNo = OH_MediaKeySession_CheckMediaKeyStatus(mediaKeySession, &mediaKeyStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ClearMediaKeys(mediaKeySession);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, (uint8_t *)GetUuid(),
        11, releaseRequest, &releaseRequestLen); // 11:len
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_MediaKeySessionDestroyAbNormal4_076, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        sessionObject->sessionImpl_->~MediaKeySessionImpl();
    }
    unsigned char testKeyReleaseResponse[50] = OFFRESPONSE;
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, (uint8_t *)GetUuid(),
        11, testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse))); // 11:len
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, (unsigned char *)GetUuid(), 1);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_ContentProtectionLevel sessionContentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySession_GetContentProtectionLevel(mediaKeySession, &sessionContentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
    bool requireSecureDecoder;
    errNo = OH_MediaKeySession_RequireSecureDecoderModule(mediaKeySession, "video/mp4", &requireSecureDecoder);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetCallbackNormal_077, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);} else {
        KeySystemResponseLen = 50;}
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data, (uint32_t)mediaKeyRequest.dataLen,
            testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);} else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetCallbackNormal2_078, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[2] = {0x07, 0x22};
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)(sizeof(testKeySessionResponse)), onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessMediaKeyResponseAbNormal_079, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data, (uint32_t)mediaKeyRequest.dataLen,
            testKeySessionResponse, &testKeySessionResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        testKeySessionResponseLen = 50;
    }errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, (uint8_t *)("onlineMediaKeyId"),
        2, releaseRequest, &releaseRequestLen); // 2:len
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ProcessOfflineReleaseResponseAbNormal_080, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(LICENSE_URL, mediaKeyRequest.data,
            (uint32_t)mediaKeyRequest.dataLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, KeySystemResponse,
        KeySystemResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char testKeyReleaseResponse[2] = {0x33, 0x22};
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        testKeyReleaseResponse, (int32_t)(sizeof(testKeyReleaseResponse)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
}

static void filltest(MediaKeySystem *mediaKeySystem, MediaKeySession *mediaKeySession)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, (uint8_t *)TESTKEYSESSIONRESPONSE,
        (int32_t)(sizeof(TESTKEYSESSIONRESPONSE)), onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char releaseRequest[8192] = { 0 }; // 8192:request len
    int32_t releaseRequestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySession_GenerateOfflineReleaseRequest(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        releaseRequest, &releaseRequestLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ProcessOfflineReleaseResponse(mediaKeySession, onlineMediaKeyId, onlineMediaKeyIdLen,
        (uint8_t *)TESTKEYRELEASERESPONSE, (int32_t)(sizeof(TESTKEYRELEASERESPONSE)));
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_RestoreOfflineMediaKeys(mediaKeySession, (unsigned char *)"onlineMediaKeyId", 1);
    EXPECT_NE(errNo, DRM_ERR_OK);
}
HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ClearMediaKeysAbNormal_081, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_ClearMediaKeys(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    // mediakeysession
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    filltest(mediaKeySystem, mediaKeySession);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    sleep(1);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_CreateMediaKeySessionAbNormal_082, TestSize.Level0)
{
    MediaKeySystem *mediaKeySystem = nullptr;
    Drm_ErrCode errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySystem) {
        MediaKeySystemObject *systemObject = reinterpret_cast<MediaKeySystemObject *>(mediaKeySystem);
        IMediaKeySessionService::ContentProtectionLevel securityLevel =
            IMediaKeySessionService::CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
        OHOS::sptr<MediaKeySessionImpl> keySessionImpl = nullptr;
        systemObject->systemImpl_->~MediaKeySystemImpl();
        systemObject->systemImpl_->CreateMediaKeySession(securityLevel, &keySessionImpl);
        keySessionImpl = nullptr;
        MediaKeySystemCallback *allback = new MediaKeySystemCallback();
        allback->~MediaKeySystemCallback();
        OHOS::sptr<MediaKeySystemFactoryImpl> fatory = MediaKeySystemFactoryImpl::GetInstance();
        fatory->Init();
    }
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_NE(errNo, DRM_ERR_OK);
    MediaKeySystem *mediaKeySystem2 = nullptr;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem2);
    EXPECT_NE(mediaKeySystem2, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem2);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SessionImplAbNormal_083, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[128] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t onlineMediaKeyIdLen = 128; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[12288] = OFFRESPONSE;
    int32_t testKeySessionResponseLen = 50;
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)testKeySessionResponseLen, onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        MediaKeySessionServiceCallback *Object = new MediaKeySessionServiceCallback(sessionObject->sessionImpl_);
        std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable = { { { 0x01 },
            MEDIA_KEY_SESSION_KEY_STATUS_USABLE } };
        bool hasNewGoodLicense = false;
        Object->SendEventKeyChanged(statusTable, hasNewGoodLicense);
    }
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

static void killclearplay(MediaKeySystem *mediaKeySystem, MediaKeySession *mediaKeySession)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    std::vector<uint8_t> licenseIdVec = { 0x01 };
    std::vector<uint8_t> ReleaseRequest = { 0x01 };
    IMediaKeySessionService::ContentProtectionLevel securityLevel;
    system(GetDrmPlugin());
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        uint32_t result = sessionObject->sessionImpl_->GenerateOfflineReleaseRequest(licenseIdVec, ReleaseRequest);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->ProcessOfflineReleaseResponse(licenseIdVec, ReleaseRequest);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->GetContentProtectionLevel(&securityLevel);
        EXPECT_NE(result, DRM_ERR_OK);
        std::map<std::string, std::string> licenseStatus2;
        result = sessionObject->sessionImpl_->CheckMediaKeyStatus(licenseStatus2);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->RestoreOfflineMediaKeys(licenseIdVec);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->ClearMediaKeys();
        EXPECT_NE(result, DRM_ERR_OK);
        std::string mimeType;
        bool status;
        result = sessionObject->sessionImpl_->RequireSecureDecoderModule(mimeType, &status);
        EXPECT_NE(result, DRM_ERR_OK);
    }
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

static void killclearplay2(MediaKeySystem *mediaKeySystem, MediaKeySession *mediaKeySession)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    bool supported = OH_MediaKeySystem_IsSupported(GetUuid());
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), "video/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    errNo =
        OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "testConfigurationString");
    EXPECT_NE(errNo, DRM_ERR_OK);
    char value[32];
    int32_t valueLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char configByteArray[32];
    int32_t byteArrayLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", configByteArray,
        &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_Statistics statistics;
    errNo = OH_MediaKeySystem_GetStatistics(mediaKeySystem, &statistics);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_SetCallbackWithObject_084, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_SetCallback(mediaKeySystem, &TestSystemEventCallBackWithObj);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback callback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &callback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    OH_MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBackWithObj,
        &TestSessoinKeyChangeCallBackWithObj };
    errNo = OH_MediaKeySession_SetCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    filldata(&info);
    errNo = OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char onlineMediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    unsigned char testKeySessionResponse[2] = {0x07, 0x22};
    int32_t onlineMediaKeyIdLen = 64; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    errNo = OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, testKeySessionResponse,
        (int32_t)(sizeof(testKeySessionResponse)), onlineMediaKeyId, &onlineMediaKeyIdLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_KillClearPlayHostAbNormal1, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    killclearplay(mediaKeySystem, mediaKeySession);
    killclearplay2(mediaKeySystem, mediaKeySession);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_CertificateStatus certStatus = CERT_STATUS_INVALID;
    errNo = OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, &certStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    sleep(5);
}

static void killDrm_Service1(MediaKeySystem *mediaKeySystem, MediaKeySession *mediaKeySession)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    std::vector<uint8_t> licenseIdVec = { 0x01 };
    std::vector<uint8_t> ReleaseRequest = { 0x01 };
    IMediaKeySessionService::ContentProtectionLevel securityLevel;
    system("killall -9 drm_service");
    if (mediaKeySession) {
        MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
        uint32_t result = sessionObject->sessionImpl_->GenerateOfflineReleaseRequest(licenseIdVec, ReleaseRequest);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->ProcessOfflineReleaseResponse(licenseIdVec, ReleaseRequest);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->GetContentProtectionLevel(&securityLevel);
        EXPECT_NE(result, DRM_ERR_OK);
        std::map<std::string, std::string> licenseStatus2;
        result = sessionObject->sessionImpl_->CheckMediaKeyStatus(licenseStatus2);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->RestoreOfflineMediaKeys(licenseIdVec);
        EXPECT_NE(result, DRM_ERR_OK);
        result = sessionObject->sessionImpl_->ClearMediaKeys();
        EXPECT_NE(result, DRM_ERR_OK);
        std::string mimeType;
        bool status;
        result = sessionObject->sessionImpl_->RequireSecureDecoderModule(mimeType, &status);
        EXPECT_NE(result, DRM_ERR_OK);
    }
    errNo = OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    MediaKeySession_Callback sessionCallback = { &TestSessoinEventCallBack, &TestSessoinKeyChangeCallBack };
    errNo = OH_MediaKeySession_SetMediaKeySessionCallback(mediaKeySession, &sessionCallback);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

static void killDrm_Service2(MediaKeySystem *mediaKeySystem, MediaKeySession *mediaKeySession)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    bool supported = OH_MediaKeySystem_IsSupported(GetUuid());
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported2(GetUuid(), "video/mp4");
    EXPECT_EQ(supported, false);
    supported = OH_MediaKeySystem_IsSupported3(GetUuid(), "video/mp4", CONTENT_PROTECTION_LEVEL_HW_CRYPTO);
    EXPECT_EQ(supported, false);
    errNo = OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, "testConfigurationString", "gezhegezhegezhe");
    EXPECT_NE(errNo, DRM_ERR_OK);
    char value[32];
    int32_t valueLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "testConfigurationString", value, valueLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char testArray[5] = {1, 2, 3, 4, 5};
    errNo = OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", testArray,
        sizeof(testArray));
    EXPECT_NE(errNo, DRM_ERR_OK);
    unsigned char configByteArray[32];
    int32_t byteArrayLen = 32;
    errNo = OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, "testConfigurationByteArray", configByteArray,
        &byteArrayLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_Statistics statistics;
    errNo = OH_MediaKeySystem_GetStatistics(mediaKeySystem, &statistics);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    errNo = OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    EXPECT_NE(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_KillDrmServiceAbNormal, TestSize.Level0)
{
    Drm_ErrCode errNo = DRM_ERR_UNKNOWN;
    MediaKeySystem *mediaKeySystem = nullptr;
    MediaKeySession *mediaKeySession = nullptr;
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_SW_CRYPTO;
    errNo = OH_MediaKeySystem_Create(GetUuid(), &mediaKeySystem);
    EXPECT_NE(mediaKeySystem, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    unsigned char request[8192] = { 0 }; // 8192:request len
    int32_t requestLen = 8192; // 8192:request len
    char defaultUrl[2048] = { 0 }; // 2048:url len
    int32_t defaultUrlLen = 2048; // 2048:url len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    unsigned char KeySystemResponse[12288] = OFFRESPONSE;
    int32_t KeySystemResponseLen = 12288;
    if (g_isWisePlay) {
        int rett = HttpPost(PROVISION_URL, request, requestLen, KeySystemResponse, &KeySystemResponseLen, 10);
        EXPECT_EQ(rett, 0);
    } else {
        KeySystemResponseLen = 50;
    }
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(mediaKeySession, nullptr);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    killDrm_Service1(mediaKeySystem, mediaKeySession);
    killDrm_Service2(mediaKeySystem, mediaKeySession);
    requestLen = 8192; // 8192:request len
    errNo = OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl,
        defaultUrlLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, KeySystemResponse, KeySystemResponseLen);
    EXPECT_NE(errNo, DRM_ERR_OK);
    DRM_CertificateStatus certStatus = CERT_STATUS_INVALID;
    errNo = OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, &certStatus);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &contentProtectionLevel, &mediaKeySession);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySession_Destroy(mediaKeySession);
    EXPECT_NE(errNo, DRM_ERR_OK);
    errNo = OH_MediaKeySystem_Destroy(mediaKeySystem);
    EXPECT_NE(errNo, DRM_ERR_OK);
    sleep(5);
}
} // DrmStandard
} // OHOS