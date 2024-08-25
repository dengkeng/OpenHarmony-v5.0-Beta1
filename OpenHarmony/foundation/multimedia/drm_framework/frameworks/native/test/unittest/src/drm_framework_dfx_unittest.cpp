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
#include <string>
#include "cstdio"
#include "cstdlib"
#include "drm_dfx.h"
#include "drm_dfx_utils.h"
#include <securec.h>
#include "native_drm_common.h"
#include "native_drm_err.h"
#include "gmock/gmock.h"
#include "meta/meta.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"
#include "drm_framework_unittest.h"
#include "http.h"

#define DRM_SAMPLE_CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
    do {                                                         \
        if (!(cond)) {                                            \
            printf(fmt, ##__VA_ARGS__);                          \
            return ret;                                          \
        }                                                        \
    } while (0)

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
#define LICENSE_URL "http://192.168.50.59:9528/getLicense"
#define PROVISION_URL "http://192.168.50.59:9528/getProvision"


using namespace testing::ext;
using namespace std;


namespace OHOS {
namespace DrmStandard {

HWTEST_F(DrmFrameworkUnitTest, Drm_Unittest_GetMediaKeySystems, TestSize.Level0)
{
    uint32_t count = 10;
    DRM_MediaKeySystemDescription infos[10];
    memset_s(infos, sizeof(infos), 0, sizeof(infos));
    Drm_ErrCode errNo = OH_MediaKeySystem_GetMediaKeySystems(infos, &count);
    EXPECT_EQ(errNo, 0);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_Unittest_GetMediaKeySystemsAbnorm, TestSize.Level0)
{
    uint32_t count = 10;
    Drm_ErrCode errNo = OH_MediaKeySystem_GetMediaKeySystems(nullptr, &count);
    EXPECT_NE(errNo, 0);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_Unittest_GetMediaKeySystemsAbnorm1, TestSize.Level0)
{
    DRM_MediaKeySystemDescription infos[10];
    memset_s(infos, sizeof(infos), 0, sizeof(infos));
    Drm_ErrCode errNo = OH_MediaKeySystem_GetMediaKeySystems(infos, nullptr);
    EXPECT_NE(errNo, 0);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_Unittest_GetMediaKeySystemsAbnorm2, TestSize.Level0)
{
    uint32_t count = 0;
    DRM_MediaKeySystemDescription infos[10];
    memset_s(infos, sizeof(infos), 0, sizeof(infos));
    Drm_ErrCode errNo = OH_MediaKeySystem_GetMediaKeySystems(infos, &count);
    EXPECT_NE(errNo, 0);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ReportFaultEvent, TestSize.Level0)
{
    uint32_t errorCode = 0;
    std::string errorMesg = "GenerateMediaKeyRequest failed";
    std::string extraMesg = "";
    ReportFaultEvent(errorCode, errorMesg, extraMesg);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ReportDecryptionFaultEvent, TestSize.Level0)
{
    uint32_t errorCode = 0;
    std::string errorMesg = "Decryption failed";
    std::string decryptAlgo = "decryptAlgo";
    std::string decryptKeyid = "decryptKeyid";
    std::string decryptIv = "decryptIv";
    ReportDecryptionFaultEvent(errorCode, errorMesg, decryptAlgo, decryptKeyid, decryptIv);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ReportServiceBehaviorEvent, TestSize.Level0)
{
    std::string serviceName = "DRM_OEM_SERVICE";
    std::string action = "start";
    ReportServiceBehaviorEvent(serviceName, action);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ReportLicenseBehaviorEvent, TestSize.Level0)
{
    std::string mediaKeyType = "keytype";
    std::string generationResult = "success";
    std::string processResult = "success";
    uint32_t generationDuration = 10;
    uint32_t processDuration = 1;
    struct StatisticsInfo statisticsInfo = {
        "123123",
        "clearplay",
        "vendor",
        "clearplay_v1",
        "bundleName",
    };
    ReportLicenseBehaviorEvent(statisticsInfo, mediaKeyType, generationDuration, generationResult,
    processDuration, processResult);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_ReportCertificateBehaviorEvent, TestSize.Level0)
{
    std::string mediaKeyType = "keytype";
    std::string generationResult = "success";
    std::string processResult = "success";
    uint32_t generationDuration = 10;
    uint32_t processDuration = 1;
    uint32_t callServerTime = 1;
    uint32_t serverCostDuration = 19;
    std::string serverResult = "serverResult";
    struct StatisticsInfo statisticsInfo = {
        "123123",
        "clearplay",
        "vendor",
        "clearplay_v1",
        "bundleName",
    };
    ReportCertificateBehaviorEvent(statisticsInfo, generationDuration, generationResult, processDuration,
        "GenerateKeySystemRequest failed", callServerTime, serverCostDuration, serverResult);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_HiSysWriteStatistic, TestSize.Level0)
{
    int32_t errNo = DRM_ERR_UNKNOWN;
    int32_t uid = 324442;
    int32_t instanceId = 324442;
    errNo = DrmEvent::GetInstance().CreateMediaInfo(uid, instanceId);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    std::shared_ptr<OHOS::Media::Meta> meta = std::make_shared<Media::Meta>();
    meta->SetData(Media::Tag::DRM_ERROR_MESG, "errMessage");
    errNo = DrmEvent::GetInstance().AppendMediaInfo(meta, instanceId);
    EXPECT_EQ(errNo, DRM_ERR_OK);
    errNo = DrmEvent::GetInstance().ReportMediaInfo(instanceId);
    EXPECT_EQ(errNo, DRM_ERR_OK);
}

HWTEST_F(DrmFrameworkUnitTest, Drm_unittest_HiSysWriteStatisticAbNormal, TestSize.Level0)
{
    int32_t errNo = DRM_ERR_UNKNOWN;
    int32_t uid = 324442;
    int32_t instanceId = 324442;
    DrmEvent::GetInstance().CreateMediaInfo(uid, instanceId);
    std::shared_ptr<OHOS::Media::Meta> meta = std::make_shared<Media::Meta>();
    errNo = DrmEvent::GetInstance().AppendMediaInfo(meta, instanceId);
    EXPECT_NE(errNo, DRM_ERR_OK);
}
} // DrmStandard
} // OHOS
