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

#ifndef DRM_DFX_H
#define DRM_DFX_H

#ifdef ENABLE_DRM_SYSEVENT_CONTROL

#include <list>
#include <string>
#include <refbase.h>
#include "drm_dfx_utils.h"
#include "nocopyable.h"
#include "nlohmann/json.hpp"
#include "meta/meta.h"
#include "hisysevent.h"
#include "hitrace/tracechain.h"
#include <chrono>
#endif

namespace OHOS {
namespace DrmStandard {
using namespace OHOS::HiviewDFX;

#ifdef ENABLE_DRM_SYSEVENT_CONTROL
struct DrmServiveInfo {
    std::string module;
    uint32_t currentTime;
    std::string serviceName;
    std::string action;
    uint32_t memoryUsage;
};

struct DrmLicenseInfo {
    std::string module;
    uint32_t currentTime;
    std::string appName;
    std::string instanceId;
    std::string drmName;
    std::string drmUuid;
    std::string clientVersion;
    std::string licenseType;
    uint32_t generationDuration;
    std::string generationResult;
    uint32_t processDuration;
    std::string processResult;
};

struct DrmCertificateInfo {
    std::string module;
    uint32_t currentTime;
    std::string appName;
    std::string instanceId;
    std::string drmName;
    std::string drmUuid;
    std::string clientVersion;
    uint32_t generationDuration;
    std::string generationResult;
    uint32_t processDuration;
    std::string processResult;
    uint32_t callServerTime;
    uint32_t serverCostDuration;
    std::string serverResult;
};

struct DrmFaultInfo {
    std::string module;
    std::string appName;
    std::string instanceId;
    int32_t errorCode;
    std::string errorMesg;
    std::string extraMesg;
};

struct DrmDecryptionInfo {
    std::string module;
    std::string appName;
    std::string instanceId;
    int32_t errorCode;
    std::string errorMesg;
    std::string decryptAlgo;
    std::string decryptKeyid;
    std::string decryptIv;
};

class DrmEvent {
public:
    static DrmEvent& GetInstance();

    void DrmStatisicsEventWrite(OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<Media::Meta>>>>& infoMap);
    void StatisicsHiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::EventType type,
        const std::vector<std::string>& infoArr);
    void ParseOneEvent(const std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>> &listPair,
        nlohmann::json& metaInfoJson);
    void CollectReportMediaInfo(uint64_t instanceId);
    int32_t AppendMediaInfo(const std::shared_ptr<Media::Meta>& meta, uint64_t instanceId);
    int32_t CreateMediaInfo(int32_t uid, uint64_t instanceId);
    int32_t ReportMediaInfo(uint64_t instanceId);
    int32_t StatisticsEventReport();
    void WriteServiceEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type, DrmServiveInfo &info);
    void WriteLicenseEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type, DrmLicenseInfo &info);
    void WriteCertificateEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        DrmCertificateInfo &info);
    void WriteFaultEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type, DrmFaultInfo &info);
    void WriteDecryptionEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
        DrmDecryptionInfo &info);
};
#endif

__attribute__((visibility("default"))) void ReportServiceBehaviorEvent(std::string serviceName, std::string action);
__attribute__((visibility("default"))) void ReportLicenseBehaviorEvent(StatisticsInfo statisticsInfo,
    std::string licenseType, uint32_t generationDuration, std::string generationResult, uint32_t processDuration,
    std::string processResult);
__attribute__((visibility("default"))) void ReportCertificateBehaviorEvent(StatisticsInfo statisticsInfo,
    uint32_t generationDuration, std::string generationResult, uint32_t processDuration, std::string processResult,
    uint32_t callServerTime, uint32_t serverCostDuration, std::string serverResult);
__attribute__((visibility("default"))) void ReportFaultEvent(uint32_t errorCode, std::string errorMesg,
    std::string extraMesg);
__attribute__((visibility("default"))) void ReportDecryptionFaultEvent(int32_t errorCode, std::string errorMesg,
    std::string decryptAlgo, std::string decryptKeyid, std::string decryptIv);
} // namespace DrmStandard
} // namespace OHOS
#endif // DRM_DFX_H