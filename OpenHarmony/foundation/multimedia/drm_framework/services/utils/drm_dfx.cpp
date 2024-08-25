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

#include "drm_dfx.h"
#include "drm_dfx_utils.h"
#include <unistd.h>
#include "drm_log.h"
#include "dump_usage.h"
#include "nlohmann/json.hpp"
#include "native_drm_err.h"
#include "securec.h"
#include "ipc_skeleton.h"
#include "hitrace/tracechain.h"
#include "meta/any.h"
#include <cstdint>

namespace {
    constexpr int64_t HOURS_BETWEEN_REPORTS = 4;
    constexpr int64_t MAX_MAP_SIZE = 100;
    std::mutex collectMut_;
    std::mutex reportMut_;
    std::chrono::system_clock::time_point currentTime_ = std::chrono::system_clock::now();
    std::map<uint64_t, int32_t> idMap_;
    std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>>>> mediaInfoMap_;
    std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>>>> reportMediaInfoMap_;
    bool g_reachMaxMapSize {false};
}
namespace OHOS {
namespace DrmStandard {
using namespace OHOS::HiviewDFX;
using json = nlohmann::json;

#ifdef ENABLE_DRM_SYSEVENT_CONTROL

DrmEvent& DrmEvent::GetInstance()
{
    static DrmEvent instance;
    return instance;
}

void DrmEvent::DrmStatisicsEventWrite(OHOS::HiviewDFX::HiSysEvent::EventType type,
    const std::map<int32_t, std::list<std::pair<uint64_t, std::shared_ptr<Media::Meta>>>>& infoMap)
{
    DRM_INFO_LOG("DrmEvent::DrmStatisicsEventWrite.");
    if (infoMap.empty()) {
        DRM_INFO_LOG("DrmEvent infoMap is empty.");
        return;
    }
    std::vector<std::string> infoArr;
    for (const auto& kv : infoMap) {
        json jsonArray;
        json eventInfoJson;
        json drmEvents;
        for (const auto& listPair : kv.second) {
            json metaInfoJson;
            ParseOneEvent(listPair, metaInfoJson);
            drmEvents.push_back(metaInfoJson);
        }
        eventInfoJson["appName"] = GetClientBundleName(kv.first);
        eventInfoJson["drmStatistics"] = drmEvents;
        jsonArray.push_back(eventInfoJson);
        infoArr.push_back(jsonArray.dump());
    }
    StatisicsHiSysEventWrite(type, infoArr);
}

void DrmEvent::ParseOneEvent(const std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>> &listPair,
    json& metaInfoJson)
{
    for (auto it = listPair.second->begin(); it != listPair.second->end(); ++it) {
        Media::Any valueType = OHOS::Media::GetDefaultAnyValue(it->first);
        if (Media::Any::IsSameTypeWith<int32_t>(valueType)) {
            int32_t intVal;
            if (listPair.second->GetData(it->first, intVal)) {
                metaInfoJson[it->first] = std::to_string(intVal);
            }
        } else if (Media::Any::IsSameTypeWith<uint32_t>(valueType)) {
            uint32_t uintVal;
            if (listPair.second->GetData(it->first, uintVal)) {
                metaInfoJson[it->first] = std::to_string(uintVal);
            }
        } else if (Media::Any::IsSameTypeWith<std::string>(valueType)) {
            metaInfoJson[it->first] = Media::AnyCast<std::string>(it->second);
        } else if (Media::Any::IsSameTypeWith<int8_t>(valueType)) {
            int8_t intVal;
            if (listPair.second->GetData(it->first, intVal)) {
                metaInfoJson[it->first] = std::to_string(intVal);
            }
        } else if (Media::Any::IsSameTypeWith<bool>(valueType)) {
            bool isTrue;
            if (listPair.second->GetData(it->first, isTrue)) {
                metaInfoJson[it->first] = isTrue ? "true" : "false";
            }
        } else {
            DRM_INFO_LOG("not found type matched with it->first: %{public}s.", it->first.c_str());
        }
    }
}

void DrmEvent::StatisicsHiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::EventType type,
    const std::vector<std::string>& infoArr)
{
    DRM_INFO_LOG("DrmEvent::StatisicsHiSysEventWrite.");
    std::string eventName = "DRM_STATISTICS";
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
                    "EVENTS", infoArr);
}

int32_t DrmEvent::AppendMediaInfo(const std::shared_ptr<Media::Meta>& meta, uint64_t instanceId)
{
    DRM_INFO_LOG("AppendMediaInfo.");
    if (meta == nullptr || meta->Empty()) {
        DRM_INFO_LOG("Insert meta is empty.");
        return DRM_ERR_INVALID_STATE;
    }

    std::lock_guard<std::mutex> lock(collectMut_);
    auto idMapIt = idMap_.find(instanceId);
    if (idMapIt == idMap_.end()) {
        DRM_INFO_LOG("Not found instanceId.");
        return DRM_ERR_INVALID_VAL;
    }
    int32_t uid = idMapIt->second;
    auto it = mediaInfoMap_.find(uid);
    if (it == mediaInfoMap_.end()) {
        DRM_INFO_LOG("Not found uid.");
        return DRM_ERR_INVALID_STATE;
    }
    auto& instanceList = it->second;
    for (const auto& instancePair : instanceList) {
        if (instancePair.first == instanceId) {
            auto arg = meta->begin();
            while (arg != meta->end()) {
                instancePair.second->SetData(arg->first, arg->second);
                ++arg;
            }
            break;
        }
    }
    return DRM_ERR_OK;
}

int32_t DrmEvent::CreateMediaInfo(int32_t uid, uint64_t instanceId)
{
    DRM_INFO_LOG("CreateMediaInfo.");
    std::lock_guard<std::mutex> lock(collectMut_);
    DRM_INFO_LOG("CreateMediaInfo uid is: %{public}" PRId32 " instanceId is: %{public}." PRIu64, uid, instanceId);
    auto instanceIdMap = idMap_.find(instanceId);
    if (instanceIdMap != idMap_.end()) {
        DRM_INFO_LOG("instanceId already exists.");
        return DRM_ERR_INVALID_VAL;
    } else {
        idMap_[instanceId] = uid;
    }

    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    std::pair<uint64_t, std::shared_ptr<Media::Meta>> metaAppIdPair(instanceId, meta);
    auto it = mediaInfoMap_.find(uid);
    if (it != mediaInfoMap_.end()) {
        it->second.push_back(metaAppIdPair);
    } else {
        mediaInfoMap_[uid].push_back(metaAppIdPair);
    }
    return DRM_ERR_OK;
}

int32_t DrmEvent::ReportMediaInfo(uint64_t instanceId)
{
    auto currentTime = std::chrono::system_clock::now();
    auto diff = currentTime - currentTime_;
    auto hour = std::chrono::duration_cast<std::chrono::hours>(diff).count();
    CollectReportMediaInfo(instanceId);
    std::lock_guard<std::mutex> lock(reportMut_);
    if (g_reachMaxMapSize) {
        DRM_INFO_LOG("Event data size exceeds 100, report the event");
        g_reachMaxMapSize = false;
        return StatisticsEventReport();
    }
    if (hour >= HOURS_BETWEEN_REPORTS) {
        DRM_INFO_LOG("Over 4 hours, report the event.");
        return StatisticsEventReport();
    }
    return DRM_ERR_OK;
}

void DrmEvent::CollectReportMediaInfo(uint64_t instanceId)
{
    int32_t uid;
    std::pair<uint64_t, std::shared_ptr<OHOS::Media::Meta>> metaAppIdPair;
    {
        std::lock_guard<std::mutex> lock(collectMut_);
        DRM_INFO_LOG("CollectReportMediaInfo.");
        auto idMapIt = idMap_.find(instanceId);
        if (idMapIt == idMap_.end()) {
            DRM_INFO_LOG("Not found instanceId in idMap, instanceId is : %{public}." PRIu64, instanceId);
            return;
        }
        uid = idMapIt->second;
        idMap_.erase(idMapIt);
        auto uidToMediaInfo = mediaInfoMap_.find(uid);
        if (uidToMediaInfo == mediaInfoMap_.end()) {
            return;
        }
        auto& instanceList = uidToMediaInfo->second;
        for (const auto& instancePair : instanceList) {
            if (instancePair.first == instanceId) {
                metaAppIdPair = instancePair;
                instanceList.remove(instancePair);
                break;
            }
        }
    }

    std::lock_guard<std::mutex> lock(reportMut_);
    auto reportUidToMediaInfo = reportMediaInfoMap_.find(uid);
    if (reportUidToMediaInfo != reportMediaInfoMap_.end()) {
        reportUidToMediaInfo->second.push_back(metaAppIdPair);
    } else {
        reportMediaInfoMap_[uid].push_back(metaAppIdPair);
    }
    g_reachMaxMapSize = (reportMediaInfoMap_.size() >= MAX_MAP_SIZE);
}

int32_t DrmEvent::StatisticsEventReport()
{
    DRM_INFO_LOG("StatisticsEventReport.");
    if (reportMediaInfoMap_.empty()) {
        DRM_INFO_LOG("reportMediaInfoMap_ is empty, can't report.");
        return DRM_ERR_INVALID_STATE;
    }

    DrmStatisicsEventWrite(OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC, reportMediaInfoMap_);
    auto currentTime = std::chrono::system_clock::now();
    currentTime_ = currentTime;
    reportMediaInfoMap_.clear();
    return DRM_ERR_OK;
}

void DrmEvent::WriteServiceEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
    DrmServiveInfo &info)
{
    int32_t res = DRM_ERR_OK;
    res = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
        "MODULE", info.module,
        "TIME", info.currentTime,
        "SERVICE_NAME", info.serviceName,
        "ACTION", info.action,
        "MEMORY", info.memoryUsage);
    if (res != DRM_ERR_OK) {
        DRM_ERR_LOG("EventWrite failed, res = %d", res);
    } else {
        DRM_INFO_LOG("EventWrite success");
    }
}

void DrmEvent::WriteLicenseEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
    DrmLicenseInfo &info)
{
    int32_t res = DRM_ERR_OK;
    res = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
        "MODULE", info.module,
        "TIME", info.currentTime,
        "APP_NAME", info.appName,
        "INSTANCE_ID", info.instanceId,
        "DRM_NAME", info.drmName,
        "DRM_UUID", info.drmUuid,
        "CLIENT_VERSION", info.clientVersion,
        "LICENSE_TYPE", info.licenseType,
        "GENERATION_DURATION", info.generationDuration,
        "GENERATION_RESULT", info.generationResult,
        "PROCESS_DURATION", info.processDuration,
        "PROCESS_RESULT", info.processResult);
    if (res != DRM_ERR_OK) {
        DRM_ERR_LOG("EventWrite failed, res = %d", res);
    } else {
        DRM_INFO_LOG("EventWrite success");
    }
}

void DrmEvent::WriteCertificateEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
    DrmCertificateInfo &info)
{
    int32_t res = DRM_ERR_OK;
    res = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
        "MODULE", info.module,
        "TIME", info.currentTime,
        "APP_NAME", info.appName,
        "INSTANCE_ID", info.instanceId,
        "DRM_NAME", info.drmName,
        "DRM_UUID", info.drmUuid,
        "CLIENT_VERSION", info.clientVersion,
        "GENERATION_DURATION", info.generationDuration,
        "GENERATION_RESULT", info.generationResult,
        "PROCESS_DURATION", info.processDuration,
        "PROCESS_RESULT", info.processResult,
        "CALL_SERVER_TIME", info.callServerTime,
        "SERVER_COST_DURATION", info.serverCostDuration,
        "SERVER_RESULT", info.serverResult);
    if (res != DRM_ERR_OK) {
        DRM_ERR_LOG("EventWrite failed, res = %d", res);
    } else {
        DRM_INFO_LOG("EventWrite success");
    }
}

void DrmEvent::WriteFaultEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type, DrmFaultInfo &info)
{
    int32_t res = DRM_ERR_OK;
    res = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
        "MODULE", info.module,
        "APP_NAME", info.appName,
        "INSTANCE_ID", info.instanceId,
        "ERROR_CODE", info.errorCode,
        "ERROR_MESG", info.errorMesg,
        "EXTRA_MESG", info.extraMesg);
    if (res != DRM_ERR_OK) {
        DRM_ERR_LOG("EventWrite failed, res = %d", res);
    } else {
        DRM_INFO_LOG("EventWrite success");
    }
}

void DrmEvent::WriteDecryptionEvent(std::string eventName, OHOS::HiviewDFX::HiSysEvent::EventType type,
    DrmDecryptionInfo &info)
{
    int32_t res = DRM_ERR_OK;

    res = HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA, eventName, type,
        "MODULE", info.module,
        "APP_NAME", info.appName,
        "INSTANCE_ID", info.instanceId,
        "ERROR_CODE", info.errorCode,
        "ERROR_MESG", info.errorMesg,
        "DECRYPT_ALGO", info.decryptAlgo,
        "DECRYPT_KEYID", info.decryptKeyid,
        "DECRYPT_IV", info.decryptIv);
    if (res != DRM_ERR_OK) {
        DRM_ERR_LOG("EventWrite failed, res = %d", res);
    } else {
        DRM_INFO_LOG("EventWrite success");
    }
}

void ReportServiceBehaviorEvent(std::string serviceName, std::string action)
{
    DrmEvent event;
    OHOS::HiviewDFX::DumpUsage dumpUse;
    uint32_t memoryUsage = dumpUse.GetPss(getpid());
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    struct DrmServiveInfo drmServiveInfo = {
        "DRM_SERVICE",
        currentTime,
        serviceName,
        action,
        memoryUsage,
    };
    event.WriteServiceEvent("DRM_SERVICE_INFO", OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR, drmServiveInfo);
}

void ReportLicenseBehaviorEvent(StatisticsInfo statisticsInfo, std::string licenseType, uint32_t generationDuration,
    std::string generationResult, uint32_t processDuration, std::string processResult)
{
    DrmEvent event;
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    struct DrmLicenseInfo drmLicenseInfo = {
        "DRM_SERVICE",
        currentTime,
        GetClientBundleName(IPCSkeleton::GetCallingUid()),
        std::to_string(HiTraceChain::GetId().GetChainId()),
        statisticsInfo.pluginName,
        statisticsInfo.pluginUuid,
        statisticsInfo.versionName,
        licenseType,
        generationDuration,
        generationResult,
        processDuration,
        processResult,
    };
    event.WriteLicenseEvent("DRM_LICENSE_DOWNLOAD_INFO", OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        drmLicenseInfo);
}

void ReportCertificateBehaviorEvent(StatisticsInfo statisticsInfo, uint32_t generationDuration,
    std::string generationResult, uint32_t processDuration, std::string processResult, uint32_t callServerTime,
    uint32_t serverCostDuration, std::string serverResult)
{
    DrmEvent event;
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    struct DrmCertificateInfo DrmCertificateInfo = {
        "DRM_SERVICE",
        currentTime,
        GetClientBundleName(IPCSkeleton::GetCallingUid()),
        std::to_string(HiTraceChain::GetId().GetChainId()),
        statisticsInfo.pluginName,
        statisticsInfo.pluginUuid,
        statisticsInfo.versionName,
        generationDuration,
        generationResult,
        processDuration,
        processResult,
        callServerTime,
        serverCostDuration,
        serverResult,
    };
    event.WriteCertificateEvent("DRM_CERTIFICATE_DOWNLOWD_INFO", OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        DrmCertificateInfo);
}

void ReportFaultEvent(uint32_t errorCode, std::string errorMesg, std::string extraMesg)
{
    DrmEvent event;
    struct DrmFaultInfo drmFaultInfo = {
        "DRM_SERVICE",
        GetClientBundleName(IPCSkeleton::GetCallingUid()),
        std::to_string(HiTraceChain::GetId().GetChainId()),
        errorCode,
        errorMesg,
        extraMesg,
    };
    event.WriteFaultEvent("DRM_COMMON_FAILURE", OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, drmFaultInfo);
}

void ReportDecryptionFaultEvent(int32_t errorCode, std::string errorMesg, std::string decryptAlgo,
    std::string decryptKeyid, std::string decryptIv)
{
    DrmEvent event;
    struct DrmDecryptionInfo drmDecryptionInfo = {
        "DRM_SERVICE",
        GetClientBundleName(IPCSkeleton::GetCallingUid()),
        std::to_string(HiTraceChain::GetId().GetChainId()),
        errorCode,
        errorMesg,
        decryptAlgo,
        decryptKeyid,
        decryptIv,
    };
    event.WriteDecryptionEvent("DRM_DECRYPTION_FAILURE", OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        drmDecryptionInfo);
}
#endif
} // namespace DrmStandard
} // namespace OHOS