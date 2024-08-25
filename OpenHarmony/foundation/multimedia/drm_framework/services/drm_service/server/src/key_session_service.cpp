/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "key_session_service.h"
#include "drm_dfx.h"
#include "drm_dfx_utils.h"
#include "drm_host_manager.h"
#include "drm_log.h"
#include "drm_trace.h"
#include "ipc_skeleton.h"
#include "hitrace/tracechain.h"

namespace OHOS {
namespace DrmStandard {
using namespace OHOS::HiviewDFX;
static std::mutex sessionMutex_;

MediaKeySessionService::MediaKeySessionService(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> hdiMediaKeySession)
{
    DRM_DEBUG_LOG("MediaKeySessionService::MediaKeySessionService.");
    sessionOperatorsCallback_ = nullptr;
    hdiMediaKeySession_ = hdiMediaKeySession;
}

MediaKeySessionService::MediaKeySessionService(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> hdiMediaKeySession,
    StatisticsInfo statisticsInfo)
{
    DRM_INFO_LOG("MediaKeySessionService::MediaKeySessionService with statisticsInfo_ enter.");
    sessionOperatorsCallback_ = nullptr;
    hdiMediaKeySession_ = hdiMediaKeySession;
    statisticsInfo_ = statisticsInfo;
}

MediaKeySessionService::~MediaKeySessionService()
{
    DRM_INFO_LOG("MediaKeySessionService::~MediaKeySessionService enter.");
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (sessionOperatorsCallback_ != nullptr) {
        sessionOperatorsCallback_ = nullptr;
    }
    if (hdiMediaKeySession_ != nullptr) {
        DRM_ERR_LOG("hdiMediaKeySession_ != nullptr");
    }
    DRM_INFO_LOG("MediaKeySessionService::~MediaKeySessionService exit.");
}

int32_t MediaKeySessionService::CloseMediaKeySessionServiceByCallback()
{
    DRM_INFO_LOG("MediaKeySessionService::CloseMediaKeySessionServiceByCallback enter.");
    int32_t currentPid = IPCSkeleton::GetCallingPid();
    DRM_DEBUG_LOG("MediaKeySessionService GetCallingPID: %{public}d", currentPid);
    if (hdiMediaKeySession_ != nullptr) {
        DRM_INFO_LOG("hdiMediaKeySession_ CloseHdiMediaKeySession");
        hdiMediaKeySession_->Destroy();
        hdiMediaKeySession_ = nullptr;
    }
    if (sessionOperatorsCallback_ != nullptr) {
        sessionOperatorsCallback_ = nullptr;
    }
    DRM_INFO_LOG("MediaKeySessionService::CloseMediaKeySessionServiceByCallback exit.");
    return DRM_OK;
}

int32_t MediaKeySessionService::Release()
{
    DRM_INFO_LOG("MediaKeySessionService::Release enter.");
    int32_t currentPid = IPCSkeleton::GetCallingPid();
    DRM_DEBUG_LOG("MediaKeySessionService GetCallingPID: %{public}d", currentPid);
    if (sessionOperatorsCallback_ != nullptr) {
        sessionOperatorsCallback_->CloseMediaKeySessionService(this);
    }
    DRM_INFO_LOG("MediaKeySessionService::Release exit.");
    return DRM_OK;
}

int32_t MediaKeySessionService::SetMediaKeySessionServiceOperatorsCallback(
    wptr<IMediaKeySessionServiceOperatorsCallback> callback)
{
    DRM_INFO_LOG("MediaKeySessionService::SetMediaKeySessionServiceOperatorsCallback enter.");
    if (callback.promote() == nullptr) {
        DRM_ERR_LOG("SetMediaKeySessionServiceOperatorsCallback callback is null");
        return DRM_INVALID_ARG;
    }
    sessionOperatorsCallback_ = callback;
    DRM_INFO_LOG("MediaKeySessionService::SetMediaKeySessionServiceOperatorsCallback exit.");
    return DRM_OK;
}

int32_t MediaKeySessionService::GenerateMediaKeyRequest(
    IMediaKeySessionService::MediaKeyRequestInfo &licenseRequestInfo,
    IMediaKeySessionService::MediaKeyRequest &licenseRequest)
{
    DrmTrace trace("MediaKeySessionService::GenerateMediaKeyRequest");
    DRM_INFO_LOG("MediaKeySessionService::GenerateMediaKeyRequest enter.");
    DRM_DEBUG_LOG("pluginName:%{public}s, pluginUuid:%{public}s\nbundleName:%{public}s,\nvendor:%{public}s,\n"
        "version:%{public}s,\n", statisticsInfo_.pluginName.c_str(), statisticsInfo_.pluginUuid.c_str(),
        statisticsInfo_.bundleName.c_str(), statisticsInfo_.vendorName.c_str(), statisticsInfo_.versionName.c_str());
    int32_t ret = DRM_OK;
    OHOS::HDI::Drm::V1_0::MediaKeyRequestInfo hdiMediaKeyRequestInfo;

    hdiMediaKeyRequestInfo.mediaKeyType = (OHOS::HDI::Drm::V1_0::MediaKeyType)licenseRequestInfo.mediaKeyType;
    hdiMediaKeyRequestInfo.mimeType = licenseRequestInfo.mimeType;
    hdiMediaKeyRequestInfo.initData.assign(licenseRequestInfo.initData.begin(), licenseRequestInfo.initData.end());
    for (std::map<std::string, std::string>::iterator it = licenseRequestInfo.optionalData.begin();
        it != licenseRequestInfo.optionalData.end(); ++it) {
        hdiMediaKeyRequestInfo.optionalData.insert(std::make_pair(it->first, it->second));
    }
    for (size_t i = 0; i < hdiMediaKeyRequestInfo.initData.size(); i++) {
        DRM_DEBUG_LOG("hdiMediaKeyRequestInfo.initData : %{public}d\n", hdiMediaKeyRequestInfo.initData[i]);
    }
    OHOS::HDI::Drm::V1_0::MediaKeyRequest hdiMediaKeyRequest;
    mediaKeyType_ = std::to_string(static_cast<int32_t>(licenseRequestInfo.mediaKeyType));
    auto timeBefore = std::chrono::system_clock::now();
    ret = hdiMediaKeySession_->GenerateMediaKeyRequest(hdiMediaKeyRequestInfo, hdiMediaKeyRequest);
    auto timeAfter = std::chrono::system_clock::now();
    auto duration = timeAfter - timeBefore;
    generationDuration_ = duration.count();
    if (ret != DRM_OK) {
        generationResult_ = "failed";
        DRM_ERR_LOG("MediaKeySessionService::GenerateMediaKeyRequest failed.");
        ReportFaultEvent(ret, "GenerateMediaKeyRequest failed", "");
        ReportLicenseBehaviorEvent(statisticsInfo_, mediaKeyType_, generationDuration_, generationResult_, 0,
            "GenerateMediaKeyRequest failed");
        return ret;
    }
    generationResult_ = "success";
    licenseRequest.requestType = (IMediaKeySessionService::RequestType)hdiMediaKeyRequest.requestType;
    licenseRequest.mData.assign(hdiMediaKeyRequest.data.begin(), hdiMediaKeyRequest.data.end());
    licenseRequest.mDefaultURL = hdiMediaKeyRequest.defaultUrl;
    DRM_INFO_LOG("MediaKeySessionService::GenerateMediaKeyRequest exit.");
    return ret;
}

int32_t MediaKeySessionService::ProcessMediaKeyResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &licenseResponse)
{
    DrmTrace trace("MediaKeySessionService::ProcessMediaKeyResponse");
    DRM_INFO_LOG("MediaKeySessionService::ProcessMediaKeyResponse enter.");
    DRM_DEBUG_LOG("pluginName:%{public}s, pluginUuid:%{public}s\nbundleName:%{public}s,\nvendor:%{public}s,\n"
        "version:%{public}s,\n", statisticsInfo_.pluginName.c_str(), statisticsInfo_.pluginUuid.c_str(),
        statisticsInfo_.bundleName.c_str(), statisticsInfo_.vendorName.c_str(), statisticsInfo_.versionName.c_str());
    int32_t ret = DRM_OK;
    auto timeBefore = std::chrono::system_clock::now();
    ret = hdiMediaKeySession_->ProcessMediaKeyResponse(licenseResponse, licenseId);
    auto timeAfter = std::chrono::system_clock::now();
    auto duration = timeAfter - timeBefore;
    auto processDuration = duration.count();
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::ProcessMediaKeyResponse failed.");
        std::string responseString = std::string(reinterpret_cast<const char*>(licenseResponse.data()),
            licenseResponse.size());

        ReportFaultEvent(ret, "ProcessMediaKeyResponse failed", responseString);
        ReportLicenseBehaviorEvent(statisticsInfo_, mediaKeyType_, generationDuration_, generationResult_,
            processDuration, "failed");
        return ret;
    }
    ReportLicenseBehaviorEvent(statisticsInfo_, mediaKeyType_, generationDuration_, generationResult_,
        processDuration, "success");
    DRM_INFO_LOG("MediaKeySessionService::ProcessMediaKeyResponse exit.");
    return ret;
}

int32_t MediaKeySessionService::GenerateOfflineReleaseRequest(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseRequest)
{
    DRM_INFO_LOG("MediaKeySessionService::GenerateOfflineReleaseRequest enter.");
    int32_t ret = DRM_OK;
    ret = hdiMediaKeySession_->GetOfflineReleaseRequest(licenseId, releaseRequest);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::GenerateOfflineReleaseRequest failed.");
        return ret;
    }
    DRM_INFO_LOG("MediaKeySessionService::GenerateOfflineReleaseRequest exit.");
    return ret;
}

int32_t MediaKeySessionService::ProcessOfflineReleaseResponse(std::vector<uint8_t> &licenseId,
    std::vector<uint8_t> &releaseResponse)
{
    DRM_INFO_LOG("MediaKeySessionService::ProcessOfflineReleaseResponse enter.");
    int32_t ret = DRM_OK;

    ret = hdiMediaKeySession_->ProcessOfflineReleaseResponse(licenseId, releaseResponse);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::ProcessOfflineReleaseResponse failed.");
        return ret;
    }
    DRM_INFO_LOG("MediaKeySessionService::ProcessOfflineReleaseResponse exit.");
    return ret;
}

int32_t MediaKeySessionService::CheckMediaKeyStatus(std::map<std::string, std::string> &licenseStatus)
{
    DRM_INFO_LOG("MediaKeySessionService::CheckMediaKeyStatus enter.");
    int32_t ret = DRM_OK;
    std::map<std::string, std::string> mp;
    ret = hdiMediaKeySession_->CheckMediaKeyStatus(mp);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::CheckMediaKeyStatus failed.");
        return ret;
    }
    for (auto m : mp) {
        std::string name = m.first;
        std::string status = m.second;
        licenseStatus.insert(std::make_pair(name, status));
    }
    if (licenseStatus.size() == 0) {
        DRM_ERR_LOG("MediaKeySessionService::CheckMediaKeyStatus licenseStatus is empty.");
        return DRM_ERROR;
    }
    DRM_INFO_LOG("MediaKeySessionService::CheckMediaKeyStatus exit.");
    return ret;
}

int32_t MediaKeySessionService::RestoreOfflineMediaKeys(std::vector<uint8_t> &licenseId)
{
    DRM_INFO_LOG("MediaKeySessionService::RestoreOfflineMediaKeys enter.");
    DRM_DEBUG_LOG("pluginName:%{public}s, pluginUuid:%{public}s\nbundleName:%{public}s,\nvendor:%{public}s,\n"
        "version:%{public}s,\n", statisticsInfo_.pluginName.c_str(), statisticsInfo_.pluginUuid.c_str(),
        statisticsInfo_.bundleName.c_str(), statisticsInfo_.vendorName.c_str(), statisticsInfo_.versionName.c_str());
    int32_t ret = DRM_OK;
    ret = hdiMediaKeySession_->RestoreOfflineMediaKeys(licenseId);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::RestoreOfflineMediaKeys failed.");
        return ret;
    }
    DRM_INFO_LOG("MediaKeySessionService::RestoreOfflineMediaKeys exit.");
    return ret;
}

int32_t MediaKeySessionService::ClearMediaKeys()
{
    DRM_INFO_LOG("MediaKeySessionService::ClearMediaKeys enter.");
    int32_t ret = DRM_OK;
    ret = hdiMediaKeySession_->ClearMediaKeys();
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::ClearMediaKeys failed.");
        return ret;
    }
    DRM_INFO_LOG("MediaKeySessionService::ClearMediaKeys exit.");
    return ret;
}

int32_t MediaKeySessionService::GetContentProtectionLevel(
    IMediaKeySessionService::ContentProtectionLevel *securityLevel)
{
    DRM_INFO_LOG("MediaKeySessionService::GetContentProtectionLevel enter.");
    int32_t ret = DRM_OK;

    OHOS::HDI::Drm::V1_0::ContentProtectionLevel level;
    ret = hdiMediaKeySession_->GetContentProtectionLevel(level);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::GetContentProtectionLevel failed.");
        return ret;
    }
    *securityLevel = (IMediaKeySessionService::ContentProtectionLevel)level;

    DRM_INFO_LOG("MediaKeySessionService::GetContentProtectionLevel exit.");
    return ret;
}

int32_t MediaKeySessionService::CreateMediaDecryptModule(sptr<IMediaDecryptModuleService> &decryptModule)
{
    DrmTrace trace("MediaKeySessionService::CreateMediaDecryptModule");
    DRM_INFO_LOG("MediaKeySessionService::CreateMediaDecryptModule enter.");
    std::lock_guard<std::mutex> lock(sessionMutex_);
    sptr<MediaDecryptModuleService> mediaDecryptService = nullptr;
    sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> hdiDecryptModule = nullptr;
    if (hdiMediaKeySession_ == nullptr) {
        DRM_ERR_LOG("MediaKeySessionService:: hdiMediaKeySession_ == nullptr");
        return DRM_SERVICE_ERROR;
    } else {
        int32_t retCode = DRM_OK;
        retCode = hdiMediaKeySession_->GetMediaDecryptModule(hdiDecryptModule);
        if (retCode != DRM_OK || hdiDecryptModule == nullptr) {
            DRM_ERR_LOG("MediaKeySessionService:: hdiDecryptModule allocation failed.");
            return DRM_SERVICE_ERROR;
        }
        mediaDecryptService = new (std::nothrow) MediaDecryptModuleService(hdiDecryptModule);
        if (mediaDecryptService == nullptr) {
            DRM_ERR_LOG("MediaKeySessionService:: new MediaDecryptModuleService allocation failed.");
            return DRM_ALLOC_ERROR;
        }
        decryptModule = mediaDecryptService;
        DRM_INFO_LOG("MediaKeySessionService::CreateMediaDecryptModule enter.");
        return DRM_OK;
    }
}

int32_t MediaKeySessionService::RequireSecureDecoderModule(std::string &mimeType, bool *status)
{
    DRM_INFO_LOG("MediaKeySessionService::RequireSecureDecoderModule enter.");

    int32_t ret = DRM_OK;
    (void)mimeType;
    (void)status;

    bool decoderModuleStatus = false;
    ret = hdiMediaKeySession_->RequiresSecureDecoderModule(mimeType, decoderModuleStatus);
    if (ret != DRM_OK) {
        DRM_ERR_LOG("MediaKeySessionService::RequireSecureDecoderModule failed.");
        return ret;
    }
    *status = decoderModuleStatus;

    DRM_INFO_LOG("MediaKeySessionService::RequireSecureDecoderModule exit.");
    return ret;
}

int32_t MediaKeySessionService::SetCallback(sptr<IMediaKeySessionServiceCallback> &callback)
{
    DRM_INFO_LOG("MediaKeySessionService::SetCallback enter.");
    std::lock_guard<std::mutex> lock(sessionMutex_);
    if (callback == nullptr) {
        DRM_ERR_LOG("MediaKeySessionService::SetCallback nullptr , failed.");
        return DRM_ERROR;
    }
    callback_ = callback;
    if (hdiMediaKeySession_ != nullptr) {
        return hdiMediaKeySession_->SetCallback(this);
    }
    DRM_ERR_LOG("MediaKeySessionService::SetCallback hdiMediaKeySession_ is nullptr , failed.");
    return DRM_OPERATION_NOT_ALLOWED;
}

int32_t MediaKeySessionService::SendEvent(OHOS::HDI::Drm::V1_0::EventType eventType, int32_t extra,
    const std::vector<uint8_t> &data)
{
    DRM_INFO_LOG("MediaKeySessionService:: SendEvent.");
    DrmEventType event = static_cast<DrmEventType>(eventType);
    if (callback_ != nullptr) {
        return callback_->SendEvent(event, extra, data);
    }
    DRM_INFO_LOG("MediaKeySystemService:: SendEvent failed because callback is nullptr");
    return DRM_OPERATION_NOT_ALLOWED;
}

int32_t MediaKeySessionService::SendEventKeyChange(
    const std::map<std::vector<uint8_t>, OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus> &keyStatus,
    bool hasNewGoodLicense)
{
    DRM_INFO_LOG("MediaKeySessionService:: SendEventKeyChange.");
    std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> keyStatusMap;
    for (auto item : keyStatus) {
        keyStatusMap.insert({ item.first, static_cast<MediaKeySessionKeyStatus>(item.second) });
    }
    if (callback_ != nullptr) {
        return callback_->SendEventKeyChanged(keyStatusMap, hasNewGoodLicense);
    }
    DRM_INFO_LOG("MediaKeySessionService:: SendEvent failed because callback is nullptr");
    return DRM_OPERATION_NOT_ALLOWED;
}
} // DrmStandard
} // OHOS