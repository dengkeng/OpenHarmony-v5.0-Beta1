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

#include <mutex>
#include <shared_mutex>
#include <string>
#include <refbase.h>
#include <securec.h>
#include "drm_log.h"
#include "drm_trace.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "key_session_impl.h"
#include "native_mediakeysession.h"
#include "native_mediakeysystem.h"

using namespace OHOS::DrmStandard;


static Drm_ErrCode DealMediaKeyRequest(IMediaKeySessionService::MediaKeyRequest &licenseRequest,
    DRM_MediaKeyRequest *mediaKeyRequest)
{
    DrmTrace trace("DealMediaKeyRequest");
    DRM_INFO_LOG("DealMediaKeyRequest enter.");
    memset_s(mediaKeyRequest, sizeof(DRM_MediaKeyRequest), 0, sizeof(DRM_MediaKeyRequest));
    mediaKeyRequest->type = (DRM_MediaKeyRequestType)(licenseRequest.requestType);
    mediaKeyRequest->dataLen = (int32_t)licenseRequest.mData.size();
    int ret = memcpy_s(mediaKeyRequest->data, licenseRequest.mData.size(), licenseRequest.mData.data(),
        licenseRequest.mData.size());
    if (ret != 0) {
        DRM_DEBUG_LOG("licenseRequest.mData.data() is nullptr!");
        return DRM_ERR_NO_MEMORY;
    }
    if (licenseRequest.mDefaultURL.size() == 0) {
        return DRM_ERR_OK;
    }
    ret = memcpy_s(mediaKeyRequest->defaultUrl, licenseRequest.mDefaultURL.size(), licenseRequest.mDefaultURL.data(),
        licenseRequest.mDefaultURL.size());
    if (ret != 0) {
        DRM_DEBUG_LOG("licenseRequest.mDefaultURL.data() is nullptr!");
        return DRM_ERR_NO_MEMORY;
    }
    DRM_INFO_LOG("DealMediaKeyRequest exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_GenerateMediaKeyRequest(MediaKeySession *mediaKeySession, DRM_MediaKeyRequestInfo *info,
    DRM_MediaKeyRequest *mediaKeyRequest)
{
    DrmTrace trace("OH_MediaKeySession_GenerateMediaKeyRequest");
    DRM_INFO_LOG("OH_MediaKeySession_GenerateMediaKeyRequest enter");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySession != nullptr) && (info != nullptr) && (mediaKeyRequest != nullptr)),
        DRM_ERR_INVALID_VAL, "parameter is error.");
    IMediaKeySessionService::MediaKeyRequestInfo licenseRequestInfo;
    IMediaKeySessionService::MediaKeyRequest licenseRequest;
    licenseRequest.requestType = OHOS::DrmStandard::IMediaKeySessionService::REQUEST_TYPE_RELEASE;
    licenseRequestInfo.mediaKeyType = (IMediaKeySessionService::MediaKeyType)info->type;
    licenseRequestInfo.mimeType = std::string(info->mimeType, info->mimeType + sizeof(info->mimeType));
    std::vector<uint8_t> initDataStr(info->initData, info->initData + info->initDataLen);
    licenseRequestInfo.initData = initDataStr;
    for (uint32_t i = 0; i < info->optionsCount; i++) {
        std::string optionsname(info->optionName[i], info->optionName[i] + strlen(info->optionName[i]));
        std::string optionsvalue(info->optionData[i], info->optionData[i] + strlen(info->optionData[i]));
        licenseRequestInfo.optionalData.insert(std::make_pair(optionsname, optionsvalue));
    }
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
    int ret = sessionObject->sessionImpl_->GenerateMediaKeyRequest(licenseRequestInfo, licenseRequest);
    DRM_CHECK_AND_RETURN_RET_LOG((ret == DRM_ERR_OK), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_GenerateMediaKeyRequest call Failed!");
    Drm_ErrCode result = DealMediaKeyRequest(licenseRequest, mediaKeyRequest);
    DRM_INFO_LOG("OH_MediaKeySession_GenerateMediaKeyRequest exit");
    return result;
}

Drm_ErrCode OH_MediaKeySession_ProcessMediaKeyResponse(MediaKeySession *mediaKeySession, uint8_t *response,
    int32_t responseLen, uint8_t *offlineMediaKeyId, int32_t *offlineMediaKeyIdLen)
{
    DrmTrace trace("OH_MediaKeySession_ProcessMediaKeyResponse");
    DRM_INFO_LOG("OH_MediaKeySession_ProcessMediaKeyResponse enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(
        ((mediaKeySession != nullptr) && (response != nullptr) && (responseLen > 0) &&
        (offlineMediaKeyId != nullptr) && (offlineMediaKeyIdLen != nullptr)), DRM_ERR_INVALID_VAL,
        "parameter is error!");
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
    std::vector<uint8_t> licenseResponseVec(response, response + responseLen);
    std::vector<uint8_t> keyIdVec;
    int32_t ret = sessionObject->sessionImpl_->ProcessMediaKeyResponse(keyIdVec, licenseResponseVec);
    DRM_CHECK_AND_RETURN_RET_LOG(ret == DRM_ERR_OK, DRM_ERR_INVALID_VAL, "got licenseResponse null!");
    if (keyIdVec.size() == 0) {
        DRM_DEBUG_LOG("keyIdVec.data() is nullptr!");
        return DRM_ERR_OK;
    }
    ret = memcpy_s(offlineMediaKeyId, *offlineMediaKeyIdLen, keyIdVec.data(), keyIdVec.size());
    if (ret != 0) {
        DRM_ERR_LOG("OH_MediaKeySession_ProcessMediaKeyResponse memcpy_s faild!");
        return DRM_ERR_NO_MEMORY;
    }
    *offlineMediaKeyIdLen = keyIdVec.size();
    DRM_INFO_LOG("OH_MediaKeySession_ProcessMediaKeyResponse exit.");
    return DRM_ERR_OK;
}

static Drm_ErrCode MapToClist(std::map<std::string, std::string> licenseStatus, DRM_MediaKeyStatus *mediaKeyStatus)
{
    DRM_INFO_LOG("MapToClist enter.");
    memset_s(mediaKeyStatus, sizeof(DRM_MediaKeyStatus), 0, sizeof(DRM_MediaKeyStatus));
    mediaKeyStatus->statusCount = licenseStatus.size();
    auto it = licenseStatus.begin();
    for (size_t i = 0; i < licenseStatus.size(); i++) {
        int32_t ret = memcpy_s(mediaKeyStatus->statusName[i], it->first.size(), it->first.c_str(), it->first.size());
        if (ret != 0) {
            DRM_DEBUG_LOG("ediaKeyStatus->statusName is nullptr!");
            return DRM_ERR_NO_MEMORY;
        }
        ret = memcpy_s(mediaKeyStatus->statusValue[i], it->second.size(), it->second.c_str(), it->second.size());
        if (ret != 0) {
            DRM_DEBUG_LOG("mediaKeyStatus->statusValue is nullptr!");
            return DRM_ERR_NO_MEMORY;
        }
        it++;
    }
    DRM_INFO_LOG("MapToClist exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_CheckMediaKeyStatus(MediaKeySession *mediaKeySessoin, DRM_MediaKeyStatus *mediaKeyStatus)
{
    DRM_INFO_LOG("OH_MediaKeySession_CheckMediaKeyStatus enter");
    std::map<std::string, std::string> licenseStatus;
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (mediaKeyStatus != nullptr)), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_ClearMediaKeys parameter is error!");
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    int32_t result = sessionObject->sessionImpl_->CheckMediaKeyStatus(licenseStatus);
    DRM_CHECK_AND_RETURN_RET_LOG(result == DRM_ERR_OK, DRM_ERR_INVALID_VAL,
        "OH_SetConfigurationByteArray mediaKeySystemImpl::SetConfigurationByteArray faild!");
    if (licenseStatus.size() == 0) {
        DRM_ERR_LOG("Licence not exist.");
        return DRM_ERR_INVALID_VAL;
    }
    Drm_ErrCode ret = MapToClist(licenseStatus, mediaKeyStatus);
    DRM_INFO_LOG("OH_MediaKeySession_CheckMediaKeyStatus exit.");
    return ret;
}

Drm_ErrCode OH_MediaKeySession_ClearMediaKeys(MediaKeySession *mediaKeySessoin)
{
    DRM_INFO_LOG("OH_MediaKeySession_ClearMediaKeys enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(mediaKeySessoin != nullptr, DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_ClearMediaKeys parameter is error!");
    int32_t currentPid = OHOS::IPCSkeleton::GetCallingPid();
    DRM_DEBUG_LOG("MediaKeySessionNapi GetCallingPID: %{public}d", currentPid);
    int32_t result = DRM_ERR_OK;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    result = sessionObject->sessionImpl_->ClearMediaKeys();
    DRM_CHECK_AND_RETURN_RET_LOG(result == DRM_ERR_OK, DRM_ERR_INVALID_VAL,
        "OH_SetConfigurationByteArray mediaKeySystemImpl::SetConfigurationByteArray faild!");
    DRM_INFO_LOG("OH_MediaKeySession_ClearMediaKeys exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_GenerateOfflineReleaseRequest(MediaKeySession *mediaKeySessoin,
    uint8_t *offlineMediaKeyId, int32_t offlineMediaKeyIdLen, uint8_t *releaseRequest, int32_t *releaseRequestLen)
{
    DRM_INFO_LOG("OH_MediaKeySession_GenerateOfflineReleaseRequest enter");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (offlineMediaKeyId != nullptr) &&
        (offlineMediaKeyIdLen > 0) && (releaseRequest != nullptr) && (releaseRequestLen != nullptr)),
        DRM_ERR_INVALID_VAL, "OH_MediaKeySession_GenerateOfflineReleaseRequest parameter is error!");
    std::vector<uint8_t> ReleaseRequest;
    std::vector<uint8_t> licenseIdVec(offlineMediaKeyId, offlineMediaKeyId + offlineMediaKeyIdLen);

    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);

    int32_t result = sessionObject->sessionImpl_->GenerateOfflineReleaseRequest(licenseIdVec, ReleaseRequest);
    DRM_CHECK_AND_RETURN_RET_LOG(result == DRM_ERR_OK, DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_GenerateOfflineReleaseRequest GenerateOfflineReleaseRequest faild!");
    if (ReleaseRequest.size() == 0) {
        DRM_DEBUG_LOG("ReleaseRequest.data() is nullptr!");
        return DRM_ERR_OK;
    }
    int32_t ret = memcpy_s(releaseRequest, *releaseRequestLen, ReleaseRequest.data(), ReleaseRequest.size());
    if (ret != 0) {
        DRM_ERR_LOG("OH_MediaKeySession_GenerateOfflineReleaseRequest memcpy_s faild!");
        return DRM_ERR_INVALID_VAL;
    }
    *releaseRequestLen = ReleaseRequest.size();
    DRM_INFO_LOG("OH_MediaKeySession_GenerateOfflineReleaseRequest exit");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_ProcessOfflineReleaseResponse(MediaKeySession *mediaKeySessoin,
    uint8_t *offlineMediaKeyId, int32_t offlineMediaKeyIdLen, uint8_t *releaseReponse, int32_t releaseReponseLen)
{
    DRM_INFO_LOG("OH_MediaKeySession_ProcessOfflineReleaseResponse enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (offlineMediaKeyId != nullptr) &&
        (offlineMediaKeyIdLen > 0) && (releaseReponse != nullptr) && (releaseReponseLen > 0)),
        DRM_ERR_INVALID_VAL, "OH_MediaKeySession_ClearMediaKeys parameter is error!");
    std::vector<uint8_t> licenseIdVec(offlineMediaKeyId, offlineMediaKeyId + offlineMediaKeyIdLen);
    std::vector<uint8_t> responseVec(releaseReponse, releaseReponse + releaseReponseLen);
    int32_t result = DRM_ERR_OK;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    result = sessionObject->sessionImpl_->ProcessOfflineReleaseResponse(licenseIdVec, responseVec);
    DRM_CHECK_AND_RETURN_RET_LOG((result == DRM_ERR_OK), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_ProcessOfflineReleaseResponse call Failed!");
    DRM_INFO_LOG("OH_MediaKeySession_ProcessOfflineReleaseResponse exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_RestoreOfflineMediaKeys(MediaKeySession *mediaKeySessoin,
    uint8_t *offlineMediaKeyId, int32_t offlineMediaKeyIdLen)
{
    DRM_INFO_LOG("OH_MediaKeySession_RestoreOfflineLMediaKey enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(
        ((mediaKeySessoin != nullptr) && (offlineMediaKeyId != nullptr) && (offlineMediaKeyIdLen > 0)),
        DRM_ERR_INVALID_VAL, "OH_MediaKeySession_RestoreOfflineLMediaKey parameter is error!");
    std::vector<uint8_t> licenseIdVec(offlineMediaKeyId, offlineMediaKeyId + offlineMediaKeyIdLen);
    int32_t result = DRM_ERR_OK;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    result = sessionObject->sessionImpl_->RestoreOfflineMediaKeys(licenseIdVec);
    DRM_CHECK_AND_RETURN_RET_LOG((result == DRM_ERR_OK), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_restoreOfflineMediaKey call Failed!");
    DRM_INFO_LOG("OH_MediaKeySession_restoreOfflineMediaKey exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_GetContentProtectionLevel(MediaKeySession *mediaKeySessoin,
    DRM_ContentProtectionLevel *contentProtectionLevel)
{
    DRM_INFO_LOG("OH_MediaKeySession_GetContentProtectionLevel enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (contentProtectionLevel != nullptr)),
        DRM_ERR_INVALID_VAL, "OH_MediaKeySession_GetContentProtectionLevel parameter is error!");
    int32_t result = DRM_ERR_OK;
    IMediaKeySessionService::ContentProtectionLevel level =
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_UNKNOWN;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    result = sessionObject->sessionImpl_->GetContentProtectionLevel(&level);
    DRM_CHECK_AND_RETURN_RET_LOG((result == DRM_ERR_OK), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_GetContentProtectionLevel get level fail!");
    *contentProtectionLevel = static_cast<DRM_ContentProtectionLevel>(level);
    if (*contentProtectionLevel < CONTENT_PROTECTION_LEVEL_UNKNOWN ||
        *contentProtectionLevel > CONTENT_PROTECTION_LEVEL_MAX) {
        DRM_ERR_LOG("OH_MediaKeySession_GetContentProtectionLevel faild!");
        return DRM_ERR_INVALID_VAL;
    }
    DRM_INFO_LOG("OH_MediaKeySession_GetContentProtectionLevel exit");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_RequireSecureDecoderModule(MediaKeySession *mediaKeySessoin, const char *mimeType,
    bool *status)
{
    DRM_INFO_LOG("OH_MediaKeySession_RequireSecureDecoderModule enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (mimeType != nullptr) && (status != nullptr)),
        DRM_ERR_INVALID_VAL, "OH_MediaKeySession_RequireSecureDecoderModule parameter is error!");
    std::string mimeTypeBuf = std::string(mimeType);
    DRM_CHECK_AND_RETURN_RET_LOG((mimeTypeBuf.size() != 0), DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_RequireSecureDecoderModule mimeTypesize is zero!");
    bool statusValue = false;
    int32_t result = DRM_ERR_OK;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    result = sessionObject->sessionImpl_->RequireSecureDecoderModule(mimeTypeBuf, &statusValue);
    if (result != DRM_ERR_OK) {
        DRM_ERR_LOG("OH_MediaKeySession_RequireSecureDecoderModule keySessionImpl_->RequireSecureDecoderModule faild!");
        return DRM_ERR_INVALID_VAL;
    }
    *status = statusValue;
    DRM_INFO_LOG("OH_MediaKeySession_RequireSecureDecoderModule exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_SetMediaKeySessionCallback(MediaKeySession *mediaKeySessoin,
    MediaKeySession_Callback *callback)
{
    DRM_INFO_LOG("OH_MediaKeySession_SetMediaKeySessionCallback enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (callback != nullptr)), DRM_ERR_INVALID_VAL,
        "mediaKeySessoin is nullptr!");
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    sessionObject->sessionCallback_->SetCallbackReference(*callback);
    DRM_INFO_LOG("OH_MediaKeySession_SetMediaKeySessionCallback exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_SetCallback(MediaKeySession *mediaKeySessoin,
    OH_MediaKeySession_Callback *callback)
{
    DRM_INFO_LOG("OH_MediaKeySession_SetCallback enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(((mediaKeySessoin != nullptr) && (callback != nullptr)), DRM_ERR_INVALID_VAL,
        "mediaKeySessoin is nullptr!");
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySessoin);
    sessionObject->sessionCallback_->SetCallbackReference(mediaKeySessoin, *callback);
    DRM_INFO_LOG("OH_MediaKeySession_SetCallback exit.");
    return DRM_ERR_OK;
}

Drm_ErrCode OH_MediaKeySession_Destroy(MediaKeySession *keySession)
{
    DRM_INFO_LOG("OH_MediaKeySession_Destroy enter.");
    DRM_CHECK_AND_RETURN_RET_LOG(keySession != nullptr, DRM_ERR_INVALID_VAL,
        "OH_MediaKeySession_Destroy keySession is nullptr!");
    int32_t result = DRM_ERR_OK;
    MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(keySession);
    result = sessionObject->sessionImpl_->Release();
    if (result != DRM_ERR_OK) {
        DRM_ERR_LOG("OH_MediaKeySession_Destroy keySessionImpl_->Release faild!");
        return DRM_ERR_INVALID_STATE;
    }
    delete sessionObject;
    DRM_INFO_LOG("OH_MediaKeySession_Destroy exit.");
    return DRM_ERR_OK;
}