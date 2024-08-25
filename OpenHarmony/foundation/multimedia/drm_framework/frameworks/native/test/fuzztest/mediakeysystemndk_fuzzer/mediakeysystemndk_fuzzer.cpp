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


#include <string>
#include <refbase.h>
#include <securec.h>
#include "drm_log.h"
#include "http.h"
#include "native_drm_common.h"
#include "native_drm_base.h"
#include "native_drm_object.h"
#include "native_mediakeysystem.h"
#include "mediakeysystemndk_fuzzer.h"

#define OFFRESPONSE                                                                                                 \
    {                                                                                                               \
        0x31, 0x64, 0x6E, 0x5A, 0x32, 0x4E, 0x57, 0x74, 0x76, 0x4D, 0x47, 0x34, 0x34, 0x4E, 0x6A, 0x42, 0x30, 0x4D, \
            0x32, 0x77, 0x33, 0x4E, 0x67, 0x3D, 0x3D, 0x3A, 0x59, 0x7A, 0x56, 0x78, 0x63, 0x48, 0x64, 0x70, 0x61,   \
            0x6D, 0x30, 0x34, 0x59, 0x57, 0x45, 0x34, 0x5A, 0x48, 0x6B, 0x79, 0x4D, 0x67, 0x3D, 0x3D                \
    }
#define REQUESTINFODATA                                                                                             \
    {                                                                                                               \
        0x00, 0x00, 0x00, 0x8B, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x5E, 0x6D, 0x35, 0x9B, 0x9A, \
            0x41, 0xE8, 0xB8, 0x43, 0xDD, 0x3C, 0x6E, 0x72, 0xC4, 0x2C, 0x00, 0x00, 0x00, 0x6B, 0x7B, 0x22, 0x76,   \
            0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x22, 0x3A, 0x22, 0x56, 0x31, 0x2E, 0x30, 0x22, 0x2C, 0x22, 0x63,   \
            0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x49, 0x44, 0x22, 0x3A, 0x22, 0x64, 0x48, 0x4D, 0x74, 0x4D, 0x6A,   \
            0x59, 0x30, 0x4C, 0x54, 0x45, 0x77, 0x4F, 0x44, 0x41, 0x74, 0x59, 0x57, 0x56, 0x7A, 0x22, 0x2C, 0x22,   \
            0x6B, 0x69, 0x64, 0x73, 0x22, 0x3A, 0x5B, 0x22, 0x47, 0x2B, 0x45, 0x6B, 0x2F, 0x2B, 0x58, 0x6D, 0x55,   \
            0x6B, 0x70, 0x42, 0x48, 0x51, 0x67, 0x58, 0x59, 0x57, 0x51, 0x51, 0x49, 0x67, 0x3D, 0x3D, 0x22, 0x5D,   \
            0x2C, 0x22, 0x65, 0x6E, 0x73, 0x63, 0x68, 0x65, 0x6D, 0x61, 0x22, 0x3A, 0x22, 0x63, 0x62, 0x63, 0x31,   \
            0x22, 0x7D                                                                                              \
    }
#define PROVISION_URL "https://drmkit.hwcloudtest.cn:8080/provision/v1/wiseplay"
#define LICENSE_URL "http://license.dev.trustdta.com:8080/drmproxy/v3/getLicense"
#define HTTPOUTTIME 10
using namespace std;
using namespace OHOS;
using namespace DrmStandard;
const int32_t MEMMAXSIZE = 128;
const int32_t OFFRESPONSELEN = 50;
const int32_t DATAMAXSIZE = 12288;
namespace OHOS {
namespace DrmStandard {
Drm_ErrCode TestSystemEventCallBack(DRM_EventType eventType, unsigned char *info, int32_t infoLen, char *extra)
{
    return DRM_ERR_OK;
}

Drm_ErrCode TestSystemEventCallBackWithObj(MediaKeySystem *mediaKeySystem, DRM_EventType eventType,
    uint8_t *info, int32_t infoLen, char *extra)
{
    DRM_INFO_LOG("TestSystemEventCallBackWithObj ok");
    DRM_INFO_LOG("Event: the mediaKeySystem object is: 0x%{public}06" PRIXPTR,
        FAKE_POINTER(mediaKeySystem));
    DRM_INFO_LOG("Event: event type: %d", eventType);
    DRM_INFO_LOG("Event: the info body is: ");
    if (info != nullptr) {
        for (int32_t i = 0; i < infoLen; i++) {
            DRM_INFO_LOG("%x", info[i]);
        }
    }
    if (extra != nullptr) {
        DRM_INFO_LOG("Event: the extra is: %s", extra);
    }
    return DRM_ERR_OK;
}

MediaKeySystemNdkFuzzer::MediaKeySystemNdkFuzzer() {}

MediaKeySystemNdkFuzzer::~MediaKeySystemNdkFuzzer() {}

void MediaKeySystemNdkFuzzer::GetUuid()
{
    if (OH_MediaKeySystem_IsSupported("com.clearplay.drm")) {
        uuid = "com.clearplay.drm";
    } else if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        uuid = "com.wiseplay.drm";
    }
}

void MediaKeySystemNdkFuzzer::IsWisePlay()
{
    if (OH_MediaKeySystem_IsSupported("com.wiseplay.drm")) {
        wisePlay = true;
    }
}

void MediaKeySystemNdkFuzzer::GenerateDeviceCertificate()
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::GenerateDeviceCertificate start");
    unsigned char request[12288] = { 0 }; // 12288:request len
    int32_t requestLen = 12288;           // 12288:request len
    char defaultUrl[2048] = { 0 };       // 2048:url len
    int32_t defaultUrlLen = 2048;        // 2048:url len
    OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl, defaultUrlLen);
    uint8_t response[12288] = OFFRESPONSE;
    int32_t responseLen = sizeof(response);
    if (wisePlay == true) {
        HttpPost(PROVISION_URL, request, requestLen, response, &responseLen, HTTPOUTTIME);
    }
    OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, response, responseLen);
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::GenerateDeviceCertificate end");
}

void MediaKeySystemNdkFuzzer::GenerateLicense()
{
    DRM_INFO_LOG("MediaKeysessionNdkFuzzer::GenerateLicense start");
    DRM_MediaKeyRequest mediaKeyRequest;
    DRM_MediaKeyRequestInfo info;
    unsigned char testData[139] = REQUESTINFODATA;
    memset_s(&info, sizeof(DRM_MediaKeyRequestInfo), 0, sizeof(DRM_MediaKeyRequestInfo));
    info.initDataLen = sizeof(testData);
    info.type = MEDIA_KEY_TYPE_OFFLINE;
    memcpy_s(info.mimeType, sizeof("video/mp4"), "video/mp4", sizeof("video/mp4"));
    memcpy_s(info.initData, sizeof(testData), testData, sizeof(testData));
    int ret = memcpy_s(info.optionName[0], sizeof("optionalDataName"), "optionalDataName", sizeof("optionalDataName"));
    if (ret != 0) {
        DRM_INFO_LOG("memcpy_s faild!");
    }
    ret = memcpy_s(info.optionData[0], sizeof("optionalDataValue"), "optionalDataValue", sizeof("optionalDataValue"));
    if (ret != 0) {
        DRM_INFO_LOG("memcpy_s faild!");
    }
    info.optionsCount = 1;
    OH_MediaKeySession_GenerateMediaKeyRequest(mediaKeySession, &info, &mediaKeyRequest);
    DRM_INFO_LOG("MediaKeysessionNdkFuzzer::GenerateLicense end");
    unsigned char keySessionResponse[12288] = OFFRESPONSE;
    int32_t keySessionResponseLen = sizeof(keySessionResponse);
    if (wisePlay) {
        HttpPost(LICENSE_URL, mediaKeyRequest.data, (uint32_t)mediaKeyRequest.dataLen, keySessionResponse,
            &keySessionResponseLen, HTTPOUTTIME);
    } else {
        keySessionResponseLen = OFFRESPONSELEN;
    }
    uint8_t mediaKeyId[64] = { 0 }; // 64:OFFLINE_MEDIA_KEY_ID_LEN
    int32_t mediaKeyIdLen = 64;     // 64:OFFLINE_MEDIA_KEY_ID_LEN
    OH_MediaKeySession_ProcessMediaKeyResponse(mediaKeySession, keySessionResponse, keySessionResponseLen,
        mediaKeyId, &mediaKeyIdLen);
}

void MediaKeySystemNdkFuzzer::Init()
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::Init start");
    GetUuid();
    IsWisePlay();
    DRM_INFO_LOG("uuid = %{public}s", uuid.c_str());
    DRM_INFO_LOG("wisePlay = %{public}d", wisePlay);
    OH_MediaKeySystem_Create(uuid.c_str(), &mediaKeySystem);
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::Init end");
}

void MediaKeySystemNdkFuzzer::Deinitialize()
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::Deinitialize start");
    if (mediaKeySystem != nullptr) {
        OH_MediaKeySystem_Destroy(mediaKeySystem);
        mediaKeySystem = nullptr;
    }
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::Deinitialize end");
}

bool MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemConfigurationNdk(uint8_t *rawData, size_t size)
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemConfigurationNdk start");
    if (rawData == nullptr) {
        return false;
    }
    Init();
    MediaKeySystemObject *tmp = new MediaKeySystemObject(nullptr);
    MediaKeySystem *tmpSystem = reinterpret_cast<MediaKeySystemObject *>(tmp);
    const char *name = reinterpret_cast<const char *>(rawData);
    const char *value = reinterpret_cast<const char *>(rawData);
    OH_MediaKeySystem_SetConfigurationString(mediaKeySystem, name, value);
    char destValue[size];
    char val[OFFRESPONSELEN];
    int valLen = OFFRESPONSELEN;
    OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, "vendor", val, valLen);
    OH_MediaKeySystem_GetConfigurationString(mediaKeySystem, name, destValue, size);
    OH_MediaKeySystem_SetConfigurationByteArray(mediaKeySystem, name, rawData, size);
    memset_s(destValue, size, 0, size);
    OH_MediaKeySystem_GetConfigurationByteArray(mediaKeySystem, name,
        reinterpret_cast<uint8_t *>(destValue), reinterpret_cast<int32_t *>(&size));
    OH_MediaKeySystem_SetConfigurationString(tmpSystem, name, value);
    OH_MediaKeySystem_GetConfigurationString(tmpSystem, name, destValue, size);
    OH_MediaKeySystem_SetConfigurationByteArray(tmpSystem, name, rawData, size);
    OH_MediaKeySystem_GetConfigurationByteArray(tmpSystem, "deviceUniqueId",
        reinterpret_cast<uint8_t *>(val), reinterpret_cast<int32_t *>(&valLen));
    OH_MediaKeySystem_GetConfigurationByteArray(tmpSystem, name,
        reinterpret_cast<uint8_t *>(destValue), reinterpret_cast<int32_t *>(&size));
    delete tmp;
    Deinitialize();
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemConfigurationNdk end");
    return true;
}

bool MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemGetNdk(uint8_t *rawData, size_t size)
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemGetNdk start");
    if (rawData == nullptr) {
        return false;
    }
    Init();
    MediaKeySystemObject *tmp = new MediaKeySystemObject(nullptr);
    MediaKeySystem *tmpSystem = reinterpret_cast<MediaKeySystemObject *>(tmp);
    DRM_Statistics statistics;
    memset_s(&statistics, sizeof(DRM_Statistics), 0, sizeof(DRM_Statistics));
    DRM_ContentProtectionLevel contentProtectionLevel = CONTENT_PROTECTION_LEVEL_UNKNOWN;
    OH_MediaKeySystem_GetStatistics(mediaKeySystem, &statistics);
    OH_MediaKeySystem_GetStatistics(tmpSystem, &statistics);
    OH_MediaKeySystem_GetMaxContentProtectionLevel(mediaKeySystem, &contentProtectionLevel);
    OH_MediaKeySystem_GetMaxContentProtectionLevel(tmpSystem, &contentProtectionLevel);
    delete tmp;
    Deinitialize();
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemGetNdk end");
    return true;
}

bool MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemDeviceCertificateNdk(uint8_t *rawData, size_t size)
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemDeviceCertificateNdk start");
    if (rawData == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    Init();
    MediaKeySystemObject *tmp = new MediaKeySystemObject(nullptr);
    MediaKeySystem *tmpSystem = reinterpret_cast<MediaKeySystemObject *>(tmp);
    unsigned char request[12288] = { 0 }; // 12288:request len
    int32_t requestLen = size % 12288;    // 12288:request len
    char defaultUrl[2048] = { 0 };       // 2048:url len
    int32_t defaultUrlLen = size % 2048; // 2048:url len
    OH_MediaKeySystem_GenerateKeySystemRequest(tmpSystem, request, &requestLen, defaultUrl, defaultUrlLen);
    requestLen = sizeof(request);
    defaultUrlLen = sizeof(defaultUrl);
    OH_MediaKeySystem_GenerateKeySystemRequest(mediaKeySystem, request, &requestLen, defaultUrl, defaultUrlLen);
    uint8_t response[12288] = OFFRESPONSE;
    int32_t responseLen = size % 12288;

    OH_MediaKeySystem_ProcessKeySystemResponse(tmpSystem, rawData, size);
    OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, response, responseLen);
    responseLen = sizeof(response);
    if (wisePlay == true) {
        HttpPost(PROVISION_URL, request, requestLen, response, &responseLen, HTTPOUTTIME);
    }
    OH_MediaKeySystem_ProcessKeySystemResponse(mediaKeySystem, response, responseLen);
    delete tmp;
    Deinitialize();
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemDeviceCertificateNdk end");
    return true;
}

bool MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemCertificateOperationNdk(uint8_t *rawData, size_t size)
{
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemCertificateOperationNdk start");
    if (rawData == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    Init();
    MediaKeySystemObject *tmp = new MediaKeySystemObject(nullptr);
    MediaKeySystem *tmpSystem = reinterpret_cast<MediaKeySystemObject *>(tmp);
    DRM_ContentProtectionLevel *contentProtectionLevel = reinterpret_cast<DRM_ContentProtectionLevel *>(rawData);

    OH_MediaKeySystem_SetMediaKeySystemCallback(tmpSystem, &TestSystemEventCallBack);
    OH_MediaKeySystem_SetMediaKeySystemCallback(mediaKeySystem, &TestSystemEventCallBack);

    OH_MediaKeySystem_SetCallback(tmpSystem, &TestSystemEventCallBackWithObj);
    OH_MediaKeySystem_SetCallback(mediaKeySystem, &TestSystemEventCallBackWithObj);

    MediaKeySession *session = nullptr;
    OH_MediaKeySystem_CreateMediaKeySession(tmpSystem, contentProtectionLevel, &session);

    OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &ContentProtectionLevel, &session);
    if (session != nullptr) {
        OH_MediaKeySession_Destroy(session);
        session = nullptr;
    }
    GenerateDeviceCertificate();
    OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &ContentProtectionLevel, &session);
    if (session != nullptr) {
        OH_MediaKeySession_Destroy(session);
        session = nullptr;
    }
    DRM_CertificateStatus certStatus = CERT_STATUS_UNAVAILABLE;
    OH_MediaKeySystem_GetCertificateStatus(tmpSystem, &certStatus);
    OH_MediaKeySystem_GetCertificateStatus(mediaKeySystem, &certStatus);

    delete tmp;
    Deinitialize();
    DRM_INFO_LOG("MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemCertificateOperationNdk end");
    return true;
}

bool MediaKeySystemNdkFuzzer::FuzzTestMediaKeySystemLicenseOperationNdk(uint8_t *rawData, size_t size)
{
    if (rawData == nullptr || size < sizeof(int32_t)) {
        return false;
    }
    Init();
    GenerateDeviceCertificate();
    OH_MediaKeySystem_CreateMediaKeySession(mediaKeySystem, &ContentProtectionLevel, &mediaKeySession);
    GenerateLicense();
    DRM_OfflineMediakeyIdArray offlineMediaKeyIds;
    MediaKeySystemObject *tmp = new MediaKeySystemObject(nullptr);
    MediaKeySystem *tmpSystem = reinterpret_cast<MediaKeySystemObject *>(tmp);
    OH_MediaKeySystem_GetOfflineMediaKeyIds(tmpSystem, &offlineMediaKeyIds);
    OH_MediaKeySystem_GetOfflineMediaKeyIds(mediaKeySystem, &offlineMediaKeyIds);
    DRM_OfflineMediaKeyStatus status = OFFLINE_MEDIA_KEY_STATUS_UNKNOWN;
    OH_MediaKeySystem_GetOfflineMediaKeyStatus(tmpSystem, rawData, size, &status);
    OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, offlineMediaKeyIds.ids[0],
        offlineMediaKeyIds.idsLen[0], &status);
    OH_MediaKeySystem_ClearOfflineMediaKeys(tmpSystem, rawData, size);
    OH_MediaKeySystem_ClearOfflineMediaKeys(mediaKeySystem, offlineMediaKeyIds.ids[0],
        offlineMediaKeyIds.idsLen[0]);
    OH_MediaKeySystem_GetOfflineMediaKeyStatus(mediaKeySystem, offlineMediaKeyIds.ids[0],
        offlineMediaKeyIds.idsLen[0], &status);
    OH_MediaKeySystem_Destroy(tmpSystem);
    if (mediaKeySession != nullptr) {
        OH_MediaKeySession_Destroy(mediaKeySession);
        mediaKeySession = nullptr;
    }
    Deinitialize();
    DRM_INFO_LOG("MediaKeysessionNdkFuzzer::FuzzTestMediaKeysessionConfigurationNdk end");
    return true;
}
} // namespace DrmStandard

bool FuzzMediaKeySystemNdk(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }
    MediaKeySystemNdkFuzzer testMediaSystem;
    testMediaSystem.FuzzTestMediaKeySystemConfigurationNdk(data, size);
    testMediaSystem.FuzzTestMediaKeySystemGetNdk(data, size);
    testMediaSystem.FuzzTestMediaKeySystemDeviceCertificateNdk(data, size);
    testMediaSystem.FuzzTestMediaKeySystemCertificateOperationNdk(data, size);
    testMediaSystem.FuzzTestMediaKeySystemLicenseOperationNdk(data, size);
    return true;
}
} // namesapce OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    uint8_t rawData[DATAMAXSIZE] = { 0 };
    int32_t ret = memcpy_s(rawData, DATAMAXSIZE - 1, data, size);
    if (ret != 0) {
        return -1;
    }
    OHOS::FuzzMediaKeySystemNdk(rawData, size);
    return 0;
}
