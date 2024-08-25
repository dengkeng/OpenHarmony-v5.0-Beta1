/*
 * Copyright (C) 2023  Huawei Device Co., Ltd.
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

#include <map>
#include <vector>
#include "napi_param_utils.h"
#include "drm_enum_napi.h"

namespace OHOS {
namespace DrmStandard {
struct JsEnumInt {
    std::string_view enumName;
    int32_t enumInt;
};

struct JsEnumString {
    std::string_view enumName;
    std::string_view enumString;
};

static const std::vector<struct JsEnumInt> g_listenerType = {
    { "LISTENER_DRM_EVENT", IMediaKeySessionService::ListenerType::LISTENER_DRM_EVENT },
    { "LISTENER_PROVISION_REQUIRED", IMediaKeySessionService::ListenerType::LISTENER_PROVISION_REQUIRED },
    { "LISTENER_KEY_REQUIRED", IMediaKeySessionService::ListenerType::LISTENER_KEY_REQUIRED },
    { "LISTENER_KEY_EXPIRED", IMediaKeySessionService::ListenerType::LISTENER_KEY_EXPIRED },
    { "LISTENER_VENDOR_DEFINED", IMediaKeySessionService::ListenerType::LISTENER_VENDOR_DEFINED },
    { "LISTENER_EXPIRATION_UPDATE", IMediaKeySessionService::ListenerType::LISTENER_EXPIRATION_UPDATE },
    { "LISTENER_KEY_CHANGE", IMediaKeySessionService::ListenerType::LISTENER_KEY_CHANGE },
};

static const std::vector<struct JsEnumInt> g_mediaKeyType = {
    { "MEDIA_KEY_TYPE_OFFLINE", IMediaKeySessionService::MediaKeyType::LICENSETYPE_OFFLINE },
    { "MEDIA_KEY_TYPE_ONLINE", IMediaKeySessionService::MediaKeyType::LICENSETYPE_ONLINE },
};

static const std::vector<struct JsEnumInt> g_offlineMediaKeyStatus = {
    { "OFFLINE_MEDIA_KEY_STATUS_UNKNOWN",
      IMediaKeySessionService::OfflineMediaKeyStatus::OFFLINELICENSESTATUS_UNKNOWN },
    { "OFFLINE_MEDIA_KEY_STATUS_USABLE",
      IMediaKeySessionService::OfflineMediaKeyStatus::OFFLINELICENSESTATUS_USABLE },
    { "OFFLINE_MEDIA_KEY_STATUS_INACTIVE",
      IMediaKeySessionService::OfflineMediaKeyStatus::OFFLINELICENSESTATUS_INACTIVE },
};

static const std::vector<struct JsEnumInt> g_certificateStatus = {
    { "CERT_STATUS_PROVISIONED", IMediaKeySystemService::CertificateStatus::CERT_STATUS_PROVISIONED },
    { "CERT_STATUS_NOT_PROVISIONED", IMediaKeySystemService::CertificateStatus::CERT_STATUS_NOT_PROVISIONED },
    { "CERT_STATUS_EXPIRED", IMediaKeySystemService::CertificateStatus::CERT_STATUS_EXPIRED },
    { "CERT_STATUS_INVALID", IMediaKeySystemService::CertificateStatus::CERT_STATUS_INVALID },
    { "CERT_STATUS_UNAVAILABLE", IMediaKeySystemService::CertificateStatus::CERT_STATUS_UNAVAILABLE },
};

static const std::vector<struct JsEnumInt> g_mediaKeyRequestType = {
    { "MEDIA_KEY_REQUEST_TYPE_UNKNOWN", IMediaKeySessionService::RequestType::REQUEST_TYPE_UNKNOWN },
    { "MEDIA_KEY_REQUEST_TYPE_INITIAL", IMediaKeySessionService::RequestType::REQUEST_TYPE_INITIAL },
    { "MEDIA_KEY_REQUEST_TYPE_RENEWAL", IMediaKeySessionService::RequestType::REQUEST_TYPE_RENEWAL },
    { "MEDIA_KEY_REQUEST_TYPE_RELEASE", IMediaKeySessionService::RequestType::REQUEST_TYPE_RELEASE },
    { "MEDIA_KEY_REQUEST_TYPE_NONE", IMediaKeySessionService::RequestType::REQUEST_TYPE_NONE },
    { "MEDIA_KEY_REQUEST_TYPE_UPDATE", IMediaKeySessionService::RequestType::REQUEST_TYPE_UPDATE },
};

static const std::vector<struct JsEnumInt> g_drmErrorCode = {
    { "ERROR_UNKNOWN", 24700101 },
    { "MAX_SYSTEM_NUM_REACHED", 24700103 },
    { "MAX_SESSION_NUM_REACHED", 24700104 },
    { "SERVICE_FATAL_ERROR", 24700201 },
};

static const std::vector<struct JsEnumInt> g_contentProtectionLevel = {
    { "CONTENT_PROTECTION_LEVEL_UNKNOWN",
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_UNKNOWN },
    { "CONTENT_PROTECTION_LEVEL_SW_CRYPTO",
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_SW_CRYPTO },
    { "CONTENT_PROTECTION_LEVEL_HW_CRYPTO",
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_HW_CRYPTO },
    { "CONTENT_PROTECTION_LEVEL_ENHANCED_HW",
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_ENHANCED_HW },
    { "CONTENT_PROTECTION_LEVEL_MAX",
        IMediaKeySessionService::ContentProtectionLevel::CONTENT_PROTECTION_LEVEL_MAX },
};

static const std::vector<struct JsEnumString> g_preDefinedConfigName = {
    { "CONFIG_DEVICE_VENDOR", "vendor" },
    { "CONFIG_DEVICE_VERSION", "version" },
    { "CONFIG_DEVICE_DESCRIPTION", "description" },
    { "CONFIG_DEVICE_ALGORITHMS", "algorithms" },
    { "CONFIG_DEVICE_UNIQUE_ID", "deviceUniqueId" },
    { "CONFIG_SESSION_MAX", "maxSessionNum" },
    { "CONFIG_SESSION_CURRENT", "currentSessionNum" },
};

static const std::map<std::string_view, const std::vector<struct JsEnumInt> &> g_intEnumClassMap = {
    { "ListenerType", g_listenerType },
    { "MediaKeyType", g_mediaKeyType },
    { "OfflineMediaKeyStatus", g_offlineMediaKeyStatus },
    { "CertificateStatus", g_certificateStatus },
    { "MediaKeyRequestType", g_mediaKeyRequestType },
    { "DrmErrorCode", g_drmErrorCode },
    { "ContentProtectionLevel", g_contentProtectionLevel },
};

static const std::map<std::string_view, const std::vector<struct JsEnumString> &> g_stringEnumClassMap = {
    { "PreDefinedConfigName", g_preDefinedConfigName },
};

napi_value DrmEnumNapi::JsEnumIntInit(napi_env env, napi_value exports)
{
    for (auto it = g_intEnumClassMap.begin(); it != g_intEnumClassMap.end(); it++) {
        auto &enumClassName = it->first;
        auto &enumItemVec = it->second;
        uint32_t vecSize = enumItemVec.size();
        std::vector<napi_value> value;
        value.resize(vecSize);
        for (uint32_t index = 0; index < vecSize; ++index) {
            napi_create_int32(env, enumItemVec[index].enumInt, &value[index]);
        }

        std::vector<napi_property_descriptor> property;
        property.resize(vecSize);
        for (uint32_t index = 0; index < vecSize; ++index) {
            property[index] =
                napi_property_descriptor DECLARE_NAPI_STATIC_PROPERTY(enumItemVec[index].enumName.data(), value[index]);
        }

        auto constructor = [](napi_env env, napi_callback_info info) {
            napi_value jsThis = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
            return jsThis;
        };

        napi_value result = nullptr;
        napi_status status = napi_define_class(env, enumClassName.data(), NAPI_AUTO_LENGTH, constructor, nullptr,
            property.size(), property.data(), &result);
        DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define enum");

        status = napi_set_named_property(env, exports, enumClassName.data(), result);
        DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set result");
    }
    return exports;
}

napi_value DrmEnumNapi::JsEnumStringInit(napi_env env, napi_value exports)
{
    for (auto it = g_stringEnumClassMap.begin(); it != g_stringEnumClassMap.end(); it++) {
        auto &enumClassName = it->first;
        auto &enumItemVec = it->second;
        uint32_t vecSize = enumItemVec.size();
        std::vector<napi_value> value;
        value.resize(vecSize);
        for (uint32_t index = 0; index < vecSize; ++index) {
            napi_create_string_utf8(env, enumItemVec[index].enumString.data(), NAPI_AUTO_LENGTH, &value[index]);
        }

        std::vector<napi_property_descriptor> property;
        property.resize(vecSize);
        for (uint32_t index = 0; index < vecSize; ++index) {
            property[index] =
                napi_property_descriptor DECLARE_NAPI_STATIC_PROPERTY(enumItemVec[index].enumName.data(), value[index]);
        }

        auto constructor = [](napi_env env, napi_callback_info info) {
            napi_value jsThis = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
            return jsThis;
        };

        napi_value result = nullptr;
        napi_status status = napi_define_class(env, enumClassName.data(), NAPI_AUTO_LENGTH, constructor, nullptr,
            property.size(), property.data(), &result);
        DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define enum");

        status = napi_set_named_property(env, exports, enumClassName.data(), result);
        DRM_CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set result");
    }
    return exports;
}

napi_value DrmEnumNapi::Init(napi_env env, napi_value exports)
{
    JsEnumIntInit(env, exports);
    JsEnumStringInit(env, exports);
    return exports;
}
} // namespace drm
} // namespace OHOS
