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

#include "napi_param_utils.h"

namespace OHOS {
namespace DrmStandard {
napi_value NapiParamUtils::GetUndefinedValue(napi_env env)
{
    napi_value result {};
    napi_get_undefined(env, &result);
    return result;
}

napi_status NapiParamUtils::GetValueInt32(const napi_env &env, int32_t &value, napi_value in)
{
    napi_status status = napi_get_value_int32(env, in, &value);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "GetValueInt32 napi_get_value_int32 failed.");
    return status;
}

napi_status NapiParamUtils::SetValueInt32(const napi_env &env, const int32_t &value, napi_value &result)
{
    napi_status status = napi_create_int32(env, value, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueInt32 napi_create_int32 failed.");
    return status;
}

napi_status NapiParamUtils::GetValueInt32(const napi_env &env, const std::string &fieldStr, int32_t &value,
    napi_value in)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_get_named_property(env, in, fieldStr.c_str(), &jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "GetValueInt32 napi_get_named_property failed.");
    status = GetValueInt32(env, value, jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "GetValueInt32 napi_get_value_int32 failed.");
    return status;
}

napi_status NapiParamUtils::SetValueInt32(const napi_env &env, const std::string &fieldStr, const int32_t value,
    napi_value &result)
{
    napi_value jsValue = nullptr;
    napi_status status = SetValueInt32(env, value, jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueInt32 napi_create_int32 failed.");
    status = napi_set_named_property(env, result, fieldStr.c_str(), jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueInt32 napi_create_int32 failed.");
    return status;
}

std::string NapiParamUtils::GetStringArgument(napi_env env, napi_value value)
{
    std::string strValue = "";
    size_t bufLength = 0;
    napi_status status = napi_get_value_string_utf8(env, value, nullptr, 0, &bufLength);
    if (status == napi_ok && bufLength > 0 && bufLength < PATH_MAX) {
        strValue.reserve(bufLength + 1);
        strValue.resize(bufLength);
        status = napi_get_value_string_utf8(env, value, strValue.data(), bufLength + 1, &bufLength);
        if (status == napi_ok) {
            DRM_DEBUG_LOG("argument = %{public}s", strValue.c_str());
        }
    }
    return strValue;
}

napi_status NapiParamUtils::SetValueString(const napi_env &env, const std::string &stringValue, napi_value &result)
{
    napi_status status = napi_create_string_utf8(env, stringValue.c_str(), NAPI_AUTO_LENGTH, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueString napi_create_string_utf8 failed.");
    return status;
}

napi_status NapiParamUtils::SetValueString(const napi_env &env, const std::string &fieldStr,
    const std::string &stringValue, napi_value &result)
{
    napi_value value = nullptr;
    napi_status status = SetValueString(env, stringValue.c_str(), value);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueString failed.");
    status = napi_set_named_property(env, result, fieldStr.c_str(), value);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueString napi_set_named_property failed.");
    return status;
}

napi_status NapiParamUtils::SetValueUint8Array(const napi_env &env, const std::vector<uint8_t> &value,
    napi_value &result)
{
    napi_status status = napi_create_array(env, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueUint8Array napi_create_array failed.");
    for (size_t i = 0; i < value.size(); i++) {
        napi_value item;
        napi_create_int32(env, value[i], &item);
        napi_set_element(env, result, i, item);
    }
    return status;
}

napi_status NapiParamUtils::SetValueUint8Array(const napi_env &env, const std::string &fieldStr,
    const std::vector<uint8_t> &value, napi_value &result)
{
    napi_value jsValue = nullptr;
    napi_status status = SetValueUint8Array(env, value, jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueUint8Array failed.");
    status = napi_set_named_property(env, result, fieldStr.c_str(), jsValue);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "napi_set_named_property failed.");
    return status;
}

napi_status NapiParamUtils::GetValueUint8Array(const napi_env &env, std::vector<uint8_t> &value, napi_value in)
{
    void *reponseData = nullptr;
    size_t reponseDataLen;
    size_t offset;
    napi_value arraybuffer = nullptr;
    napi_typedarray_type type;
    napi_status status = napi_get_typedarray_info(env, in, &type, &reponseDataLen, &reponseData, &arraybuffer, &offset);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "napi_get_typedarray_info failed.");
    uint8_t *reponseDataPtr = reinterpret_cast<uint8_t *>(reponseData);
    std::vector<uint8_t> initDataStr(reponseDataPtr, reponseDataPtr + reponseDataLen);
    value.assign(initDataStr.begin(), initDataStr.end());
    return status;
}

napi_status NapiParamUtils::SetValueBoolean(const napi_env &env, const bool boolValue, napi_value &result)
{
    napi_status status = napi_get_boolean(env, boolValue, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetValueBoolean napi_get_boolean failed.");
    return status;
}

napi_status NapiParamUtils::SetValueMap(const napi_env &env,
    std::map<std::vector<uint8_t>, MediaKeySessionKeyStatus> statusTable, napi_value &statusTableMap)
{
    uint32_t index = 0;
    napi_status status;
    napi_create_array_with_length(env, statusTable.size(), &statusTableMap);
    for (auto itemTmp : statusTable) {
        napi_value jsObject;
        napi_value jsKeyId;
        napi_value jsKeyStatus;
        napi_create_object(env, &jsObject);
        status = napi_create_array_with_length(env, itemTmp.first.size(), &jsKeyId);
        DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "failed to call napi_create_array_with_length");
        for (uint32_t i = 0; i < itemTmp.first.size(); i++) {
            napi_value number = nullptr;
            (void)napi_create_uint32(env, itemTmp.first[i], &number);
            (void)napi_set_element(env, jsKeyId, i, number);
        }
        status = napi_set_named_property(env, jsObject, "keyId", jsKeyId);
        DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "failed to call napi_set_named_property");
        std::string value;
        switch (itemTmp.second) {
            case MEDIA_KEY_SESSION_KEY_STATUS_USABLE:
                value = "USABLE";
                break;
            case MEDIA_KEY_SESSION_KEY_STATUS_EXPIRED:
                value = "EXPIRED";
                break;
            case MEDIA_KEY_SESSION_KEY_STATUS_OUTPUT_NOT_ALLOWED:
                value = "OUTPUT_NOT_ALLOWED";
                break;
            case MEDIA_KEY_SESSION_KEY_STATUS_PENDING:
                value = "PENDING";
                break;
            case MEDIA_KEY_SESSION_KEY_STATUS_INTERNAL_ERROR:
                value = "INTERNAL_ERROR";
                break;
            case MEDIA_KEY_SESSION_KEY_STATUS_USABLE_IN_FUTURE:
                value = "USABLE_IN_FUTURE";
                break;
            default:
                value = "Fault Status";
                break;
        }
        status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &jsKeyStatus);
        DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "failed to call napi_create_string_utf8");
        status = napi_set_named_property(env, jsObject, "value", jsKeyStatus);
        DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "failed to call napi_set_named_property");
        status = napi_set_element(env, statusTableMap, index, jsObject);
        DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "failed to call napi_set_element");
        index++;
    }
    return status;
}

napi_status NapiParamUtils::GetValueOptionsData(const napi_env &env, std::map<std::string, std::string> &valueMap,
    napi_value in)
{
    uint32_t optionalDataCount = 0;
    napi_status status = napi_get_array_length(env, in, &optionalDataCount);
    if (optionalDataCount > 0) {
        for (size_t i = 0; i < optionalDataCount; i++) {
            napi_value tmpData;
            napi_value tmpName;
            napi_value tmpValue;
            size_t nameLength = 0;
            size_t valueLength = 0;
            status = napi_get_element(env, in, i, &tmpData);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "Could not able to read optionalData element!");
            status = napi_get_named_property(env, tmpData, "name", &tmpName);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "Could not able to read optionalData property!");
            status = napi_get_named_property(env, tmpData, "value", &tmpValue);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "Could not able to read optionalData property!");
            status = napi_get_value_string_utf8(env, tmpName, nullptr, 0, &nameLength);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status,
                "Could not able to transfer optionalData buffer info!");
            status = napi_get_value_string_utf8(env, tmpValue, nullptr, 0, &valueLength);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status,
                "Could not able to transfer optionalData buffer info!");
            std::string name(nameLength, 0);
            status = napi_get_value_string_utf8(env, tmpName, &name[0], nameLength + 1, &nameLength);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status,
                "Could not able to transfer optionalData buffer info!");
            std::string value(valueLength, 0);
            status = napi_get_value_string_utf8(env, tmpValue, &value[0], valueLength + 1, &valueLength);
            DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status,
                "Could not able to transfer optionalData buffer info!");
            valueMap.insert(std::make_pair(name, value));
        }
    }
    return status;
}

napi_status NapiParamUtils::SetProvisionRequest(const napi_env &env, const NapiProvisionRequest &provisionRequest,
    napi_value &result)
{
    napi_status status = napi_create_object(env, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetProvisionRequest napi_create_object failed.");
    status = SetValueString(env, "defaultURL", provisionRequest.defaultURL, result);
    status = SetValueUint8Array(env, "data", provisionRequest.data, result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetProvisionRequest SetValueUint8Array failed.");
    return status;
}

napi_status NapiParamUtils::SetMediaKeyRequest(const napi_env &env,
    const IMediaKeySessionService::MediaKeyRequest &mediaKeyRequest, napi_value &result)
{
    napi_status status = napi_create_object(env, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetMediaKeyRequest napi_create_object failed.");
    status = SetValueInt32(env, "mediaKeyRequestType", mediaKeyRequest.requestType, result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetMediaKeyRequest SetValueInt32 failed.");
    status = SetValueUint8Array(env, "data", mediaKeyRequest.mData, result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetMediaKeyRequest SetValueUint8Array failed.");
    status = SetValueString(env, "defaultURL", mediaKeyRequest.mDefaultURL, result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetMediaKeyRequest SetValueString failed.");
    return status;
}

napi_status NapiParamUtils::SetDrmEventInfo(const napi_env &env, DrmEventParame &eventParame, napi_value &result)
{
    napi_status status = napi_create_object(env, &result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetDrmEventInfo napi_create_object failed.");
    status = SetValueUint8Array(env, "info", eventParame.data, result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetDrmEventInfo SetValueUint8Array failed.");
    status = SetValueString(env, "extraInfo", std::to_string(eventParame.extra), result);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetDrmEventInfo SetValueString failed.");
    return status;
}

napi_status NapiParamUtils::SetDrmKeysChangeEventInfo(const napi_env &env, DrmKeysChangeEventParame &eventParame,
    napi_value &statusTable, napi_value &hasNewGoodLicense)
{
    napi_status status = SetValueMap(env, eventParame.statusTable, statusTable);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetDrmKeysChangeEventInfo SetValueMap failed.");
    status = SetValueBoolean(env, eventParame.hasNewGoodLicense, hasNewGoodLicense);
    DRM_NAPI_CHECK_AND_RETURN_LOG(status == napi_ok, status, "SetDrmKeysChangeEventInfo SetValueBoolean failed.");
    return napi_ok;
}
} // namespace DrmStandard
} // namespace OHOS
