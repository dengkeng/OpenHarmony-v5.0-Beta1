/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "devicestatus_event.h"

#include <js_native_api.h>
#include <map>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "DeviceStatusEvent"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t EVENT_MAP_MAX { 20 };
constexpr size_t EVENT_LIST_MAX { 30 };
} // namespace

DeviceStatusEvent::DeviceStatusEvent(napi_env env)
{
    env_ = env;
}

DeviceStatusEvent::~DeviceStatusEvent()
{
    eventOnces_.clear();
    events_.clear();
}

bool DeviceStatusEvent::On(int32_t eventType, napi_value handler, bool isOnce)
{
    FI_HILOGD("On for event:%{public}d, isOnce:%{public}d", eventType, isOnce);
    std::lock_guard<std::mutex> guard(mutex_);
    if ((events_.size() > EVENT_MAP_MAX) || (eventOnces_.size() > EVENT_MAP_MAX)) {
        FI_HILOGE("events_ or eventOnces_ size over");
        return false;
    }
    if (events_[eventType].size() > EVENT_LIST_MAX || eventOnces_[eventType].size() > EVENT_LIST_MAX) {
        FI_HILOGE("list size over");
        return false;
    }
    if (isOnce) {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, eventOnces_)) {
            FI_HILOGE("Failed to save eventOnces_ callback");
            return false;
        }
    } else {
        if (!SaveCallbackByEvent(eventType, handler, isOnce, events_)) {
            FI_HILOGE("Failed to save events_ callback");
            return false;
        }
    }
    return true;
}

bool DeviceStatusEvent::SaveCallbackByEvent(int32_t eventType, napi_value handler, bool isOnce,
    std::map<int32_t, std::list<std::shared_ptr<DeviceStatusEventListener>>> events_)
{
    CALL_DEBUG_ENTER;
    napi_ref onHandlerRef = nullptr;
    napi_status status = napi_create_reference(env_, handler, 1, &onHandlerRef);
    if (status != napi_ok) {
        FI_HILOGE("Failed to napi_create_reference");
        return false;
    }
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("eventType:%{public}d not exists", eventType);
        events_[eventType] = std::list<std::shared_ptr<DeviceStatusEventListener>>();
    }
    if (events_[eventType].empty()) {
        FI_HILOGE("events_ save callback");
        SaveCallback(eventType, onHandlerRef, isOnce);
        return true;
    }
    if (!IsNoExistCallback(events_[eventType], handler, eventType)) {
        FI_HILOGE("Callback already exists");
        return false;
    }
    SaveCallback(eventType, onHandlerRef, isOnce);
    return true;
}

bool DeviceStatusEvent::IsNoExistCallback(std::list<std::shared_ptr<DeviceStatusEventListener>>,
    napi_value handler, int32_t eventType)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    bool equal = false;
    for (const auto &item : events_[eventType]) {
        napi_status napiStatus = napi_get_reference_value(env_, item->onHandlerRef, &result);
        if (napiStatus != napi_ok) {
            FI_HILOGE("Failed to napi_get_reference_value");
            return false;
        }
        napiStatus = napi_strict_equals(env_, result, handler, &equal);
        if (napiStatus != napi_ok) {
            FI_HILOGE("Failed to napi_strict_equals");
            return false;
        }
        if (equal) {
            FI_HILOGE("Map callback is exist");
            return false;
        }
    }
    return true;
}

void DeviceStatusEvent::SaveCallback(int32_t eventType, napi_ref onHandlerRef, bool isOnce)
{
    auto listener = std::make_shared<DeviceStatusEventListener>();
    listener->onHandlerRef = onHandlerRef;
    if (isOnce) {
        eventOnces_[eventType].push_back(listener);
    } else {
        events_[eventType].push_back(listener);
    }
    FI_HILOGD("Add handler to list %{public}d", eventType);
}

bool DeviceStatusEvent::Off(int32_t eventType, napi_value handler)
{
    FI_HILOGD("DeviceStatusEvent off in for event:%{public}d", eventType);
    std::lock_guard<std::mutex> guard(mutex_);
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("eventType %{public}d not found", eventType);
        return false;
    }
    bool equal = false;
    napi_value result = nullptr;

    for (const auto &listener : events_[eventType]) {
        napi_status status = napi_get_reference_value(env_, listener->onHandlerRef, &result);
        if (status != napi_ok) {
            FI_HILOGE("Failed to napi_get_reference_value");
            return false;
        }
        status = napi_strict_equals(env_, result, handler, &equal);
        if (status != napi_ok) {
            FI_HILOGE("Failed to napi_strict_equals");
            return false;
        }
        if (equal) {
            FI_HILOGI("Delete handler from list %{public}d", eventType);
            status = napi_delete_reference(env_, listener->onHandlerRef);
            if (status != napi_ok) {
                FI_HILOGW("Failed to napi_delete_reference");
            }
            events_[eventType].remove(listener);
            break;
        }
    }
    FI_HILOGI("%{public}zu listeners in the list of %{public}d",
        events_[eventType].size(), eventType);
    return events_[eventType].empty();
}

bool DeviceStatusEvent::OffOnce(int32_t eventType, napi_value handler)
{
    FI_HILOGD("DeviceStatusEvent OffOnce in for event:%{public}d", eventType);
    auto iter = eventOnces_.find(eventType);
    if (iter == eventOnces_.end()) {
        FI_HILOGE("eventType %{public}d not found", eventType);
        return false;
    }
    bool equal = false;
    napi_value result = nullptr;
    for (const auto &listener : eventOnces_[eventType]) {
        napi_get_reference_value(env_, listener->onHandlerRef, &result);
        napi_strict_equals(env_, result, handler, &equal);
        if (equal) {
            FI_HILOGI("Delete once handler from list %{public}d", eventType);
            napi_status status = napi_delete_reference(env_, listener->onHandlerRef);
            if (status != napi_ok) {
                FI_HILOGW("Failed to napi_delete_reference");
            }
            eventOnces_[eventType].remove(listener);
            break;
        }
    }
    FI_HILOGI("%{public}zu listeners in the once list of %{public}d",
        eventOnces_[eventType].size(), eventType);
    return events_[eventType].empty();
}

bool DeviceStatusEvent::RemoveAllCallback(int32_t eventType)
{
    CALL_DEBUG_ENTER;
    auto iter = events_.find(eventType);
    if (iter == events_.end()) {
        FI_HILOGE("evenType %{public}d not found", eventType);
        return false;
    }
    events_.erase(eventType);
    return true;
}

void DeviceStatusEvent::CheckRet(int32_t eventType, size_t argc, int32_t value,
    std::shared_ptr<DeviceStatusEventListener> &typeHandler)
{
    CHKPV(typeHandler);
    napi_value handler = nullptr;
    napi_status status = napi_ok;
    status = napi_get_reference_value(env_, typeHandler->onHandlerRef, &handler);
    if (status != napi_ok) {
        FI_HILOGE("OnEvent handler for %{public}d failed, status:%{public}d", eventType, status);
        return;
    }
    napi_value result = nullptr;
    SendRet(eventType, value, result);
    napi_value callResult = nullptr;
    FI_HILOGD("Report to hap");
    status = napi_call_function(env_, nullptr, handler, argc, &result, &callResult);
    if (status != napi_ok) {
        FI_HILOGE("CheckRet:napi_call_function for %{public}d failed, status:%{public}d", eventType, status);
        return;
    }
}

void DeviceStatusEvent::SendRet(int32_t eventType, int32_t value, napi_value &result)
{
    napi_status status = napi_create_object(env_, &result);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create object");
        return;
    }
    napi_value tmpValue = nullptr;
    status = napi_create_int32(env_, eventType, &tmpValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create object");
        return;
    }
    status = napi_set_named_property(env_, result, "type", tmpValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set name");
        return;
    }

    status = napi_create_int32(env_, value, &tmpValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to create value");
        return;
    }
    status = napi_set_named_property(env_, result, "value", tmpValue);
    if (status != napi_ok) {
        FI_HILOGE("Failed to set_named");
        return;
    }
}

void DeviceStatusEvent::OnEvent(int32_t eventType, size_t argc, int32_t value, bool isOnce)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("OnEvent for %{public}d, isOnce:%{public}d", eventType, isOnce);
    std::map<int32_t, std::list<std::shared_ptr<DeviceStatusEventListener>>>::iterator typeHandler;
    if (isOnce) {
        typeHandler = eventOnces_.find(eventType);
        if (typeHandler == eventOnces_.end()) {
            FI_HILOGE("OnEvent eventType %{public}d not found", eventType);
            return;
        }
    } else {
        typeHandler = events_.find(eventType);
        if (typeHandler == events_.end()) {
            FI_HILOGE("OnEvent eventType %{public}d not found", eventType);
            return;
        }
    }
    FI_HILOGD("%{public}zu callbacks of eventType %{public}d are sent",
        typeHandler->second.size(), eventType);
    for (auto handler : typeHandler->second) {
        CheckRet(eventType, argc, value, handler);
    }
}

void DeviceStatusEvent::ClearEventMap()
{
    for (const auto &iter : events_) {
        for (const auto &eventListener : iter.second) {
            napi_status status = napi_delete_reference(env_, eventListener->onHandlerRef);
            if (status != napi_ok) {
                FI_HILOGW("Failed to napi_delete_reference");
            }
        }
    }
    for (const auto &iter : eventOnces_) {
        for (const auto &eventListener : iter.second) {
            napi_status status = napi_delete_reference(env_, eventListener->onHandlerRef);
            if (status != napi_ok) {
                FI_HILOGW("Failed to napi_delete_reference");
                napi_delete_reference(env_, eventListener->onHandlerRef);
            }
        }
    }
    events_.clear();
    eventOnces_.clear();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
