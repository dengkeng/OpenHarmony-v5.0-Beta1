/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "pointerstyle_fuzzer.h"

#include "ipc_skeleton.h"
#include "securec.h"

#include "input_manager.h"

namespace OHOS {
namespace MMI {
template <class T> size_t GetObject(const uint8_t *data, size_t size, T &object)
{
    size_t objectSize = sizeof(object);
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

size_t GetString(const uint8_t *data, size_t size, char *object, size_t objectSize)
{
    if (objectSize > size) {
        return 0;
    }
    errno_t ret = memcpy_s(&object, objectSize, data, objectSize);
    if (ret != EOK) {
        return 0;
    }
    return objectSize;
}

void UpdateHotAreas(const uint8_t *data, size_t size, WindowInfo &windowInfo)
{
    size_t startPos = 0;
    std::vector<Rect> defaultHotAreasInfo;
    std::vector<Rect> pointerHotAreasInfo;
    for (size_t j = 0; j < WindowInfo::MAX_HOTAREA_COUNT; ++j) {
        Rect defaultRect;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.height);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, defaultRect.y);
        defaultHotAreasInfo.push_back(defaultRect);
        Rect pointerRect;
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.height);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.width);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.x);
        startPos += GetObject<int32_t>(data + startPos, size - startPos, pointerRect.y);
        pointerHotAreasInfo.push_back(pointerRect);
    }
    windowInfo.defaultHotAreas = defaultHotAreasInfo;
    windowInfo.pointerHotAreas = pointerHotAreasInfo;
}

void UpdateDisplayInfo(const uint8_t *data, size_t size, int32_t windowId)
{
    DisplayGroupInfo displayGroupInfo;
    size_t startPos = 0;
    size_t stringSize = 4;
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.width);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.height);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayGroupInfo.focusWindowId);
    std::vector<WindowInfo> windowsInfo;
    std::vector<DisplayInfo> displaysInfo;
    WindowInfo windowInfo;
    windowInfo.id = windowId;
    windowInfo.pid = IPCSkeleton::GetCallingPid();
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.uid);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.x);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.y);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.width);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowInfo.area.height);
    UpdateHotAreas(data, size, windowInfo);
    windowsInfo.push_back(windowInfo);

    DisplayInfo displayInfo;
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.id);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.x);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.y);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.width);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.height);
    startPos += GetObject<int32_t>(data + startPos, size - startPos, displayInfo.dpi);
    char name[] = "name";
    startPos += GetString(data + startPos, size - startPos, name, stringSize);
    displayInfo.name = name;
    char uniq[] = "uniq";
    GetString(data + startPos, size - startPos, uniq, stringSize);
    displayInfo.uniq = uniq;
    displaysInfo.push_back(displayInfo);
    displayGroupInfo.windowsInfo = windowsInfo;
    displayGroupInfo.displaysInfo = displaysInfo;
    InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo);
}

void PointerStyleFuzzTest(const uint8_t *data, size_t size)
{
    int32_t windowId;
    size_t startPos = 0;
    startPos += GetObject<int32_t>(data + startPos, size - startPos, windowId);
    UpdateDisplayInfo(data, size, windowId);
    PointerStyle pointerStyle;
    GetObject<int32_t>(data + startPos, size - startPos, pointerStyle.id);
    InputManager::GetInstance()->SetPointerStyle(windowId, pointerStyle);
    InputManager::GetInstance()->GetPointerStyle(windowId, pointerStyle);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::MMI::PointerStyleFuzzTest(data, size);
    return 0;
}