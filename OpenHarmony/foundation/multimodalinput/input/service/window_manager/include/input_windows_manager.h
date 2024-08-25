/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef INPUT_WINDOWS_MANAGER_H
#define INPUT_WINDOWS_MANAGER_H

#include <vector>

#include "libinput.h"
#include "nocopyable.h"
#include "pixel_map.h"
#include "singleton.h"

#include "extra_data.h"
#include "input_display_bind_helper.h"
#include "input_event.h"
#include "input_event_data_transformation.h"
#include "knuckle_drawing_manager.h"
#include "knuckle_dynamic_drawing_manager.h"
#include "pointer_event.h"
#include "pointer_style.h"
#include "window_info.h"
#include "window_manager_lite.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
struct MouseLocation {
    int32_t displayId { -1 };
    int32_t physicalX { 0 };
    int32_t physicalY { 0 };
};

struct Coordinate2D {
    double x;
    double y;
};

struct CursorPosition {
    int32_t displayId { -1 };
    Coordinate2D cursorPos {};
};

struct WindowInfoEX {
    WindowInfo window;
    bool flag { false };
};

class InputWindowsManager final {
    DECLARE_DELAYED_SINGLETON(InputWindowsManager);
public:
    DISALLOW_COPY_AND_MOVE(InputWindowsManager);
    void Init(UDSServer& udsServer);
    void SetMouseFlag(bool state);
    bool GetMouseFlag();
    void JudgMouseIsDownOrUp(bool dragState);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetClientFd(std::shared_ptr<PointerEvent> pointerEvent, int32_t windowId);
    bool HandleWindowInputType(const WindowInfo &window, std::shared_ptr<PointerEvent> pointerEvent);
    void UpdateCaptureMode(const DisplayGroupInfo &displayGroupInfo);
    void UpdateDisplayInfo(DisplayGroupInfo &displayGroupInfo);
    void UpdateDisplayInfoExtIfNeed(DisplayGroupInfo &displayGroupInfo, bool needUpdateDisplayExt);
    void UpdateWindowInfo(const WindowGroupInfo &windowGroupInfo);
    void SetWindowPointerStyle(WindowArea area, int32_t pid, int32_t windowId);
    void UpdateWindowPointerVisible(int32_t pid);
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    int32_t GetWindowPid(int32_t windowId, const std::vector<WindowInfo> &windowsInfo) const;
    int32_t GetWindowPid(int32_t windowId) const;
    int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode);
    bool GetMouseIsCaptureMode() const;
    void DeviceStatusChanged(int32_t deviceId, const std::string &sysUid, const std::string devStatus);
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t AppendExtraData(const ExtraData& extraData);
    bool IsWindowVisible(int32_t pid);
    void ClearExtraData();
    ExtraData GetExtraData() const;
    const std::vector<WindowInfo>& GetWindowGroupInfoByDisplayId(int32_t displayId) const;
    std::pair<double, double> TransformWindowXY(const WindowInfo &window, double logicX, double logicY) const;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t GetPidAndUpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
    int32_t UpdateTarget(std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t CheckWindowIdPermissionByPid(int32_t windowId, int32_t pid);

#ifdef OHOS_BUILD_ENABLE_POINTER
    MouseLocation GetMouseInfo();
    CursorPosition GetCursorPos();
    CursorPosition ResetCursorPos();
    void SetGlobalDefaultPointerStyle();
    void UpdateAndAdjustMouseLocation(int32_t& displayId, double& x, double& y, bool isRealData = true);
    const DisplayGroupInfo& GetDisplayGroupInfo();
    int32_t SetHoverScrollState(bool state);
    bool GetHoverScrollState() const;
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle, bool isUiExtension = false);
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
        bool isUiExtension = false) const;
    void SetUiExtensionInfo(bool isUiExtension, int32_t uiExtensionPid, int32_t uiExtensionWindoId);
    void DispatchPointer(int32_t pointerAction);
    void SendPointerEvent(int32_t pointerAction);
    PointerStyle GetLastPointerStyle() const;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    bool IsNeedRefreshLayer(int32_t windowId);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif //OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void AdjustDisplayCoordinate(const DisplayInfo& displayInfo, double& physicalX, double& physicalY) const;
    bool TouchPointToDisplayPoint(int32_t deviceId, struct libinput_event_touch* touch,
        EventTouch& touchInfo, int32_t& targetDisplayId);
    void ReverseRotateScreen(const DisplayInfo& info, const double x, const double y, Coordinate2D& cursorPos) const;
    void RotateScreen(const DisplayInfo& info, PhysicalCoordinate& coord) const;
    bool TransformTipPoint(struct libinput_event_tablet_tool* tip, PhysicalCoordinate& coord, int32_t& displayId) const;
    bool CalculateTipPoint(struct libinput_event_tablet_tool* tip,
        int32_t& targetDisplayId, PhysicalCoordinate& coord) const;
    const DisplayInfo *GetDefaultDisplayInfo() const;
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_ANCO
    void UpdateWindowInfoExt(const WindowGroupInfo &windowGroupInfo, const DisplayGroupInfo &displayGroupInfo);
    void UpdateShellWindow(const WindowInfo &window);
    void UpdateDisplayInfoExt(const DisplayGroupInfo &displayGroupInfo);
    bool IsInAncoWindow(const WindowInfo &window, int32_t x, int32_t y) const;
    bool IsAncoWindow(const WindowInfo &window) const;
    bool IsAncoWindowFocus(const WindowInfo &window) const;
    void SimulatePointerExt(std::shared_ptr<PointerEvent> pointerEvent);
    void DumpAncoWindows(std::string& out) const;
#endif // OHOS_BUILD_ENABLE_ANCO

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool UpdateDisplayId(int32_t& displayId);
    void DrawTouchGraphic(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t UpdateTargetPointer(std::shared_ptr<PointerEvent> pointerEvent);
    const DisplayInfo* GetPhysicalDisplay(int32_t id) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
    void UpdatePointerChangeAreas();
#endif // OHOS_BUILD_ENABLE_POINTER
    std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId);
    void GetTargetWindowIds(int32_t pointerItemId, std::vector<int32_t> &windowIds);
    void AddTargetWindowIds(int32_t pointerItemId, int32_t windowId);
    void ClearTargetWindowIds();
    bool IsTransparentWin(void* pixelMap, int32_t logicalX, int32_t logicalY);
    int32_t SetCurrentUser(int32_t userId);

private:
    int32_t GetDisplayId(std::shared_ptr<InputEvent> inputEvent) const;
    void PrintWindowInfo(const std::vector<WindowInfo> &windowsInfo);
    void PrintDisplayInfo();
    void PrintWindowGroupInfo(const WindowGroupInfo &windowGroupInfo);
    void CheckFocusWindowChange(const DisplayGroupInfo &displayGroupInfo);
    void CheckZorderWindowChange(const std::vector<WindowInfo> &oldWindowsInfo,
        const std::vector<WindowInfo> &newWindowsInfo);
    void UpdateDisplayIdAndName();
    void UpdatePointerAction(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsNeedDrawPointer(PointerEvent::PointerItem &pointerItem) const;
    void UpdateDisplayInfoByIncrementalInfo(const WindowInfo &window, DisplayGroupInfo &displayGroupInfo);
    void UpdateWindowsInfoPerDisplay(const DisplayGroupInfo &displayGroupInfo);
    std::pair<int32_t, int32_t> TransformSampleWindowXY(int32_t logicX, int32_t logicY) const;
    bool IsValidZorderWindow(const WindowInfo &window, const std::shared_ptr<PointerEvent>& pointerEvent);
    void UpdateTopBottomArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateLeftRightArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void UpdateInnerAngleArea(const Rect &windowArea, std::vector<int32_t> &pointerChangeAreas,
        std::vector<Rect> &windowHotAreas);
    void CoordinateCorrection(int32_t width, int32_t height, int32_t &integerX, int32_t &integerY);
    void GetWidthAndHeight(const DisplayInfo* displayInfo, int32_t &width, int32_t &height);

#ifdef OHOS_BUILD_ENABLE_POINTER
    void GetPointerStyleByArea(WindowArea area, int32_t pid, int32_t winId, PointerStyle& pointerStyle);
    int32_t UpdateMouseTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdatePointerEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent, const WindowInfo& touchWindow);
    void NotifyPointerToWindow();
    void OnSessionLost(SessionPtr session);
    void InitPointerStyle();
    int32_t UpdatePoinerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle);
    int32_t UpdateSceneBoardPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
        bool isUiExtension = false);
    int32_t UpdateTouchPadTarget(std::shared_ptr<PointerEvent> pointerEvent);
    std::optional<WindowInfo> SelectWindowInfo(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent>& pointerEvent);
    std::optional<WindowInfo> GetWindowInfo(int32_t logicalX, int32_t logicalY);
    bool IsInsideDisplay(const DisplayInfo& displayInfo, int32_t physicalX, int32_t physicalY);
    void FindPhysicalDisplay(const DisplayInfo& displayInfo, int32_t& physicalX,
        int32_t& physicalY, int32_t& displayId);
    void InitMouseDownInfo();
    bool SelectPointerChangeArea(const WindowInfo &windowInfo, PointerStyle &pointerStyle,
        int32_t logicalX, int32_t logicalY);
    void UpdatePointerChangeAreas(const DisplayGroupInfo &displayGroupInfo);
#endif // OHOS_BUILD_ENABLE_POINTER

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
void PointerDrawingManagerOnDisplayInfo(const DisplayGroupInfo &displayGroupInfo);
bool NeedUpdatePointDrawFlag(const std::vector<WindowInfo> &windows);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool SkipAnnotationWindow(uint32_t flag, int32_t toolType);
    int32_t UpdateTouchScreenTarget(std::shared_ptr<PointerEvent> pointerEvent);
    void PullEnterLeaveEvent(int32_t logicalX, int32_t logicalY,
        const std::shared_ptr<PointerEvent> pointerEvent, const WindowInfo* touchWindow);
    void DispatchTouch(int32_t pointerAction);
    const DisplayInfo* FindPhysicalDisplayInfo(const std::string& uniq) const;
    void GetPhysicalDisplayCoord(struct libinput_event_touch* touch,
        const DisplayInfo& info, EventTouch& touchInfo);
#endif // OHOS_BUILD_ENABLE_TOUCH

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool IsInHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, const WindowInfo &window) const;
    bool InWhichHotArea(int32_t x, int32_t y, const std::vector<Rect> &rects, PointerStyle &pointerStyle) const;
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
    int32_t UpdateJoystickTarget(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_JOYSTICK

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    void UpdateDisplayMode();
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

private:
    UDSServer* udsServer_ { nullptr };
#ifdef OHOS_BUILD_ENABLE_POINTER
    bool isUiExtension_ { false };
    int32_t uiExtensionPid_ { -1 };
    int32_t uiExtensionWindowId_ { -1 };
    int32_t firstBtnDownWindowId_ { -1 };
    int32_t lastLogicX_ { -1 };
    int32_t lastLogicY_ { -1 };
    WindowInfo lastWindowInfo_;
    std::shared_ptr<PointerEvent> lastPointerEvent_ { nullptr };
    std::map<int32_t, std::map<int32_t, PointerStyle>> pointerStyle_;
    std::map<int32_t, std::map<int32_t, PointerStyle>> uiExtensionPointerStyle_;
    WindowInfo mouseDownInfo_;
    PointerStyle globalStyle_;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    int32_t lastTouchLogicX_ { -1 };
    int32_t lastTouchLogicY_ { -1 };
    WindowInfo lastTouchWindowInfo_;
    std::shared_ptr<PointerEvent> lastTouchEvent_ { nullptr };
#endif // OHOS_BUILD_ENABLE_POINTER
    DisplayGroupInfo displayGroupInfoTmp_;
    DisplayGroupInfo displayGroupInfo_;
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay_;
    PointerStyle lastPointerStyle_ {.id = -1};
    PointerStyle dragPointerStyle_ {.id = -1};
    MouseLocation mouseLocation_ = { -1, -1 };
    CursorPosition cursorPos_ {};
    std::map<int32_t, WindowInfoEX> touchItemDownInfos_;
    std::map<int32_t, std::vector<Rect>> windowsHotAreas_;
    InputDisplayBindHelper bindInfo_;
    struct CaptureModeInfo {
        int32_t windowId { -1 };
        bool isCaptureMode { false };
    } captureModeInfo_;
    ExtraData extraData_;
    bool haveSetObserver_ { false };
    bool dragFlag_ { false };
    bool isDragBorder_ { false };
    bool pointerDrawFlag_ { false };
    DisplayMode displayMode_ { DisplayMode::UNKNOWN };
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr { nullptr };
    bool mouseFlag_ {false};
    std::map<int32_t, std::vector<int32_t>> targetWindowIds_;
    int32_t pointerActionFlag_ { -1 };
    int32_t currentUserId_ { -1 };
    std::shared_ptr<KnuckleDynamicDrawingManager> knuckleDynamicDrawingManager_ { nullptr };
};

#define WinMgr ::OHOS::DelayedSingleton<InputWindowsManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_WINDOWS_MANAGER_H