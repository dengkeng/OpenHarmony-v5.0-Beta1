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

#ifndef POINTER_DRAWING_MANAGER_H
#define POINTER_DRAWING_MANAGER_H

#include <iostream>
#include <list>

#include <ui/rs_canvas_node.h>
#include <ui/rs_surface_node.h>
#include <transaction/rs_transaction.h>
#include <transaction/rs_interfaces.h>

#include "draw/canvas.h"
#include "nocopyable.h"
#include "pixel_map.h"
#include "window.h"

#include "device_observer.h"
#include "i_pointer_drawing_manager.h"
#include "mouse_event_normalize.h"
#include "setting_observer.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
struct isMagicCursor {
    std::string name;
    bool isShow { false };
};

class PointerDrawingManager final : public IPointerDrawingManager,
                                    public IDeviceObserver,
                                    public std::enable_shared_from_this<PointerDrawingManager> {
public:
    PointerDrawingManager();
    DISALLOW_COPY_AND_MOVE(PointerDrawingManager);
    ~PointerDrawingManager() override = default;
    void DrawPointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
        const PointerStyle pointerStyle, Direction direction) override;
    void UpdateDisplayInfo(const DisplayInfo& displayInfo) override;
    void OnDisplayInfo(const DisplayGroupInfo& displayGroupInfo) override;
    void OnWindowInfo(const WinInfo &info) override;
    void UpdatePointerDevice(bool hasPointerDevice, bool isPointerVisible, bool isHotPlug) override;
    bool Init() override;
    int32_t SetPointerColor(int32_t color) override;
    int32_t GetPointerColor() override;
    void DeletePointerVisible(int32_t pid) override;
    int32_t SetPointerVisible(int32_t pid, bool visible, int32_t priority) override;
    bool GetPointerVisible(int32_t pid) override;
    int32_t SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
        bool isUiExtension = false) override;
    int32_t ClearWindowPointerStyle(int32_t pid, int32_t windowId) override;
    int32_t GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
        bool isUiExtension = false) override;
    int32_t SetPointerSize(int32_t size) override;
    int32_t GetPointerSize() override;
    void DrawPointerStyle(const PointerStyle& pointerStyle) override;
    bool IsPointerVisible() override;
    void SetPointerLocation(int32_t x, int32_t y) override;
    void AdjustMouseFocus(Direction direction, ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);
    void SetMouseDisplayState(bool state) override;
    bool GetMouseDisplayState() const override;
    int32_t SetCustomCursor(void* pixelMap, int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY) override;
    int32_t SetMouseIcon(int32_t pid, int32_t windowId, void* pixelMap) override;
    int32_t SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) override;
    PointerStyle GetLastMouseStyle() override;
    std::map<MOUSE_ICON, IconStyle> GetMouseIconPath() override;
    IconStyle GetIconStyle(const MOUSE_ICON mouseStyle) override;
    bool HasMagicCursor();
    int32_t DrawCursor(const MOUSE_ICON mouseStyle);
    int32_t SwitchPointerStyle() override;
private:
    IconStyle GetIconType(MOUSE_ICON mouseIcon);
    void DrawLoadingPointerStyle(const MOUSE_ICON mouseStyle);
    void DrawRunningPointerAnimate(const MOUSE_ICON mouseStyle);
    void CreatePointerWindow(int32_t displayId, int32_t physicalX, int32_t physicalY, Direction direction);
    sptr<OHOS::Surface> GetLayer();
    sptr<OHOS::SurfaceBuffer> GetSurfaceBuffer(sptr<OHOS::Surface> layer) const;
    void DoDraw(uint8_t *addr, uint32_t width, uint32_t height, const MOUSE_ICON mouseStyle = MOUSE_ICON::DEFAULT);
    void DrawPixelmap(OHOS::Rosen::Drawing::Canvas &canvas, const MOUSE_ICON mouseStyle);
    void DrawManager();
    void FixCursorPosition(int32_t &physicalX, int32_t &physicalY);
    std::shared_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);
    void UpdatePointerVisible();
    int32_t UpdateDefaultPointerStyle(int32_t pid, int32_t windowId, PointerStyle style, bool isUiExtension = false);
    void CheckMouseIconPath();
    void InitStyle();
    int32_t InitLayer(const MOUSE_ICON mouseStyle);
    int32_t SetPointerStylePreference(PointerStyle pointerStyle);
    void UpdateMouseStyle();
    int32_t UpdateCursorProperty(void* pixelMap, const int32_t &focusX, const int32_t &focusY);
    void RotateDegree(Direction direction);
    void DrawMovePointer(int32_t displayId, int32_t physicalX, int32_t physicalY,
        const PointerStyle pointerStyle, Direction direction);
    void AdjustMouseFocusByDirection0(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);
    void AdjustMouseFocusByDirection90(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);
    void AdjustMouseFocusByDirection180(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);
    void AdjustMouseFocusByDirection270(ICON_TYPE iconType, int32_t &physicalX, int32_t &physicalY);
    void CreateMagicCursorChangeObserver();
    void CreatePointerSwiftObserver(isMagicCursor& item);
    int32_t GetIndependentPixels();
    bool CheckPointerStyleParam(int32_t windowId, PointerStyle pointerStyle);
    std::map<MOUSE_ICON, IconStyle>& GetMouseIcons();
    void UpdateIconPath(const MOUSE_ICON mouseStyle, std::string iconPath);

private:
    struct PidInfo {
        int32_t pid { 0 };
        bool visible { false };
    };
    bool hasDisplay_ { false };
    DisplayInfo displayInfo_ {};
    bool hasPointerDevice_ { false };
    int32_t lastPhysicalX_ { -1 };
    int32_t lastPhysicalY_ { -1 };
    PointerStyle lastMouseStyle_ {};
    PointerStyle currentMouseStyle_ {};
    int32_t pid_ { 0 };
    int32_t windowId_ { 0 };
    int32_t imageWidth_ { 0 };
    int32_t imageHeight_ { 0 };
    int32_t canvasWidth_ = 64;
    int32_t canvasHeight_ = 64;
    std::map<MOUSE_ICON, IconStyle> mouseIcons_;
    std::list<PidInfo> pidInfos_;
    bool mouseDisplayState_ { false };
    bool mouseIconUpdate_ { false };
    std::unique_ptr<OHOS::Media::PixelMap> userIcon_ { nullptr };
    uint64_t screenId_ { 0 };
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode_;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode_;
    int32_t userIconHotSpotX_ { 0 };
    int32_t userIconHotSpotY_ { 0 };
    int32_t tempPointerColor_ { -1 };
    Direction lastDirection_ { DIRECTION0 };
    Direction currentDirection_ { DIRECTION0 };
    isMagicCursor hasMagicCursor_;
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_DRAWING_MANAGER_H
