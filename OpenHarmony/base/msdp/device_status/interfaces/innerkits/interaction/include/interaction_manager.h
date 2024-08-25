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

#ifndef INTERACTION_MANAGER_H
#define INTERACTION_MANAGER_H

#include <functional>
#include <memory>

#include "nocopyable.h"

#include "coordination_message.h"
#include "drag_data.h"
#include "i_coordination_listener.h"
#include "i_drag_listener.h"
#include "i_event_listener.h"
#include "i_hotarea_listener.h"
#include "i_start_drag_listener.h"
#include "i_subscript_listener.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class InteractionManager {
public:

    static InteractionManager *GetInstance();
    virtual ~InteractionManager() = default;

    /**
     * @brief Registers a listener for screen hopping events of the mouse pointer.
     * @param listener Indicates the listener for screen hopping events of the mouse pointer.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t RegisterCoordinationListener(std::shared_ptr<ICoordinationListener> listener,
        bool isCompatible = false);

    /**
     * @brief Unregisters a listener for screen hopping events of the mouse pointer.
     * @param listener Indicates the listener for screen hopping events of the mouse pointer.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t UnregisterCoordinationListener(std::shared_ptr<ICoordinationListener> listener,
        bool isCompatible = false);

    /**
     * @brief Prepares for screen hopping.
     * @param callback Indicates the callback used to receive the result of enabling or disabling screen hopping.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t PrepareCoordination(std::function<void(const std::string&, CoordinationMessage)> callback,
        bool isCompatible = false);

    /**
     * @brief Cancels the preparation for screen hopping.
     * @param callback Indicates the callback used to receive the result of enabling or disabling screen hopping.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t UnprepareCoordination(std::function<void(const std::string&, CoordinationMessage)> callback,
        bool isCompatible = false);

    /**
     * @brief Starts screen hopping for the mouse pointer.
     * @param s remoteNetworkId Indicates the descriptor of the target input device (network ID) for screen hopping.
     * @param startDeviceId Indicates the ID of the source input device (device ID handle) for screen hopping.
     * @param callback Indicates the callback used to receive the result of starting screen hopping.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t ActivateCoordination(const std::string &remoteNetworkId, int32_t startDeviceId,
        std::function<void(const std::string&, CoordinationMessage)> callback, bool isCompatible = false);

    /**
     * @brief Stops screen hopping for the mouse pointer.
     * @param isUnchained Specifies Whether to disable the cross-device link.
     * The value <b>true</b> means to disable the cross-device link, and <b>false</b> means the opposite.
     * @param callback Indicates the callback used to receive the result of stopping screen hopping.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t DeactivateCoordination(bool isUnchained,
        std::function<void(const std::string&, CoordinationMessage)> callback, bool isCompatible = false);

    /**
     * @brief Obtains the screen hopping status of a mouse pointer.
     * @param networkId Indicates the descriptor of the input device.
     * @param callback Indicates the callback used to receive the screen hopping status.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t GetCoordinationState(const std::string &networkId, std::function<void(bool)> callback,
        bool isCompatible = false);
    
    /**
     * @brief Obtains the screen hopping status of a mouse pointer.
     * @param udId Indicates the descriptor of the input device.
     * @param state Indicates the state of crossing switch.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 12
     */
    int32_t GetCoordinationState(const std::string &udId, bool &state);

    /**
     * @brief Registers a listener for mouse pointer position information on the specified device.
     * @param networkId Indicates the descriptor of the input device.
     * @param listener Indicates the listener for mouse pointer position information on the specified device.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t RegisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener);

    /**
     * @brief Unregisters a listener for mouse pointer position information on the specified device.
     * @param networkId Indicates the descriptor of the input device.
     * @param listener Indicates the listener mouse pointer position information on the specified device.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t UnregisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener = nullptr);

    /**
     * @brief Starts dragging.
     * @param dragData Indicates additional data used for dragging.
     * @param listener Indicates the listener used to notify dragging result etc.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener);

    /**
     * @brief Stops dragging.
     * @param result Indicates the dragging result. The value <b>0</b> means that the dragging operation is successful;
     * <b>1</b> means that the dragging operation is failed; <b>2</b> means that the dragging operation is canceled.
     * @param hasCustomAnimation Specifies whether a custom animation is played when the dragging is successful.
     * The value <b>true</b> means that a custom animation is played,
     * and <b>false</b> means that the default animation is played.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t StopDrag(const DragDropResult &dropResult);

    /**
     * @brief Updates the mouse pointer style used for dragging.
     * @param style Indicates the new mouse pointer style.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t UpdateDragStyle(DragCursorStyle style);

    /**
     * @brief Obtains the PID of the target window.
     * @return Returns a value greater than or equal to 0 in normal cases; returns <b>-1</b> if the PID is invalid.
     * @since 10
     */
    int32_t GetDragTargetPid();

    /**
     * @brief Obtains the unified data key of the target window.
     * @param UdKey Indicates the unified data key of the target window.
     * @return Returns a value greater than or equal to 0 in normal cases; returns <b>-1</b> if the PID is invalid.
     * @since 10
     */
    int32_t GetUdKey(std::string &udKey);

    /**
     * @brief Registers a listener for dragging status changes.
     * @param listener Indicates the listener for dragging status changes.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t AddDraglistener(std::shared_ptr<IDragListener> listener);

    /**
     * @brief Unregisters a listener for dragging status changes.
     * @param listener Indicates the listener for dragging status changes.
     * If no value is passed, all listeners are canceled.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t RemoveDraglistener(std::shared_ptr<IDragListener> listener = nullptr);

    /**
     * @brief Register a listener for dragging corner style changes.
     * @param listener Indicates the listener for dragging corner style changes.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t AddSubscriptListener(std::shared_ptr<ISubscriptListener> listener);

    /**
     * @brief Unregisters a listener for dragging corner style changes.
     * @param listener Indicates the listener for dragging corner style changes.
     * If no value is passed, all listeners are canceled.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t RemoveSubscriptListener(std::shared_ptr<ISubscriptListener> listener);

    /**
     * @brief Displays or hides the dragging window.
     * @param visible Specifies whether to display the dragging window.
     * The value <b>true</b> means to display the dragging window, and <b>false</b> means to hide the window.
     * @param isForce Specifies Enforce the visibility of the drag window, which is applied to this drag.
     * For example, if you set the drag window to Hidden and isForce to true during a drag, the setting does not
     * take effect when the drag window is displayed and isForce is false, and the setting becomes invalid at the
     * end of the current drag.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t SetDragWindowVisible(bool visible, bool isForce = false);

    /**
     * @brief Obtains the position of the touch point or mouse pointer relative to
     * the upper left corner of the shadow thumbnail.
     * @param offsetX Indicates the x coordinate.
     * @param offsetY Indicates the y coordinate.
     * @param width Indicates the width of the shadow thumbnail.
     * @param height Indicates the height of the shadow thumbnail.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 10
     */
    int32_t GetShadowOffset(int32_t &offsetX, int32_t &offsetY, int32_t &width, int32_t &height);

    /**
     * @brief Updates the shadow thumbnail information used for dragging.
     * @param shadowInfo Indicates the new shadow thumbnail information.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 10
     */
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);

    /**
     * @brief Obtains the dragging data.
     * @param dragData Indicates the dragging data.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 10
     */
    int32_t GetDragData(DragData &dragData);

    /**
     * @brief Obtains the current droping type.
     * @param dragAction dropping type while user pressed ctrl or not.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 10
     */
    int32_t GetDragAction(DragAction &dragAction);

    /**
     * @brief Obtains the 'extraInfo' field in the drag data.
     * @param extraInfo Indicates the 'extraInfo' field in the drag data, mainly to save whether to allow drag across
     * the device "drag_allow_distributed" field.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 10
     */
    int32_t GetExtraInfo(std::string &extraInfo);

    /**
     * @brief Registers a listener for screen hot area of the mouse pointer.
     * @param listener Indicates the listener for screen hot area of the mouse pointer.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 11
     */
    int32_t AddHotAreaListener(std::shared_ptr<IHotAreaListener> listener);

    /**
     * @brief Obtains the dragging state.
     * @param dragState Dragging state.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 10
     */
    int32_t GetDragState(DragState &dragState);

    /**
     * @brief Unregisters a listener for screen hot area of the mouse pointer.
     * @param listener Indicates the listener for screen hot area of the mouse pointer.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 9
     */
    int32_t RemoveHotAreaListener(std::shared_ptr<IHotAreaListener> listener = nullptr);

    /**
     * @brief Update preview style when dragging.
     * @param previewStyle Indicates the preview style param for dragged item.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 11
     */
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);

    /**
     * @brief Update preview style with animation when dragging.
     * @param previewStyle Indicates the preview style param for dragged item.
     * @param animation Indicates the animation param for dragged item.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 11
     */
    int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);

    /**
     * @brief Obtains data summary of the drag object.
     * @param summarys Indicates data summary of the drag object.
     * @return Returns <b>0</b> if the operation is successful; returns other values if the operation fails.
     * @since 11
     */
    int32_t GetDragSummary(std::map<std::string, int64_t> &summarys);

    /**
     * @brief Specifies whether to implement 8dp movement in the text editor area.
     * @param enable Indicates whether to enable 8dp movement.
     * The value <b>true</b> means to enable 8dp movement, and the value <b>false</b> means the opposite.
     * @return Returns <b>0</b> if the operation is successful; returns a non-zero value otherwise.
     * @since 11
     */
    int32_t EnterTextEditorArea(bool enable);

    int32_t AddPrivilege();

private:
    InteractionManager() = default;
    DISALLOW_COPY_AND_MOVE(InteractionManager);
    static InteractionManager *instance_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS

#define INTERACTION_MGR OHOS::Msdp::DeviceStatus::InteractionManager::GetInstance()

#endif // INTERACTION_MANAGER_H
