/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef CELLULAR_CALL_CONTROL_IMS_VIDEO_CALL_H
#define CELLULAR_CALL_CONTROL_IMS_VIDEO_CALL_H

#include "call_manager_errors.h"
#include "cellular_call_data_struct.h"
#include "ims_call_types.h"
#include "module_service_utils.h"
#include "singleton.h"
#include "surface.h"
#include "telephony_log_wrapper.h"

namespace OHOS {
namespace Telephony {
class ImsVideoCallControl : public std::enable_shared_from_this<ImsVideoCallControl> {
    DECLARE_DELAYED_SINGLETON(ImsVideoCallControl);

public:
    /**
     * ControlCamera
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param cameraId
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t ControlCamera(int32_t slotId, int32_t callIndex, const std::string &cameraId);

    /**
     * SetPreviewWindow
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPreviewWindow(int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface);

    /**
     * SetDisplayWindow
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param surfaceID Surface id of window object
     * @param surface The surface object of window
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDisplayWindow(int32_t slotId, int32_t callIndex, const std::string &surfaceID, sptr<Surface> surface);

    /**
     * SetCameraZoom
     *
     * @param zoomRatio
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetCameraZoom(float zoomRatio);

    /**
     * SetPausePicture
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param path
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetPausePicture(int32_t slotId, int32_t callIndex, const std::string &path);

    /**
     * SetDeviceDirection
     *
     * @param slotId[in], The slot id
     * @param callIndex Indicates the call index number.
     * @param rotation
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SetDeviceDirection(int32_t slotId, int32_t callIndex, int32_t rotation);

    /**
     * IMS Send Update Call Media Mode Request
     *
     * @param CellularCallInfo
     * @param ImsCallMode
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeRequest(const CellularCallInfo &callInfo, ImsCallMode mode);

    /**
     * IMS Send Update Call Media Mode Response
     *
     * @param CellularCallInfo
     * @param ImsCallMode
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t SendUpdateCallMediaModeResponse(const CellularCallInfo &callInfo, ImsCallMode mode);

    /**
     * Cancel Call Upgrade
     *
     * @param slotId the slot id
     * @param callIndex the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t CancelCallUpgrade(int32_t slotId, int32_t callIndex);

    /**
     * Request Camera Capabilities
     *
     * @param slotId the slot id
     * @param callIndex the call index number.
     * @return Returns TELEPHONY_SUCCESS on success, others on failure.
     */
    int32_t RequestCameraCapabilities(int32_t slotId, int32_t callIndex);

private:
    ImsCallType ConverToImsCallType(ImsCallMode mode);

private:
    ModuleServiceUtils moduleUtils_;
};
} // namespace Telephony
} // namespace OHOS
#endif // CELLULAR_CALL_CONTROL_IMS_H
