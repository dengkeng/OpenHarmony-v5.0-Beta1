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

#ifndef TELEPHONY_IMS_CALL_IPC_INTERFACE_CODE_H
#define TELEPHONY_IMS_CALL_IPC_INTERFACE_CODE_H

/* SAID:4006 */
namespace OHOS {
namespace Telephony {
enum class ImsCallInterfaceCode {
    /****************** basic ******************/
    IMS_DIAL = 5000,
    IMS_HANG_UP,
    IMS_REJECT_WITH_REASON,
    IMS_ANSWER,
    IMS_HOLD,
    IMS_UN_HOLD,
    IMS_SWITCH,
    IMS_COMBINE_CONFERENCE,
    IMS_INVITE_TO_CONFERENCE,
    IMS_KICK_OUT_CONFERENCE,
    IMS_SEND_CALL_MEDIA_MODE_REQUEST,
    IMS_CALL_STATE_CHANGE,
    IMS_GET_CALL_DATA,
    IMS_GET_LAST_CALL_FAIL_REASON,
    IMS_SEND_CALL_MEDIA_MODE_RESPONSE,
    IMS_CANCEL_CALL_UPGRADE,
    IMS_REQUEST_CAMERA_CAPABILITIES,

    /****************** dtmf rtt ******************/
    IMS_START_DTMF = 5100,
    IMS_SEND_DTMF,
    IMS_STOP_DTMF,
    IMS_START_RTT,
    IMS_STOP_RTT,

    /****************** ims config ******************/
    IMS_SET_DOMAIN_PREFERENCE_MODE = 5200,
    IMS_GET_DOMAIN_PREFERENCE_MODE,
    IMS_SET_SWITCH_STATUS,
    IMS_GET_SWITCH_STATUS,
    IMS_SET_IMS_CONFIG_STRING,
    IMS_SET_IMS_CONFIG_INT,
    IMS_GET_IMS_CONFIG,
    IMS_SET_IMS_FEATURE,
    IMS_GET_IMS_FEATURE,
    IMS_SET_MUTE,
    IMS_GET_MUTE,
    IMS_SET_IMS_REG_ERROR_REPORT,
    IMS_UPDATE_CAPABILITY,
    IMS_GET_IMPU_FROM_NETWORK,

    /****************** video settings ******************/
    IMS_CTRL_CAMERA = 5300,
    IMS_SET_PREVIEW_WINDOW,
    IMS_SET_DISPLAY_WINDOW,
    IMS_SET_CAMERA_ZOOM,
    IMS_SET_PAUSE_IMAGE,
    IMS_SET_DEVICE_DIRECTION,

    /****************** Supplement ******************/
    IMS_GET_CLIP = 5400,
    IMS_SET_CLIP,
    IMS_SET_CLIR,
    IMS_GET_CLIR,
    IMS_SET_CALL_TRANSFER,
    IMS_GET_CALL_TRANSFER,
    IMS_CAN_SET_CALL_TRANSFER_TIME,
    IMS_SET_CALL_RESTRICTION,
    IMS_GET_CALL_RESTRICTION,
    IMS_SET_CALL_WAITING,
    IMS_GET_CALL_WAITING,
    IMS_SET_COLR,
    IMS_GET_COLR,
    IMS_SET_COLP,
    IMS_GET_COLP,

    /****************** callback ******************/
    IMS_CALL_REGISTER_CALLBACK = 5500,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CALL_IPC_INTERFACE_CODE_H