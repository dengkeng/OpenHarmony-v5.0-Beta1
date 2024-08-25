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

#ifndef TELEPHONY_IMS_CALL_CALLBACK_IPC_INTERFACE_CODE_H
#define TELEPHONY_IMS_CALL_CALLBACK_IPC_INTERFACE_CODE_H

/* SAID:4006 */
namespace OHOS {
namespace Telephony {
enum class ImsCallCallbackInterfaceCode {
    /**
     * @brief map the specific request service function in ipc, one id corresponds one service,
     * between ImsCallCallbackProxy and ImsCallCallbackStub
     */
    /****************** call basic ******************/
    IMS_DIAL = 0,
    IMS_HANG_UP,
    IMS_REJECT,
    IMS_ANSWER,
    IMS_HOLD,
    IMS_UN_HOLD,
    IMS_SWITCH,
    IMS_COMBINE_CONFERENCE,
    IMS_INVITE_TO_CONFERENCE,
    IMS_KICK_OUT_CONFERENCE,
    IMS_RECV_CALL_MEDIA_MODE_REQUEST,
    IMS_EMERGENCY_CALL,
    IMS_CALL_STATE_CHANGE,
    IMS_SERVICE_STATUS,
    IMS_LAST_CALL_FAIL_REASON,
    IMS_GET_CALLS_DATA,
    IMS_SRVCC_STATE,
    IMS_VT_OR_WFC,
    IMS_CALL_CRING,
    IMS_RECV_CALL_MEDIA_MODE_RESPONSE,
    IMS_CALL_SESSION_EVENT_CHANGED,
    IMS_CALL_PEER_DIMENSIONS_CHANGED,
    IMS_CALL_DATA_USAGE_CHANGED,
    IMS_CALL_CAMERA_CAPABILITIES_CHANGED,

    /****************** dtmf rtt ******************/
    IMS_START_DTMF,
    IMS_SEND_DTMF,
    IMS_STOP_DTMF,
    IMS_START_RTT,
    IMS_STOP_RTT,

    /****************** ims config ******************/
    IMS_SET_PRE_MODE,
    IMS_GET_PRE_MODE,
    IMS_SET_SWITCH_STATUS,
    IMS_GET_SWITCH_STATUS,
    IMS_SET_CONFIG,
    IMS_GET_CONFIG,
    IMS_SET_FEATURE,
    IMS_GET_FEATURE,
    IMS_SET_MUTE,
    IMS_GET_MUTE,
    IMS_GET_EMERGENCY_CALL_LIST,

    /****************** video settings ******************/
    IMS_CONTROL_CAMERA,
    IMS_SET_PREVIEW_WINDOW,
    IMS_SET_DISPLAY_WINDOW,
    IMS_SET_CAMERA_ZOOM,
    IMS_SET_PAUSE_IMAGE,
    IMS_SET_DEVICE_DIRECTION,

    /****************** supplement ******************/
    IMS_GET_CALL_CLIP,
    IMS_SET_CALL_CLIP,
    IMS_GET_CALL_CLIR,
    IMS_SET_CALL_CLIR,
    IMS_GET_CALL_FORWARD,
    IMS_SET_CALL_FORWARD,
    IMS_GET_CALL_RESTRICTION,
    IMS_SET_CALL_RESTRICTION,
    IMS_GET_CALL_WAIT,
    IMS_SET_CALL_WAIT,
    IMS_GET_CALL_COLR,
    IMS_SET_CALL_COLR,
    IMS_SET_CALL_COLP,
    IMS_GET_CALL_COLP,
};
} // namespace Telephony
} // namespace OHOS
#endif // TELEPHONY_IMS_CALL_CALLBACK_IPC_INTERFACE_CODE_H