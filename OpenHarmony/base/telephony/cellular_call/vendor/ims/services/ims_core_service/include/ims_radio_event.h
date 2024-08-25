/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef IMS_RADIO_EVENT_H
#define IMS_RADIO_EVENT_H
enum ImsRadioEvent {
    /****************** call ******************/
    IMS_RADIO_DIAL = 0,
    IMS_RADIO_HANGUP,
    IMS_RADIO_ANSWER,
    IMS_RADIO_REJECT,
    IMS_RADIO_REJECT_WITH_REASON,
    IMS_RADIO_HOLD,
    IMS_RADIO_UN_HOLD,
    IMS_RADIO_SWITCH,
    IMS_RADIO_COMBINE_CONFERENCE,
    IMS_RADIO_INVITE_TO_CONFERENCE,
    IMS_RADIO_KICK_OUT_CONFERENCE,
    IMS_RADIO_UPDATE_CALL_MEDIA_MODE,
    IMS_RADIO_GET_CALL_DATA,
    IMS_RADIO_CALL_RINGBACK,
    IMS_RADIO_GET_LAST_CALL_FAIL_REASON,
    IMS_RADIO_CALL_STATE_CHANGED,
    IMS_RADIO_REG_ERR_REPORT,
    IMS_RADIO_MT_STATUS_REPORT,
    IMS_RADIO_GET_IMS_DOMAIN,

    /****************** dtmf rtt ******************/
    IMS_RADIO_START_DTMF = 100,
    IMS_RADIO_SEND_DTMF,
    IMS_RADIO_STOP_DTMF,
    IMS_RADIO_START_RTT,
    IMS_RADIO_STOP_RTT,

    /****************** ims config ******************/
    IMS_RADIO_SERVICE_STATUS = 200,
    IMS_RADIO_GET_REGISTRATION_STATUS,
    IMS_RADIO_NET_STATE_CHANGE,
    IMS_RADIO_SET_DOMAIN_PREFERENCE_MODE,
    IMS_RADIO_GET_DOMAIN_PREFERENCE_MODE,
    IMS_RADIO_SET_LTE_SWITCH_STATUS,
    IMS_RADIO_GET_LTE_SWITCH_STATUS,
    IMS_RADIO_SET_CONFIG,
    IMS_RADIO_GET_CONFIG,
    IMS_RADIO_SET_FEATURE,
    IMS_RADIO_GET_FEATURE,
    IMS_RADIO_SET_MUTE,
    IMS_RADIO_GET_MUTE,
    IMS_RADIO_SRVCC_STATUS,

    /****************** video settings ******************/
    IMS_RADIO_CTRL_CAMERA = 300,
    IMS_RADIO_SET_PREVIEW_WINDOW,
    IMS_RADIO_SET_DISPLAY_WINDOW,
    IMS_RADIO_SET_CAMERA_ZOOM,
    IMS_RADIO_SET_PAUSE_IMAGE,
    IMS_RADIO_SET_DEVICE_DIRECTION,
    IMS_RADIO_VT_WFC,

    /****************** Supplement ******************/
    IMS_RADIO_GET_CLIP = 400,
    IMS_RADIO_SET_CLIP,
    IMS_RADIO_SET_CLIR,
    IMS_RADIO_GET_CLIR,
    IMS_RADIO_SET_CALL_TRANSFER,
    IMS_RADIO_GET_CALL_TRANSFER,
    IMS_RADIO_SET_CALL_RESTRICTION,
    IMS_RADIO_GET_CALL_RESTRICTION,
    IMS_RADIO_SET_CALL_WAITING,
    IMS_RADIO_GET_CALL_WAITING,
    IMS_RADIO_SET_COLR,
    IMS_RADIO_GET_COLR,
    IMS_RADIO_SET_COLP,
    IMS_RADIO_GET_COLP,

    /****************** sms      ******************/
    IMS_RADIO_SENDMESSAGE = 500,
    IMS_RADIO_SET_SMS_CONFIG,
    IMS_RADIO_GET_SMS_CONFIG,

    /****************** callback ******************/
    IMS_RADIO_CALL_REGISTER_CALLBACK = 600,
    IMS_RADIO_RIL_REGISTER_OBSERVER_CALLBACK,
    IMS_RADIO_RIL_REGISTER_RESPONSE_CALLBACK,
};
#endif // IMS_RADIO_EVENT_H
