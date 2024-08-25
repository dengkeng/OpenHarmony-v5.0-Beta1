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

#ifndef TELEPHONY_IMS_CALL_TYPES_H
#define TELEPHONY_IMS_CALL_TYPES_H

#include "call_manager_errors.h"
#include "call_manager_inner_type.h"
#include "tel_ril_call_parcel.h"
#include "ims_core_service_types.h"

namespace OHOS {
namespace Telephony {
const int32_t kMaxNumberLength = 255;
const int32_t SLOT_0 = 0;
const int32_t SLOT_1 = 1;

/**
 * @brief Indicates the reason for rejecting the ims call.
 */
enum ImsRejectReason {
    /**
     * Indicates the reject reason is user busy.
     */
    USER_IS_BUSY = 0,
    /**
     * Indicates the reject reason is user decline.
     */
    USER_DECLINE = 1,
};

/**
 * @brief Indicates the class of Ims service,which used in IMS Set Call Waiting interface.
 */
enum ImsServiceClass {
    /**
     * Indicates service class is voice.
     */
    SERVICE_CLASS_VOICE = 1,
    /**
     * Indicates service class is video.
     */
    SERVICE_CLASS_VIDEO = 2,
};

/**
 * @brief Indicates the state of Srvcc.
 */
enum SrvccState {
    /**
     * Indicates SrvccState is null.
     */
    SRVCC_NONE = -1,
    /**
     * Indicates SrvccState is started.
     */
    STARTED = 0,
    /**
     * Indicates SrvccState is completed.
     */
    COMPLETED = 1,
    /**
     * Indicates SrvccState is failed.
     */
    FAILED = 2,
    /**
     * Indicates SrvccState is canceled.
     */
    CANCELED = 3
};

enum ImsSrvccAction {
    ACTION_DIAL,
    ACTION_HANGUP,
    ACTION_ANSWER,
    ACTION_REJECT,
    ACTION_CONFERENCE,
    ACTION_SWITCH_CALL,
    ACTION_SEND_DTMF,
    ACTION_START_DTMF,
    ACTION_STOP_DTMF,
};

/**
 * @brief Indicates the type of ImsCall.
 */
enum ImsCallType {
    /**
     * Indicates the ImsCall type is voice.
     */
    TEL_IMS_CALL_TYPE_VOICE,
    /**
     * Indicates the ImsCall type is VT_TX.
     */
    TEL_IMS_CALL_TYPE_VT_TX,
    /**
     * Indicates the ImsCall type is VT_RX.
     */
    TEL_IMS_CALL_TYPE_VT_RX,
    /**
     * Indicates the ImsCall type is VT.
     */
    TEL_IMS_CALL_TYPE_VT,
    /**
     * Indicates the ImsCall type is VT call pause.
     */
    TEL_IMS_CALL_TYPE_PAUSE,
};

/**
 * @brief Indicates the type of video call event.
 */
enum VideoCallEventType {
    /**
     * Indicates the camera event failure type.
     */
    EVENT_CAMERA_FAILURE = 0,
    /**
     * Indicates the camera event ready type.
     */
    EVENT_CAMERA_READY,
    /**
     * Indicates the display surface release type.
     */
    EVENT_RELEASE_DISPLAY_SURFACE = 100,
    /**
     * Indicates the preview surface release type.
     */
    EVENT_RELEASE_PREVIEW_SURFACE,
};

/**
 * @brief Indicates the result of ImsCall mode request.
 */
enum ImsCallModeRequestResult {
    /**
     * Indicates the ImsCall Mode request success.
     */
    MODIFY_REQUEST_SUCCESS = 0,
    /**
     * Indicates the ImsCall Mode request fail.
     */
    MODIFY_REQUEST_FAIL,
    /**
     * Indicates the ImsCall Mode request invalid.
     */
    MODIFY_REQUEST_INVALID,
    /**
     * Indicates the ImsCall Mode request timeout.
     */
    MODIFY_REQUEST_TIMED_OUT,
    /**
     * Indicates the ImsCall Mode request reject by remote.
     */
    MODIFY_REQUEST_REJECTED_BY_REMOTE,
    /**
     * Indicates the ImsCall Mode request cancel.
     */
    MODIFY_REQUEST_CANCEL,
    /**
     * Indicates the ImsCall Mode downgrade RTP time out.
     */
    MODIFY_DOWNGRADE_RTP_OR_RTCP_TIMEOUT = 100,
    /**
     * Indicates the ImsCall Mode downgrade RTP and RTCP time out.
     */
    MODIFY_DOWNGRADE_RTP_AND_RTCP_TIMEOUT,
};

/**
 * @brief Indicates the type of ImsCall.
 */
struct ImsSrvccActionInfo {
    CellularCallInfo callInfo;
    /**
     * Indicates the initial value of dtmfCode is 0.
     */
    char dtmfCode = 0;
};

/**
 * @brief Indicates the code of TransferState.
 */
enum TransferState {
    /**
     * Indicates the code value of VT transfer to WFC is 0.
     */
    VT_TRANSFER_TO_WFC = 0,
    /**
     * Indicates the code value of WFC transfer to VT is 1.
     */
    WFC_TRANSFER_TO_VT = 1,
};

/**
 * @brief Indicates the information of ImsCall.
 */
struct ImsCallInfo {
    /**
     * Indicates the call phone number,its initial value is 0.
     */
    char phoneNum[kMaxNumberLength] = { 0 };
    /**
     * Indicates the slotId.
     */
    int32_t slotId = 0;
    /**
     * Indicates the video state,when the audio state is 0 represents audio and 3 represents video.
     */
    int32_t videoState = 0;
    /**
     * Indicates the call index and its initial value is 0.
     */
    int32_t index = 0;
};

/**
 * @brief Indicates the call status information.
 */
struct ImsCurrentCall {
    /**
     * Indicates connection Index for use with, eg, AT+CHLD.
     */
    int32_t index = 0;
    /**
     * Indicates the call direction, The value 0 indicates mobile originated (MO) call,
     * and the value 1 indicates mobile terminated (MT) call.
     */
    int32_t dir = 0;
    /**
     * Indicates the call state:
     * - 0: activated state
     * - 1: holding state
     * - 2: MO call, dialing state
     * - 3: MO call, alerting state
     * - 4: MT call, incoming call state
     * - 5: MT call, call waiting state
     */
    int32_t state = 0;
    /**
     * Indicates the call mode:
     * - 0: voice call
     * - 1: data call
     * - 2: fax
     */
    int32_t mode = 0;
    /**
     * Indicates the multiparty call status:
     * - 0: not one of multiparty (conference) call parties
     * - 1: one of multiparty (conference) call parties
     */
    int32_t mpty = 0;
    /**
     * Identifies the service domain:
     * - 0: CS domain phone
     * - 1: IMS domain phone
     */
    int32_t voiceDomain = 0;
    /**
     * Indicates the call type:
     * - 0: Voice call
     * - 1: VT_TX Video call: send one-way video, two-way voice
     * - 2: VT_RX Video call: one-way receiving video, two-way voice
     * - 3: VT Video call: two-way video, two-way voice
     */
    ImsCallType callType = ImsCallType::TEL_IMS_CALL_TYPE_VOICE;
    /**
     * Indicates remote party number.
     */
    std::string number = "";
    /**
     * Indicates the type of address octet in integer format.
     */
    int32_t type = 0;
    /**
     * Indicates alphanumeric representation of <number> corresponding to the entry found in phonebook;
     */
    std::string alpha = "";
    /**
     * Indicates the type of address, eg 145 = intl.
     */
    int32_t toa = 0;
    /**
     * Indicates the color tone type.
     */
    int32_t toneType = 0;
    /**
     * Indicates the initial type of this call.
     */
    int32_t callInitialType = 0;
};

/**
 * @brief Indicates the call status information list.
 */
struct ImsCurrentCallList {
    /**
     * Indicates the size of call status information list.
     */
    int32_t callSize = 0;
    /**
     * Indicates the ID of call status information list.
     */
    int32_t flag = 0;
    /**
     * Indicates the call status information list.
     */
    std::vector<ImsCurrentCall> calls {};
};

/**
 * @brief Indicates the call mode information.
 */
struct ImsCallModeReceiveInfo {
    /**
     * Indicates connection Index of call.
     */
    int32_t callIndex = 0;
    /**
     * Indicates response result.
     */
    ImsCallModeRequestResult result = ImsCallModeRequestResult::MODIFY_REQUEST_SUCCESS;
    /**
     * Indicates the call type:
     * - 0: Voice call
     * - 1: VT_TX Video call: send one-way video, two-way voice
     * - 2: VT_RX Video call: one-way receiving video, two-way voice
     * - 3: VT Video call: two-way video, two-way voice
     */
    ImsCallType callType = ImsCallType::TEL_IMS_CALL_TYPE_VOICE;
};

/**
 * @brief Indicates the call session event information.
 */
struct ImsCallSessionEventInfo {
    /**
     * Indicates connection Index of call.
     */
    int32_t callIndex = 0;
    /**
     * Indicates the call  session event type:
     * - 0: Indicates the camera event failure type.
     * - 1: Indicates the camera event ready type.
     * - 2: Indicates the display surface release type.
     * - 3: Indicates the preview surface release type.
     */
    VideoCallEventType eventType = VideoCallEventType::EVENT_CAMERA_FAILURE;
};

/**
 * @brief Indicates the video window width and height in video call.
 */
struct ImsCallPeerDimensionsInfo {
    /**
     * Indicates connection Index of call.
     */
    int32_t callIndex = 0;
    /**
     * the width of video window
     */
    int32_t width = 0;
    /**
     * the height of video window
     */
    int32_t height = 0;
};

/**
 * @brief Indicates the ims video call data usage info
 */
struct ImsCallDataUsageInfo {
    /**
     * Indicates connection Index of call.
     */
    int32_t callIndex = 0;
    /**
     * the data usage info
     */
    int64_t dataUsage = 0;
};

/**
 * @brief Indicates camera capabilities info in ims video call
 */
struct CameraCapabilitiesInfo {
    /**
     * Indicates connection Index of call.
     */
    int32_t callIndex = 0;
    /**
     * the width of video window
     */
    int32_t width = 0;
    /**
     * the height of video window
     */
    int32_t height = 0;
};
} // namespace Telephony
} // namespace OHOS

#endif // TELEPHONY_IMS_CALL_TYPES_H
