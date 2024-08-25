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

#ifndef CELLULAR_CALL_MMICODE_MSG_H
#define CELLULAR_CALL_MMICODE_MSG_H

#include "cellular_call_data_struct.h"
#include "ims_error.h"
#include "telephony_types.h"
#include <stdlib.h>
#include <string>

namespace OHOS {
namespace Telephony {
/**
 * Calling line identification restriction (CLIR) is set to the default according to the
 * subscription of the CLIR service.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_OUTGOING_DEFAULT = 0;
/**
 * Activate Calling line identification restriction for outgoing calls.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_OUTGOING_INVOCATION = 1;
/**
 * Deactivate Calling line identification restriction for outgoing calls.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_OUTGOING_SUPPRESSION = 2;

/**
 * Calling line identification restriction is currently not provisioned.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_STATUS_NOT_PROVISIONED = 0;
/**
 * Calling line identification restriction is currently provisioned in permanent mode.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_STATUS_PROVISIONED_PERMANENT = 1;
/**
 * Calling line identification restriction is currently unknown, e.g. no network, etc.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_STATUS_UNKNOWN = 2;
/**
 * Calling line identification restriction temporary mode, temporarily restricted.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_STATUS_TEMPORARILY_RESTRICTED = 3;
/**
 * Calling line identification restriction temporary mode, temporarily allowed.
 *
 * See TS 27.007, section 7.7 for more information.
 */
const int32_t CLIR_STATUS_TEMPORARILY_ALLOWED = 4;

const int32_t SS_DISABLED = 0;
const int32_t SS_ENABLED = 1;
const int32_t MAX_MESSAGE_NUMBER = 500;
const int32_t TRANSFER_REASON_TYPE_NO_REPLY = 2;

const std::string TRANSFER_UNCONDITIONAL_SUCCESS = "Transfer unconditional success";
const std::string TRANSFER_BUSY_SUCCESS = "Transfer busy success";
const std::string TRANSFER_NO_REPLYL_SUCCESS = "Transfer no replay success";
const std::string TRANSFER_NOT_REACHABLE_SUCCESS = "Transfer not reachable success";
const std::string QUERY_SS_SUCCESS = "Query SS success";
const std::string QUERY_SS_FAILED = "Query SS failed";
const std::string INVALID_MMI_CODE = "Invalid MMI code";
const std::string GET_CALL_WAITING_SUCCESS = "Get call waiting success";
const std::string GET_CALL_WAITING_FAILED = "Get call waiting failed";
const std::string SET_CALL_WAITING_SUCCESS = "Set call waiting success";
const std::string SET_CALL_WAITING_FAILED = "Set call waiting failed";
const std::string GET_CALL_TRANSFER_SUCCESS = "Get call transfer success";
const std::string GET_CALL_TRANSFER_FAILED = "Get call transfer failed";
const std::string SET_CALL_TRANSFER_SUCCESS = "Set call transfer success";
const std::string SET_CALL_TRANSFER_FAILED = "Set call transfer failed";
const std::string GET_CALL_RESTRICTION_SUCCESS = "Get call restriction success";
const std::string GET_CALL_RESTRICTION_FAILED = "Get call restriction failed";
const std::string SET_CALL_RESTRICTION_SUCCESS = "Set call restriction success";
const std::string SET_SET_BARRING_PASSWORD_SUCCESS = "Set call restriction password success";
const std::string SET_CALL_RESTRICTION_FAILED = "Set call restriction failed";
const std::string SET_SET_BARRING_PASSWORD_FAILED = "Set call restriction password failed";
const std::string GET_CLIP_SUCCESS = "Get clip success";
const std::string GET_CLIP_FAILED = "Get clip failed";
const std::string SET_CLIP_SUCCESS = "Set clip success";
const std::string SET_CLIP_FAILED = "Set clip failed";
const std::string GET_CLIR_SUCCESS = "Get clir success";
const std::string GET_CLIR_FAILED = "Get clir failed";
const std::string SET_CLIR_SUCCESS = "Set clir success";
const std::string SET_CLIR_FAILED = "Set clir failed";
const std::string GET_COLR_SUCCESS = "Get colr success";
const std::string GET_COLR_FAILED = "Get colr failed";
const std::string SET_COLR_SUCCESS = "Set colr success";
const std::string SET_COLR_FAILED = "Set colr failed";
const std::string GET_COLP_SUCCESS = "Get colp success";
const std::string GET_COLP_FAILED = "Get colp failed";
const std::string SET_COLP_SUCCESS = "Set colp success";
const std::string SET_COLP_FAILED = "Set colp failed";
const std::string MIS_MATCH_PIN_PUK = "PIN or PUK don\'t match";
const std::string INVAILD_PIN_PUK = "Invaild PIN or PUK numbers";
const std::string SEND_USSD_SUCCESS = "Send ussd success";
const std::string GENERIC_FAILURE = "Generic fail, please retry";
const std::string SERVICE_ENABLE = "Service was enabled";
const std::string SERVICE_ENABLE_FOR = "Service was enabled for:";
const std::string SERVICE_DISABLE = "Service has been disabled";
const std::string SERVICE_NOT_PROVISIONED = "Service not provisioned";
const std::string CF_NOT_FORWARDED = "%s: Not forwarded";
const std::string CF_FORWARDED = "%s: %s";
const std::string CF_FORWARDED_TIME = "%s: %s after %d seconds";
const std::string CLIR_PERMANENT = "You can not change the caller ID setting";
const std::string CLIR_DEFAULT_ON_NEXT_ON = "Caller ID defaults to restricted. Next call: Restricted";
const std::string CLIR_DEFAULT_ON_NEXT_OFF = "Caller ID defaults to restricted. Next call: Not restricted";
const std::string CLIR_DEFAULT_OFF_NEXT_OFF = "Caller ID defaults to not restricted. Next call: Not restricted";
const std::string CLIR_DEFAULT_OFF_NEXT_ON = "Caller ID defaults to not restricted. Next call: Restricted";

/**
 * Create get call waiting result message
 *
 * @param resultMessage  the result message
 * @param callWaitResponse  the result of get callwaiting
 * @return void.
 */
void CreateGetCallWaitingResultMessage(std::string &resultMessage, CallWaitResponse response);

void CreateSuppSvcQueryResultMessage(std::string &resultMessage, int32_t result, int32_t status);

void CreateGetCallTransferResultMessage(std::string &resultMessage, CallTransferResponse response);

void MakeCallTransferMessageEx(std::string &resultMessage, CallTransferResponse response, int32_t classex);

void CreateGetClirResultMessage(std::string &resultMessage, ClirResponse response);

std::string GetServiceClassName(int32_t classex);

void CreateServiceClassMessage(std::string &resultMessage, int32_t classex);

} // namespace Telephony
} // namespace OHOS

#endif // CELLULAR_CALL_MMICODE_MSG_H
