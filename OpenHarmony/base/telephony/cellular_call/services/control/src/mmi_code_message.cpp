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

#include "mmi_code_message.h"

#include "cellular_call_data_struct.h"
#include "ims_error.h"
#include "securec.h"
#include "telephony_types.h"

namespace OHOS {
namespace Telephony {
void CreateGetCallWaitingResultMessage(std::string &resultMessage, CallWaitResponse response)
{
    if (response.result == TELEPHONY_SUCCESS) {
        resultMessage.append("\n");
        if (response.status == 1) {
            resultMessage.append(SERVICE_ENABLE_FOR);
            CreateServiceClassMessage(resultMessage, response.classCw);
        } else {
            resultMessage.append(SERVICE_DISABLE);
        }
    }
}

void CreateSuppSvcQueryResultMessage(std::string &resultMessage, int32_t result, int32_t status)
{
    if (result == TELEPHONY_SUCCESS) {
        resultMessage.append("\n");
        if (status == SS_ENABLED) {
            resultMessage.append(SERVICE_ENABLE);
        } else if (status == SS_DISABLED) {
            resultMessage.append(SERVICE_DISABLE);
        }
    }
}

void CreateGetCallTransferResultMessage(std::string &resultMessage, CallTransferResponse response)
{
    if (response.result == TELEPHONY_SUCCESS) {
        resultMessage.append("\n");
        for (uint32_t classMask = 1; classMask <= ServiceClassType::DEDICATED_PAD_ACCESS; classMask <<= 1) {
            if (response.classx > 0 && (static_cast<uint32_t>(response.classx) & classMask) != 0) {
                MakeCallTransferMessageEx(resultMessage, response, static_cast<uint32_t>(response.classx) & classMask);
            }
        }
    }
}

void MakeCallTransferMessageEx(std::string &resultMessage, CallTransferResponse response, int32_t classex)
{
    char tempMessage[MAX_MESSAGE_NUMBER] = {0};
    bool needTime = response.reason == TRANSFER_REASON_TYPE_NO_REPLY;
    std::string className = GetServiceClassName(classex);
    if (response.status == SS_ENABLED) {
        if (needTime) {
            if (sprintf_s(tempMessage, sizeof(tempMessage), CF_FORWARDED_TIME.c_str(), className.c_str(),
                    response.number, response.time) != -1) {
                resultMessage.append(tempMessage);
            }
        } else {
            if (sprintf_s(tempMessage, sizeof(tempMessage), CF_FORWARDED.c_str(), className.c_str(),
                    response.number) != -1) {
                resultMessage.append(tempMessage);
            }
        }
    } else {
        if (sprintf_s(tempMessage, sizeof(tempMessage), CF_NOT_FORWARDED.c_str(), className.c_str()) != -1) {
            resultMessage.append(tempMessage);
        }
    }
}

void CreateGetClirResultMessage(std::string &resultMessage, ClirResponse response)
{
    if (response.result == TELEPHONY_SUCCESS) {
        resultMessage.append("\n");
        int32_t clirInfoN = response.action;
        int32_t clirInfoM = response.clirStat;
        switch (clirInfoM) {
            case CLIR_STATUS_NOT_PROVISIONED:
                resultMessage.append(SERVICE_NOT_PROVISIONED);
                break;
            case CLIR_STATUS_PROVISIONED_PERMANENT:
                resultMessage.append(CLIR_PERMANENT);
                break;
            case CLIR_STATUS_TEMPORARILY_RESTRICTED:
                // 'n' parameter.
                switch (clirInfoN) {
                    case CLIR_OUTGOING_DEFAULT:
                    case CLIR_OUTGOING_INVOCATION:
                        resultMessage.append(CLIR_DEFAULT_ON_NEXT_ON);
                        break;
                    case CLIR_OUTGOING_SUPPRESSION:
                        resultMessage.append(CLIR_DEFAULT_ON_NEXT_OFF);
                        break;
                    default:
                        resultMessage.append(SERVICE_NOT_PROVISIONED);
                }
                break;
            case CLIR_STATUS_TEMPORARILY_ALLOWED:
                // 'n' parameter.
                switch (clirInfoN) {
                    case CLIR_OUTGOING_SUPPRESSION:
                    case CLIR_OUTGOING_DEFAULT:
                        resultMessage.append(CLIR_DEFAULT_OFF_NEXT_OFF);
                        break;
                    case CLIR_OUTGOING_INVOCATION:
                        resultMessage.append(CLIR_DEFAULT_OFF_NEXT_ON);
                        break;
                    default:
                        resultMessage.append(SERVICE_NOT_PROVISIONED);
                }
                break;
            default:
                resultMessage.append(SERVICE_NOT_PROVISIONED);
        }
    }
}

void CreateServiceClassMessage(std::string &resultMessage, int32_t classex)
{
    for (uint32_t classMask = 1; classMask <= ServiceClassType::DEDICATED_PAD_ACCESS; classMask <<= 1) {
        if (classex > 0 && (static_cast<uint32_t>(classex) & classMask) != 0) {
            resultMessage.append("\n");
            resultMessage.append(GetServiceClassName(static_cast<uint32_t>(classex) & classMask));
        }
    }
}

std::string GetServiceClassName(int32_t classex)
{
    switch (classex) {
        case ServiceClassType::VOICE:
            return "Voice";
        case ServiceClassType::FAX:
            return "Fax";
        case ServiceClassType::SHORT_MESSAGE_SERVICE:
            return "Message";
        case ServiceClassType::DATA_CIRCUIT_SYNC:
            return "Sync";
        case ServiceClassType::DATA_CIRCUIT_ASYNC:
            return "Async";
        case ServiceClassType::DEDICATED_PACKET_ACCESS:
            return "Package";
        case ServiceClassType::DEDICATED_PAD_ACCESS:
            return "Pad";
        default:
            return "Unknow";
    }
}

} // namespace Telephony
} // namespace OHOS