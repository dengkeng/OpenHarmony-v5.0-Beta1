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

#ifndef SEND_SHORT_MESSAGE_CALLBACK_IPC_INTERFACE_CODE_H
#define SEND_SHORT_MESSAGE_CALLBACK_IPC_INTERFACE_CODE_H

/* SAID:4008 */
namespace OHOS {
namespace Telephony {
enum class SendShortMessageCallbackInterfaceCode {
    /**
     * @brief Indicates the call back event of sending SMS.
     */
    ON_SMS_SEND_RESULT,
};
} // namespace Telephony
} // namespace OHOS
#endif // SEND_SHORT_MESSAGE_CALLBACK_IPC_INTERFACE_CODE_H