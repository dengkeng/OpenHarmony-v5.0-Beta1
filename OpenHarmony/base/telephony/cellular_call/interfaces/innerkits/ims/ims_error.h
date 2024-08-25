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

#ifndef IMS_ERROR_H
#define IMS_ERROR_H

#include "telephony_errors.h"

namespace OHOS {
namespace Telephony {
/**
 * @brief Indicates the error type when use UT.
 */
enum {
    /**
     * Indicates the SS doesn't use UT interface.
     */
    IMS_ERROR_UT_NO_CONNECTION = IMS_ERR_OFFSET,
    /**
     * Indicates the UE will retry on CS when UT fail.
     */
    IMS_ERROR_UT_CS_FALLBACK,
};
} // namespace Telephony
} // namespace OHOS
#endif // IMS_ERROR_H
