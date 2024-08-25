/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "log.h"

#include "securec.h"

#ifdef HILOG_ENABLE
#include "hilog/log.h"
#define HCF_MAX_LOG_BUFF_LEN 512

void HcfLogPrint(uint32_t hcfLogLevel, const char *funcName, uint32_t lineNo, const char *format, ...)
{
    char logBuf[HCF_MAX_LOG_BUFF_LEN] = {0};

    va_list arg;
    va_start(arg, format);
    int32_t ret = vsnprintf_s(logBuf, HCF_MAX_LOG_BUFF_LEN, HCF_MAX_LOG_BUFF_LEN - 1, format, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "crypto framework log concatenate error.");
        return;
    }

    switch (hcfLogLevel) {
        case HCF_LOG_LEVEL_I:
            HILOG_INFO(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, logBuf);
            break;
        case HCF_LOG_LEVEL_E:
            HILOG_ERROR(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, logBuf);
            break;
        case HCF_LOG_LEVEL_W:
            HILOG_WARN(LOG_CORE, "%{public}s[%{public}u]: %{public}s\n", funcName, lineNo, logBuf);
            break;
        case HCF_LOG_LEVEL_D:
            HILOG_DEBUG(LOG_CORE, "%{public}s[%{public}u]: %{private}s\n", funcName, lineNo, logBuf);
            break;
        default:
            return;
    }
}
#endif
