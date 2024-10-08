/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTERFACES_KITS_JS_SRC_COMMON_LOG_H
#define INTERFACES_KITS_JS_SRC_COMMON_LOG_H

#include <cstdio>
#include <string>
#include <vector>

#ifndef FILE_SUBSYSTEM_DEBUG_LOCAL
#include "hilog/log.h"
#endif

namespace OHOS {
namespace DistributedFS {
#ifndef FILE_SUBSYSTEM_DEBUG_LOCAL
#define FILEIO_DOMAIN_ID 0xD004388
static constexpr OHOS::HiviewDFX::HiLogLabel FILEIO_LABEL = { LOG_CORE, FILEIO_DOMAIN_ID, "file_api" };

#ifdef HILOGD
#undef HILOGD
#endif

#ifdef HILOGF
#undef HILOGF
#endif

#ifdef HILOGE
#undef HILOGE
#endif

#ifdef HILOGW
#undef HILOGW
#endif

#ifdef HILOGI
#undef HILOGI
#endif

#define HILOGD(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Debug(OHOS::DistributedFS::FILEIO_LABEL, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define HILOGI(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Info(OHOS::DistributedFS::FILEIO_LABEL, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define HILOGW(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Warn(OHOS::DistributedFS::FILEIO_LABEL, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define HILOGE(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Error(OHOS::DistributedFS::FILEIO_LABEL, "%{public}s: " fmt, __func__, ##__VA_ARGS__)
#define HILOGF(fmt, ...) \
    (void)OHOS::HiviewDFX::HiLog::Fatal(OHOS::DistributedFS::FILEIO_LABEL, "%{public}s: " fmt, __func__, ##__VA_ARGS__)

#else

#define HILOGF(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_FATAL, FILEIO_DOMAIN_ID, FILEMGMT_LOG_TAG, \
    "[%{public}s:%{public}d->%{public}s] " fmt, FILEMGMT_FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__))
#define HILOGE(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, FILEIO_DOMAIN_ID, FILEMGMT_LOG_TAG, \
    "[%{public}s:%{public}d->%{public}s] " fmt, FILEMGMT_FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__))
#define HILOGW(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_WARN, FILEIO_DOMAIN_ID, FILEMGMT_LOG_TAG, \
    "[%{public}s:%{public}d->%{public}s] " fmt, FILEMGMT_FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__))
#define HILOGI(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_INFO, FILEIO_DOMAIN_ID, FILEMGMT_LOG_TAG, \
    "[%{public}s:%{public}d->%{public}s] " fmt, FILEMGMT_FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__))
#define HILOGD(fmt, ...)            \
    ((void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, FILEIO_DOMAIN_ID, FILEMGMT_LOG_TAG, \
    "[%{public}s:%{public}d->%{public}s] " fmt, FILEMGMT_FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__))

#endif
} // namespace DistributedFS
} // namespace OHOS
#endif // INTERFACES_KITS_JS_SRC_COMMON_LOG_H