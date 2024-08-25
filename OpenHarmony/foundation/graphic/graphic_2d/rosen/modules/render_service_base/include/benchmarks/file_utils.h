/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ROSEN_RENDER_SERVICE_BASE_BENCHMARKS_RS_FILE_UTIL_H
#define ROSEN_RENDER_SERVICE_BASE_BENCHMARKS_RS_FILE_UTIL_H

#include <string>
#include "message_parcel.h"
#include "common/rs_macros.h"

namespace OHOS {
namespace Rosen {
namespace Benchmarks {
RSB_EXPORT bool IsValidFile(const std::string& realPathStr, const std::string& validPath = "/data/");
RSB_EXPORT std::string GetRealAndValidPath(const std::string& filePath);
RSB_EXPORT bool CreateFile(const std::string& filePath);
RSB_EXPORT bool WriteToFile(uintptr_t data, size_t size, const std::string& filePath);
RSB_EXPORT bool WriteStringToFile(int fd, const std::string& str);
RSB_EXPORT bool WriteStringToFile(const std::string& str, const std::string& filePath);
RSB_EXPORT bool WriteMessageParcelToFile(std::shared_ptr<MessageParcel> messageParcel,
    const std::string& opsDescription, int frameNum, const std::string& fileDir);
} // namespace Benchmarks
} // namespace Rosen
} // namespace OHOS

#endif // RS_FILE_UTILs