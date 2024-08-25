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

#ifndef UDMF_FILE_H
#define UDMF_FILE_H

#include "unified_record.h"

namespace OHOS {
namespace UDMF {
class File : public UnifiedRecord {
public:
    File();
    explicit File(const std::string &uri);
    File(UDType type, ValueType value);
    int64_t GetSize() override;

    std::string GetUri() const;
    void SetUri(const std::string &uri);

    std::string GetRemoteUri() const;
    void SetRemoteUri(const std::string &uri);

    void SetDetails(UDDetails &variantMap);
    UDDetails GetDetails() const;

protected:
    std::string oriUri_;
    std::string remoteUri_;
    UDDetails details_;
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_FILE_H
