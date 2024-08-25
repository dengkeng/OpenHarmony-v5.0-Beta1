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

#ifndef FOUNDATION_ACE_FRAMEWORKS_CORE_RECORDER_EXPOSURE_PROCESSOR_H
#define FOUNDATION_ACE_FRAMEWORKS_CORE_RECORDER_EXPOSURE_PROCESSOR_H

#include <string>

#include "base/memory/ace_type.h"
#include "core/common/recorder/event_config.h"

namespace OHOS::Ace::Recorder {
class ExposureProcessor : public AceType {
    DECLARE_ACE_TYPE(ExposureProcessor, AceType)

public:
    explicit ExposureProcessor(const std::string& pageUrl, const std::string& inspectorId);
    ~ExposureProcessor() = default;

    bool IsNeedRecord() const;

    double GetRatio() const;

    void OnVisibleChange(bool isVisible, const std::string& param = "");

private:
    ExposureCfg cfg_ = { "", 0.0, 0 };
    int64_t startTime_ = -1;

    std::string pageUrl_;
    std::string navDstName_;

    ACE_DISALLOW_COPY_AND_MOVE(ExposureProcessor);
};
} // namespace OHOS::Ace::Recorder
#endif // FOUNDATION_ACE_FRAMEWORKS_CORE_RECORDER_EXPOSURE_PROCESSOR_H
