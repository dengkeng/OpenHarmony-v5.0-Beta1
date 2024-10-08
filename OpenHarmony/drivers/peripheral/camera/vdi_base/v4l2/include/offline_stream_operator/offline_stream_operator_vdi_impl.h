/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_OFFLINE_STREAM_OPERATOR_VDI_IMPL_H
#define HOS_CAMERA_OFFLINE_STREAM_OPERATOR_VDI_IMPL_H

#include <map>
#include <mutex>
#include "v1_0/ioffline_stream_operator_vdi.h"
#include "camera.h"
#include "offline_stream.h"

namespace OHOS::Camera {
using namespace OHOS::VDI::Camera::V1_0;
class OfflineStreamOperatorVdiImpl : public IOfflineStreamOperatorVdi {
public:
    OfflineStreamOperatorVdiImpl();
    virtual ~OfflineStreamOperatorVdiImpl();
    int32_t CancelCapture(int32_t captureId)  override;
    int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) override;
    int32_t Release() override;

public:
    RetCode CommitOfflineStream(const std::shared_ptr<OfflineStream> &of);

private:
    std::shared_ptr<OfflineStream> FindStreamByCaptureId(int32_t captureId);

private:
    std::mutex lock_;
    std::map<int, std::shared_ptr<OfflineStream>> offlineStreamMap_ = {};
};
} // namespace OHOS::Camera
#endif // HOS_CAMERA_OFFLINE_STREAM_OPERATOR_VDI_IMPL_H
