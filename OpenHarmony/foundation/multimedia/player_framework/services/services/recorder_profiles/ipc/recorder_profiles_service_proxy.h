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

#ifndef RECORDERPROFILES_SERVICE_PROXY_H
#define RECORDERPROFILES_SERVICE_PROXY_H

#include "i_standard_recorder_profiles_service.h"
#include "nocopyable.h"
#include "media_parcel.h"
#include "recorder_profiles_parcel.h"

namespace OHOS {
namespace Media {
class RecorderProfilesServiceProxy : public IRemoteProxy<IStandardRecorderProfilesService>, public NoCopyable {
public:
    explicit RecorderProfilesServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~RecorderProfilesServiceProxy();

    bool IsAudioRecorderConfigSupported(const RecorderProfilesData &profile) override;
    bool HasVideoRecorderProfile(int32_t sourceId, int32_t qualityLevel) override;
    std::vector<RecorderProfilesData> GetAudioRecorderCapsInfo() override;
    std::vector<RecorderProfilesData> GetVideoRecorderCapsInfo() override;
    RecorderProfilesData GetVideoRecorderProfileInfo(int32_t sourceId, int32_t qualityLevel) override;
    int32_t DestroyStub() override;

private:
    static inline BrokerDelegator<RecorderProfilesServiceProxy> delegator_;
};
}  // namespace Media
}  // namespace OHOS
#endif  // RECORDERPROFILES_SERVICE_PROXY_H
