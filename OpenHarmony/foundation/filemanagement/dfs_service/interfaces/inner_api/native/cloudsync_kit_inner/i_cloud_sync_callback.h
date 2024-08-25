/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FILEMGMT_I_CLOUD_SYNC_CALLBACK_H
#define OHOS_FILEMGMT_I_CLOUD_SYNC_CALLBACK_H

#include "iremote_broker.h"

#include "cloud_sync_callback.h"

namespace OHOS::FileManagement::CloudSync {
class ICloudSyncCallback : public CloudSyncCallback, public IRemoteBroker {
public:
    enum {
        SERVICE_CMD_ON_SYNC_STATE_CHANGED = 0,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Filemanagement.Dfs.ICloudSyncCallback")
};
} // namespace OHOS::FileManagement::CloudSync

#endif // OHOS_FILEMGMT_I_CLOUD_SYNC_CALLBACK_H