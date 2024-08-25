/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import print from '@ohos.print';
import wifi from '@ohos.wifiManager';
import { Log } from './Log';
import { WIFI_INACTIVE } from '../model/ErrorMessage';

const TAG: string = 'Permission';

export function checkWifiEnable(): boolean {
  let wifiStatus: boolean = wifi.isWifiActive();
  if (!wifiStatus) {
    //wifi 关闭
    Log.error(TAG, 'wifi is inactive');
    //wifi关闭了, 上报异常
    print.updateExtensionInfo(JSON.stringify(WIFI_INACTIVE));
  }
  return wifiStatus;
}