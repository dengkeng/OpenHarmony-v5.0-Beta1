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

import  wifi from '@ohos.wifiManager'
import { Log } from '@ohos/common';

const TAG = 'WifiP2pHelper';

export default class WifiP2pHelper {
  async checkConnectState(printerId: string) {
    Log.info(TAG, `checkConnectState enter...`);
    let printerDevices = this.parsePrinterId(printerId);
    Log.info(TAG, `printerDevices is ${printerDevices}`);
    let connectInfo = await wifi.getP2pLinkedInfo();
    Log.info(TAG, `connectInfo is ${connectInfo.connectState}`);
    if (connectInfo.connectState === P2pConnectState.CONNECTED) {
      let groupInfo = await wifi.getCurrentGroup();
      if (groupInfo.ownerInfo.deviceAddress === printerDevices) {
        return true;
      }
    }
    return false;
  }

  public static checkWifiActive(): boolean {
    let wifiState: boolean = wifi.isWifiActive();
    return wifiState;
  }

  private parsePrinterId(printerId: string) {
    let split = printerId.split('//');
    return split[split.length - 1].replace(/-/g, ':');
  }
}

enum P2pConnectState {
  DISCONNECTED = 0,
  CONNECTED = 1,
  UNKNOWN_ERROR = -1
}