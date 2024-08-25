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

import { Log } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import CommonUtils from '../utils/CommonUtils';
import type { WifiListener } from '../model/WifiModel';
import ArrayList from '@ohos.util.ArrayList';
import HashSet from '@ohos.util.HashSet';
import wifi from '@ohos.wifi';
import CommonEventManager from '@ohos.commonEventManager';

const TAG = 'P2pDiscoveryChannel';
const DISCOVERY_SLEEP: number = 60000;

export class P2PDiscoveryChannel implements WifiListener {
  private static instance: P2PDiscoveryChannel;
  private static readonly printerPattern: RegExp = /^(^3-.+-[145])|(0003.+000[145])$/;
  private readonly p2pDevices: ArrayList<wifi.WifiP2pDevice> = new ArrayList<wifi.WifiP2pDevice>();
  private discoveryCallback: (found: boolean, peer: wifi.WifiP2pDevice) => void;
  private discoverySleepTimer: number;
  private wifiSubscriber;

  public static getInstance(): P2PDiscoveryChannel {
    Log.info(TAG, 'getInstance enter');
    if (this.instance === undefined) {
      this.instance = new P2PDiscoveryChannel();
    }
    return this.instance;
  }

  startDiscovery(callback: (found: boolean, peer: wifi.WifiP2pDevice) => void): void {
    this.discoveryCallback = callback;
    wifi.on('p2pPeerDeviceChange', this.updatePeerDevices);
    this.startP2pDiscovery();
    this.registerWifiCommonEvent();

    // 3分钟后，native p2pService进入休眠状态，清除标记
    this.discoverySleepTimer = setInterval(()=> {
      Log.debug(TAG, 'native p2p service is sleep, start discovery');
      this.startP2pDiscovery();
    }, DISCOVERY_SLEEP);
  }

  private startP2pDiscovery(): void {
    wifi.startDiscoverDevices();
    wifi.getP2pPeerDevices().then((peers: wifi.WifiP2pDevice[]) => {
      this.updatePeerDevices(peers);
    });
  }

  /**
   *  register wifi common event;
   */
  private async registerWifiCommonEvent(): Promise<void> {
    try {
      this.wifiSubscriber = await CommonEventManager.createSubscriber({events:
      [CommonEventManager.Support.COMMON_EVENT_WIFI_P2P_CONN_STATE]});
      CommonEventManager.subscribe(this.wifiSubscriber, (err, data) => {
        if (err) {
          Log.error(TAG, `subscribe failed, code is ${err.code}, message is ${err.message}`);
        } else {
          this.onConnectionStateChanged(data);
        }
      });
    } catch (error) {
      Log.error(TAG, 'create subscriber fail: ' + JSON.stringify(error));
    }
  }

  private updatePeerDevices = (newDevices: wifi.WifiP2pDevice[]): void => {
    if (CheckEmptyUtils.isEmptyArr<wifi.WifiP2pDevice>(newDevices)) {
      Log.error(TAG, 'newDevices is empty');
      return;
    }
    Log.debug(TAG, `found length: ${newDevices.length}`);
    let oldDevices = new ArrayList<wifi.WifiP2pDevice>();
    for (let p2pDevice of this.p2pDevices) {
      oldDevices.add(p2pDevice);
    }
    this.p2pDevices.clear();
    for (let newDevice of newDevices) {
      if (newDevice !== undefined && newDevice.primaryDeviceType !== undefined &&
      P2PDiscoveryChannel.printerPattern.test(<string>newDevice.primaryDeviceType)) {
        let index = this.p2pDevices.convertToArray().findIndex((device) => {
          return device.deviceAddress === newDevice.deviceAddress;
        });
        if (index < 0) {
          this.p2pDevices.add(newDevice);
        }
      }
    }

    // notify new found devices
    let foundAddress: HashSet<string> = new HashSet<string>();
    let foundPrinters = this.p2pDevices.convertToArray().filter((newDevice) => {
      foundAddress.add(newDevice.deviceAddress);
      let index = oldDevices.convertToArray().findIndex((device) => {
        return device.deviceAddress === newDevice.deviceAddress;
      });
      if (index < 0) {
        return true;
      }
      return false;
    });
    if (!CheckEmptyUtils.isEmptyArr<wifi.WifiP2pDevice>(foundPrinters)) {
      for (let foundPrinter of foundPrinters) {
        this.discoveryCallback(true, foundPrinter);
      }
    }

    // notify lost devices
    for (let oldDevice of oldDevices) {
      if (!foundAddress.has(oldDevice.deviceAddress)) {
        this.discoveryCallback(false, oldDevice);
      }
    }
  };

  onConnectionStateChanged(data): void {
    if (data.event === CommonEventManager.Support.COMMON_EVENT_WIFI_P2P_CONN_STATE && data.code === wifi.P2pConnectState.DISCONNECTED) {
      Log.debug(TAG, 'p2p connect state change event: ' + JSON.stringify(data));
      if (this.discoverySleepTimer !== undefined) {
        this.startP2pDiscovery();
      }
    }
  }

  /**
	 * stop discovery
  */
  public cancel(): void {
    Log.info('stop p2p discovery');
    this.p2pDevices.clear();
    wifi.off('p2pPeerDeviceChange', this.updatePeerDevices);
    wifi.stopDiscoverDevices();
    if (this.wifiSubscriber !== undefined) {
      CommonEventManager.unsubscribe(this.wifiSubscriber);
    }
    clearTimeout(this.discoverySleepTimer);
  }
}