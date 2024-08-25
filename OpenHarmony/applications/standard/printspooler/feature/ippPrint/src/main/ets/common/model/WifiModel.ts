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

import wifi from '@ohos.wifi';
import { Log } from '@ohos/common';
import print from '@ohos.print';
import { P2P_SERVICE_ERROR } from '@ohos/common';
import CommonEventManager from '@ohos.commonEventManager';
import ArrayList from '@ohos.util.ArrayList';

const TAG = 'WifiModel';

export class WifiModel {
  public static readonly p2pPeerDeviceChange: string = 'p2pPeerDeviceChange';
  public static readonly p2pConnectionChange: string = 'p2pConnectionChange';
  public static readonly p2pStateChange: string = 'p2pStateChange';
  private wifiListener: ArrayList<WifiListener> = new ArrayList<WifiListener>();
  private wifiSubscriber;

  constructor() {
    this.registerWifiCommonEvent();
  }

  public addListener(listener: WifiListener): void {
    if (!this.wifiListener.has(listener)) {
      this.wifiListener.add(listener);
    } else {
      Log.error(TAG, 'listener is exist');
    }
  }

  public removeListener(listener: WifiListener): void {
    if (this.wifiListener.has(listener)) {
      this.wifiListener.remove(listener);
    } else {
      Log.error(TAG, 'listener is not exist');
    }
  }

  /**
   *  register wifi common event;
   */
  private async registerWifiCommonEvent(): Promise<void> {
    try {
      this.wifiSubscriber = await CommonEventManager.createSubscriber({events:
      [CommonEventManager.Support.COMMON_EVENT_WIFI_POWER_STATE, CommonEventManager.Support.COMMON_EVENT_WIFI_CONN_STATE,
        CommonEventManager.Support.COMMON_EVENT_WIFI_P2P_CONN_STATE]});
      CommonEventManager.subscribe(this.wifiSubscriber, (err, data) => {
        if (err) {
          Log.error(TAG, `subscribe failed, code is ${err.code}, message is ${err.message}`);
        } else {
          for (let wifiListener of this.wifiListener) {
            wifiListener.onConnectionStateChanged(data);
          }
        }
      });
    } catch (error) {
      Log.error(TAG, 'create subscriber fail: ' + JSON.stringify(error));
    }
  }

  /**
   * 获取当前设备连接信息
   */
  async getP2pLinkInfo(): Promise<wifi.WifiP2pLinkedInfo> {
    return wifi.getP2pLinkedInfo() as Promise<wifi.WifiP2pLinkedInfo>;
  }


  registerWifiP2pEvent(event, callback): void {
    wifi.on(event, callback);
  }

  unregisterWifiP2pEvent(event: string, callback?: (data) => void): void {
    switch (event) {
      case WifiModel.p2pPeerDeviceChange:
        wifi.off('p2pPeerDeviceChange', callback);
        break;
      case WifiModel.p2pConnectionChange:
        wifi.off('p2pConnectionChange', callback);
        break;
      case WifiModel.p2pStateChange:
        wifi.off('p2pStateChange');
        break;
      default:
        Log.error(TAG, 'error event: ' + event);
    }
  }

  /**
   * 开始发现p2p设备
   */
  discoveryP2pDevices(): boolean {
    let result: boolean = <boolean>wifi.startDiscoverDevices();
    if (!result) {
      Log.error(TAG, `discoveryStatus is ${result}`);
      //底层p2p服务未启动， 上报错误
      print.updateExtensionInfo(JSON.stringify(P2P_SERVICE_ERROR));
    }
    return result;
  }

  stopDiscoveryP2pDevices(): boolean {
    return wifi.stopDiscoverDevices() as boolean;
  }

  getP2pDevices(callback: (p2pDevices: wifi.WifiP2pDevice[]) => void): void {
    wifi.getP2pPeerDevices().then((p2pDevices: wifi.WifiP2pDevice[]) => {
      callback(p2pDevices);
    }).catch((error) => {
      Log.error(TAG, 'get p2p device failed: ' + JSON.stringify(error));
    });
  }

  /**
   * 连接打印机
   *
   * @param config
   * @param callback
   */
  connectToPrinter(config): boolean {
    Log.info(TAG, 'start to connect');
    return <boolean>wifi.p2pConnect(config);
  }

  /**
   * 断开打印机连接
   *
   * @param callback
   */
  disconnectToPrinter(): boolean {
    Log.info(TAG, 'start to disconnect');
    return <boolean>wifi.removeGroup();
  }

  stopConnection(): void {
    Log.debug(TAG, 'stop Connection');
    this.unregisterWifiP2pEvent(WifiModel.p2pConnectionChange);
    wifi.p2pCancelConnect();
  }

  close(): void {
    this.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange);
    this.stopConnection();
    if (this.wifiSubscriber !== undefined) {
      CommonEventManager.unsubscribe(this.wifiSubscriber);
    }
  }
}


export interface WifiListener {
  onConnectionStateChanged(data): void;
}