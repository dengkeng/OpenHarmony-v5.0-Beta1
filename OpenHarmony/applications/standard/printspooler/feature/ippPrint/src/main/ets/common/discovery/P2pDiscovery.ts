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

import type { P2PDiscoveryListener } from './Discovery';
import type wifi from '@ohos.wifi';
import DiscoveredPrinter from '../discovery/DiscoveredPrinter';
import { Log } from '@ohos/common';
import type { PrintServiceAdapter } from '../PrintServiceAdapter';
import Discovery from './Discovery';
import CheckEmptyUtils from '@ohos/common';

const TAG = 'P2pDiscovery';

/**
 * Discover previously-added P2P devices, if any.
 */
export class P2PDiscovery extends Discovery implements P2PDiscoveryListener {
  /**
   * SCHEME P2P
   */
  public static readonly schemeP2p: string = 'p2p';

  private mDiscoveringPeers: boolean = false;
  private mPrintServiceAdapter: PrintServiceAdapter;

  constructor(printServiceAdapter: PrintServiceAdapter) {
    super();
    this.mPrintServiceAdapter = printServiceAdapter;
  }

  /**
   * 把发现的p2p打印机转换为DiscoveredPrinter
   *
   * @param device
   */
  public static toPrinter(device: wifi.WifiP2pDevice): DiscoveredPrinter {
    let path: string = this.toPath(device);
    let deviceName: string = <string>device.deviceName;
    if (deviceName.trim() === '') {
      deviceName = device.deviceAddress;
    }
    return new DiscoveredPrinter(deviceName, path, <number>device.deviceStatus, <string>device.deviceAddress);
  }

  /**
   * path 添加 p2p发现标记
   *
   * @param device
   */
  public static toPath(device: wifi.WifiP2pDevice): string {
    return this.schemeP2p + '://' + device.deviceAddress.replace(/:/g, '-');
  }

  /**
   * 开始发现p2打印机设备
   */
  onStartDiscovery(): void {
    if (this.mDiscoveringPeers) {
      Log.error(TAG, 'p2p discovery is already start');
      return;
    }

    this.mDiscoveringPeers = true;
    Log.info(TAG, `onStartDiscovery ${this.mDiscoveringPeers}`);
    //开始发现
    this.mPrintServiceAdapter.p2pMonitor.discovery(this);
  }

  /**
   * 停止发现打印机设备
   */
  onStopDiscovery(): void {
    if (this.mDiscoveringPeers) {
      this.mDiscoveringPeers = false;
      //停止发现打印机
      this.mPrintServiceAdapter.p2pMonitor.stopDiscover(this);
      this.clearPrinterMap(false);
    }
  }

  onPeerFound(p2pDevice): void {
    if (CheckEmptyUtils.isEmpty(p2pDevice)) {
      Log.error(TAG, 'p2p devices is null');
      return;
    }
    const printer = P2PDiscovery.toPrinter(p2pDevice);
    this.printerFound(printer);
  }

  onPeerLost(p2pDevice): void {
    if (CheckEmptyUtils.isEmpty(p2pDevice)) {
      Log.error(TAG, 'p2p devices is null');
      return;
    }
    this.printerLost(P2PDiscovery.toPath(p2pDevice));
  }
}
