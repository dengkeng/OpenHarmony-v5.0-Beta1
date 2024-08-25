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
import { WIFI_POWER_CLOSED, P2P_DISCOVERY_DELAY } from '@ohos/common';
import type { Listener } from './discovery/Discovery';
import type DiscoveredPrinter from './discovery/DiscoveredPrinter';
import P2pUtils from './utils/P2pUtils';
import { Log } from '@ohos/common';
import type { PrintServiceAdapter } from './PrintServiceAdapter';
import LocalPrinter from './LocalPrinter';
import print from '@ohos.print';
import type { WifiListener } from './model/WifiModel';
import CommonEventManager from '@ohos.commonEventManager';
import HashSet from '@ohos.util.HashSet';
import taskpool from '@ohos.taskpool';
import type { PrinterInfo } from '@ohos/common';

const TAG = 'LocalDiscoverySession';

export class LocalDiscoverySession implements Listener, WifiListener {

  // Printers are removed after not being seen for this long
  private readonly mPrintServiceAdapter: PrintServiceAdapter;
  private readonly mPrinters: Map<string, LocalPrinter> = new Map();
  private readonly connectingIds: HashSet<string> = new HashSet<string>();

  constructor(printServiceAdapter: PrintServiceAdapter) {
    this.mPrintServiceAdapter = printServiceAdapter;
    this.mPrintServiceAdapter.wifiModel.addListener(this);
  }

  /**
   * 开始扫描打印机
   */
  public startPrinterDiscovery(): void {
    Log.info(TAG, 'startPrinterDiscovery() ');
    this.mPrintServiceAdapter.mdnsDiscovery.addListener(this);
    setTimeout(() => {
      this.mPrintServiceAdapter.p2pDiscovery.addListener(this);
    }, P2P_DISCOVERY_DELAY);
  }

  /**
   * 停止扫描打印机
   */
  public stopPrinterDiscovery(): void {
    Log.info(TAG, 'stopPrinterDiscovery() ');
    this.mPrintServiceAdapter.p2pDiscovery.removeListener(this);
    this.mPrintServiceAdapter.mdnsDiscovery.removeListener(this);
    if (!this.connectingIds.isEmpty()) {
      Log.info(TAG, 'p2p printer is connecting, close');
      for (let id of this.connectingIds) {
        let localPrinter: LocalPrinter = this.mPrinters.get(<string>id);
        if (localPrinter !== undefined && P2pUtils.isP2p(localPrinter.getDiscoveryPrinter())) {
          localPrinter.stopTracking();
        }
      }
      this.connectingIds.clear();
    }
  }

  /**
   * 开始连接打印机
   * @param path
   */
  public startConnectPrinter(path: string): void {
    Log.info(TAG, 'start Connect Printer enter...');

    if (!this.mPrinters.has(path)) {
      Log.error(TAG, 'printer is not exist');
      return;
    }
    let localPrinter: LocalPrinter = this.mPrinters.get(path);
    localPrinter.startTracking();
  }

  /**
   * 将正常连接中的p2p打印机存放到ids中
   * @param printerId
   */
  public addConnectingId(printerId: string): void {
    this.connectingIds.add(printerId);
  }

  /**
   * 删除连接成功或者连接失败的printerId
   * @param printerId
   */
  public removeConnectedId(printerId: string): void {
    if (!this.connectingIds.has(printerId)) {
      Log.error(TAG, 'removeConnectedId failed, printerId is not exist');
      return;
    }
    this.connectingIds.remove(printerId);
  }

  public stopConnectPrinter(printerId: string): void {
    Log.info(TAG, 'stop Connect Printer enter...');

    if (!this.mPrinters.has(printerId)) {
      Log.error(TAG, 'printer is not exist');
      return;
    }
    let localPrinter: LocalPrinter = this.mPrinters.get(printerId);
    localPrinter.stopTracking();
  }

  public getCapabilities(printerId: string): void {
    Log.info(TAG, 'get capabilities enter...');

    if (!this.mPrinters.has(printerId)) {
      Log.error(TAG, 'printerId is not exist');
      return;
    }

    let localPrinter: LocalPrinter = this.mPrinters.get(printerId);
    localPrinter.getCapabilities();
  }

  /**
   * getDiscoveryPrinterInfo
   *
   * @param printerId printer Id
   */
  public getDiscoveryPrinterInfo(printerId: string): DiscoveredPrinter {
    Log.debug(TAG, 'getDiscoveryPrinterInfo enter');
    let printerKey: string = undefined;
    let printer = undefined;
    for (let key of this.mPrinters.keys()) {
      if (printerId.indexOf(<string>key) > 0) {
        printerKey = key;
      }
    }
    if (printerKey === undefined) {
      Log.info(TAG, 'printerId is not exist');
      return undefined;
    }
    printer = this.mPrinters.get(printerKey);
    if (printer !== undefined) {
      // @ts-ignore
      return <object> printer.getDiscoveryPrinter();
    }
    return undefined;
  }

  public updateLocalPrinter(printer: DiscoveredPrinter): void {
    Log.debug(TAG, 'updateLocalPrinter enter');
    let localPrinter = this.mPrinters.get(printer.getPath());
    localPrinter.setDiscoveryPrinter(printer);
    this.mPrinters.set(printer.getPath(), localPrinter);
  }

  public close(): void {
    this.mPrinters.clear();
    this.mPrintServiceAdapter.p2pDiscovery.clearPrinterMap(false);
    this.mPrintServiceAdapter.mdnsDiscovery.clearPrinterMap(false);
    this.mPrintServiceAdapter.wifiModel.removeListener(this);
  }

  /**
   * 打印机发现的回调
   * @param discoveredPrinter
   */
  onPrinterFound(printer: DiscoveredPrinter): void {
    Log.info(TAG, 'onPrinterFound() enter, cache printer length: ' + this.mPrinters.size);
    if (P2pUtils.isUnavailable(printer)) {
      return;
    }
    let localPrinter: LocalPrinter = undefined;
    localPrinter = new LocalPrinter(this.mPrintServiceAdapter, this, printer);
    this.mPrinters.set(<string>printer.getPath(), localPrinter);

    // 构建printerInfo
    const printerInfo = localPrinter.createPrinterInfo();
    let task = new taskpool.Task(addPrinters, [printerInfo]);
    taskpool.execute(task);
  };


  /**
   * A previously-found printer is no longer discovered.
   *
   * @param printer DiscoveredPrinter
   */
  onPrinterLost(printer: DiscoveredPrinter): void {
    // this.mPrinters.delete(<string>printer.getPath());
    // 打印机丢失
    let task = new taskpool.Task(removePrinters, [printer.getId()]);
    taskpool.execute(task);
  };

  onConnectionStateChanged(data): void {
    if (data.event === CommonEventManager.Support.COMMON_EVENT_WIFI_POWER_STATE && data.code === WIFI_POWER_CLOSED) {
      // 上报wifi关闭事件
      Log.error(TAG, 'wifi state is closed');
      this.mPrintServiceAdapter.p2pDiscovery.clearPrinterMap(true);
      this.mPrintServiceAdapter.mdnsDiscovery.clearPrinterMap(true);
      this.mPrintServiceAdapter.p2pDiscovery.removeListener(this);
      this.mPrintServiceAdapter.mdnsDiscovery.removeListener(this);
    } else if (data.event === CommonEventManager.Support.COMMON_EVENT_WIFI_CONN_STATE && data.code === wifi.ConnState.DISCONNECTING) {
      Log.info(TAG, 'wifi state Disconnecting event: ' + JSON.stringify(data));
      this.mPrintServiceAdapter.mdnsDiscovery.clearPrinterMap(true);
    }
  }
}

function addPrinters(printerInfos :PrinterInfo[]): void {
  'use concurrent';
  print.addPrinters(printerInfos);
}

function removePrinters(printerIds :string[]): void {
  'use concurrent';
  print.removePrinters(printerIds);
}