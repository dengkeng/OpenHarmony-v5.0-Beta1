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

import type DiscoveredPrinter from './DiscoveredPrinter';
import ArrayList from '@ohos.util.ArrayList';
import { Log } from '@ohos/common';
import CommonUtils from '../utils/CommonUtils';
import CheckEmptyUtils from '@ohos/common';

const TAG = 'Discovery';

export default abstract class Discovery {
  mCachePrinters: Map<string, DiscoveredPrinter> = new Map<string, DiscoveredPrinter>();
  private mListeners: ArrayList<Listener> = new ArrayList<Listener>();
  private mStarted: boolean = false;

  constructor() {

  }

  /**
  * 开始查找打印机
  */
  abstract onStartDiscovery(): void;

  /**
   * 停止搜索打印机，释放所有与搜索相关的资源
   */
  abstract onStopDiscovery(): void;

  /**
   * 任何Discovery对象找到打印机, 就添加监听器
   * @param listener 监听器
   */
  public addListener(listener: Listener): void {
    if (!this.mListeners.has(listener)) {
      Log.info(TAG, 'addListener ' + typeof listener);
      this.mListeners.add(listener);
    }
    this.start();
  }

  /**
   * Remove a listener so that it no longer receives notifications of found printers.
   * Discovery will continue for other listeners until the last one is removed.
   *
   * @param listener listener
   */
  public removeListener(listener: Listener): void {
    if (!this.mListeners.has(listener)) {
      Log.error(TAG, 'listener is not exist');
    } else {
      this.mListeners.remove(listener);
    }
    if (this.mListeners.isEmpty()) {
      this.stop();
    }
  }

  /**
   * Start if not already started
   */
  private start(): void {
    if (!this.mStarted) {
      Log.info(TAG, 'discovery is not started, now start');
      this.mStarted = true;
      this.onStartDiscovery();
    } else {
      this.reportCachePrinters();
    }
  }

  private async reportCachePrinters(): Promise<void> {
    Log.debug(TAG, 'discovery is started, no need start');
    if (this.mCachePrinters.size > 0) {
      let printers: DiscoveredPrinter[] = Array.from(this.mCachePrinters.values());
      this.mListeners.forEach((listener: Listener) => {
        for (let printer of printers) {
          listener.onPrinterFound(printer);
        }
      });
    }
  }

  public stop(): void {
    if (this.mStarted) {
      Log.info(TAG, 'discovery is started, now stop');
      this.mStarted = false;
      this.onStopDiscovery();
      this.mCachePrinters.clear();
    } else {
      Log.debug(TAG, 'discovery is not started, no need stop');
    }
  }

  /**
   * 发现了打印机列表
   *
   * @param printerArray
   */
  public printerFound(printer: DiscoveredPrinter): void {
    if (CheckEmptyUtils.isEmpty<DiscoveredPrinter>(printer)) {
      Log.error(TAG, 'printer is empty');
      return;
    }
    if (this.mCachePrinters.has(<string>printer.getPath()) ) {
      Log.info(TAG, 'Already reported the printer, ignoring');
      return;
    }
    Log.info(TAG, `found printer: ${CommonUtils.getSecurityPrinterName(printer.getDeviceName())}`);
    this.mCachePrinters.set(<string>printer.getPath(), printer);
    for (let listener of this.mListeners) {
      listener.onPrinterFound(printer);
    }
  }

  /**
   * 打印丢失, 上报并删除缓存的打印机
   *
   * @param uri
   */
  public printerLost(path: string): void {
    if (!this.mCachePrinters.has(path)) {
      Log.error(TAG, `${path} is not exist`);
      return;
    }
    let printer = this.mCachePrinters.get(path);

    let result = this.mCachePrinters.delete(path);
    if (!result) {
      Log.error(TAG, 'remove result is false');
      return;
    }
    Log.info(TAG, `${CommonUtils.getSecurityPrinterName(printer.getDeviceName())} lost`);
    for (let listener of this.mListeners) {
      listener.onPrinterLost(printer);
    }
  }

  /**
   * 删除map中的所有打印机信息
   */
  clearPrinterMap(isReported: boolean): void {
    Log.info(TAG, 'clear printer map');
    if (this.mCachePrinters.size === 0) {
      return;
    }
    if (isReported) {
      for (let key of this.mCachePrinters.keys()) {
        this.printerLost(<string>key);
      }
    } else {
      this.mCachePrinters.clear();
    }
  }

  /**
   * this object is in a started state
   *
   * @return Return true if this object is in a started state
   */
  isStarted(): boolean {
    return this.mStarted;
  }
}


export interface Listener {

  /**
  * A new printer has been discovered, or an existing printer has been updated
  *
  * @param printer DiscoveredPrinter
  */
  onPrinterFound(printer: DiscoveredPrinter): void;

  /**
   * A previously-found printer is no longer discovered.
   *
   * @param printer DiscoveredPrinter
   */
  onPrinterLost(printer: DiscoveredPrinter): void;
}

export interface P2PDiscoveryListener {
  onPeerFound(p2pDevice): void;
  onPeerLost(p2pDevice): void;
}