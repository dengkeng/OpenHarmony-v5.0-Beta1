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

import type Want from '@ohos.application.Want';
// @ts-ignore
import PrintExtensionAbility from '@ohos.app.ability.PrintExtensionAbility';
import {LocalDiscoverySession} from '@ohos/ippprint';
import { P2PDiscovery } from '@ohos/ippprint';
import { P2PMonitor } from '@ohos/ippprint';
import { MdnsDiscovery } from '@ohos/ippprint';
import {PrintServiceAdapter} from '@ohos/ippprint';
import { Backend } from '@ohos/ippprint';
import { CapabilitiesCache } from '@ohos/ippprint';
import { Log, MediaSizeHelper } from '@ohos/common';
import { WifiModel } from '@ohos/ippprint';
import type { PrintJob } from '@ohos/common';
import { SERVICE_IPP } from '@ohos/common';
import { checkWifiEnable } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import print from '@ohos.print';

const TAG = 'PrintExtension';

export default class PrintExtension extends PrintExtensionAbility {
  private mPrintServiceAdapter: PrintServiceAdapter;
  private mLocalDiscoverySession: LocalDiscoverySession;

  onCreate(want: Want): void {
    // @ts-ignore
    GlobalThisHelper.createValue(this.context, GlobalThisStorageKey.KEY_ABILITY_CONTEXT);
    // @ts-ignore
    GlobalThisHelper.createValue<string>(<string> this.context.filesDir, GlobalThisStorageKey.KEY_FILES_DIR);
    this.init();
  }

  /**
   * init
   */
  init(): void {
    this.mPrintServiceAdapter = <PrintServiceAdapter>PrintServiceAdapter.getInstance();
    this.mPrintServiceAdapter.backend = <Backend> new Backend();
    this.mPrintServiceAdapter.wifiModel = <WifiModel> new WifiModel();
    this.mPrintServiceAdapter.capabilitiesCache = <CapabilitiesCache> new CapabilitiesCache(this.mPrintServiceAdapter);
    this.mPrintServiceAdapter.p2pDiscovery = <P2PDiscovery> new P2PDiscovery(this.mPrintServiceAdapter);
    this.mPrintServiceAdapter.p2pMonitor = <P2PMonitor> new P2PMonitor();
    this.mPrintServiceAdapter.mdnsDiscovery = <MdnsDiscovery> new MdnsDiscovery(SERVICE_IPP);
    this.mPrintServiceAdapter.localDiscoverySession = <LocalDiscoverySession> new LocalDiscoverySession(this.mPrintServiceAdapter);
    // @ts-ignore
    MediaSizeHelper.init(this.context);
  }

  /**
   * start discovery printer
   */
  onStartDiscoverPrinter(): void {
    Log.info(TAG, 'onStartDiscoverPrinter enter');
    this.mLocalDiscoverySession = <LocalDiscoverySession> this.mPrintServiceAdapter.localDiscoverySession;
    if (this.mLocalDiscoverySession === undefined) {
      return;
    }
    if (!checkWifiEnable()) {
      Log.error(TAG, 'wifi is inactive');
      return;
    }
    this.mLocalDiscoverySession.startPrinterDiscovery();
  }

  /**
   * stop discovery printer
   */
  onStopDiscoverPrinter(): void {
    Log.info(TAG, 'onStopDiscoverPrinter enter');
    if (this.mLocalDiscoverySession === undefined) {
      Log.error(TAG, 'mLocalDiscoverySession is null');
      return;
    }
    this.mLocalDiscoverySession.stopPrinterDiscovery();
  }

  /**
   * connect to printer
   */
  onConnectPrinter(printerId: string | number): void {
    Log.info(TAG, 'onConnectPrinter enter');
    if (printerId === undefined || printerId === null) {
      Log.error(TAG, 'printerId is undefined');
      return;
    }
    if (typeof printerId === 'number') {
      printerId = printerId.toString();
    }
    if (this.mLocalDiscoverySession === undefined) {
      Log.error(TAG, 'mLocalDiscoverySession is undefined');
      return;
    }
    this.mLocalDiscoverySession.startConnectPrinter(printerId);
  }

  /**
   * disconnect to printer
   */
  onDisconnectPrinter(printerId: string | number): void {
    Log.info(TAG, 'onDisconnectPrinter enter');
    if (printerId === undefined || printerId === null) {
      Log.error(TAG, 'printerId is undefined');
      return;
    }
    if (typeof printerId === 'number') {
      printerId = printerId.toString();
    }
    if (this.mLocalDiscoverySession === undefined) {
      Log.error(TAG, 'mLocalDiscoverySession is undefined');
      return;
    }
    this.mLocalDiscoverySession.stopConnectPrinter(printerId);
  }

  /**
   * start job
   *
   * @param printJob
   */
  onStartPrintJob(printJob: PrintJob): void {
    Log.debug(TAG, 'onStartPrintJob');
  }

  /**
   * cancel job
   *
   * @param PrintJob
   */
  onCancelPrintJob(printJob: PrintJob): void {
    Log.info(TAG, 'onCancelPrintJob');
  }


  /**
   * request printer caps
   *
   * @param printerId
   */
  onRequestPrinterCapability(printerId: string | number): print.PrinterCapability {
    Log.info(TAG, 'onRequestPrinterCapability enter');
    if (printerId === undefined || printerId === null) {
      Log.error(TAG, 'printerId is undefined');
      return;
    }
    if (typeof printerId === 'number') {
      printerId = printerId.toString();
    }
    if (this.mLocalDiscoverySession === undefined) {
      Log.error(TAG, 'mLocalDiscoverySession is undefined');
      return;
    }
    this.mLocalDiscoverySession.getCapabilities(printerId);
  }

  onDestroy(): void {
    Log.info(TAG, 'onDestroy');
  }
}