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
import P2PUtils from './utils/P2pUtils';
import CheckEmptyUtils, { Log, PrinterCapability, PrinterInfo, IPP_CONNECT_ERROR } from '@ohos/common';
import type { PrintServiceAdapter } from './PrintServiceAdapter';
import type { LocalDiscoverySession } from './LocalDiscoverySession';
import type DiscoveredPrinter from './discovery/DiscoveredPrinter';
import LocalPrinterCapabilities from './napi/LocalPrinterCapabilities';
import type ConnectionListener from './connect/ConnectionListener';
import P2PPrinterConnection from './connect/P2pPrinterConnection';
import type { CapabilitiesCache, OnLocalPrinterCapabilities } from './ipp/CapabilitiesCache';
import print from '@ohos.print';

const TAG = 'LocalPrinter';

export default class LocalPrinter implements ConnectionListener, OnLocalPrinterCapabilities {
  private static readonly p2pDiscoveryProtocol: string = 'wifi_direct';
  private static readonly descriptionSplit: string = '&&';
  private static readonly maxRetryTimes: number = 2;
  private readonly mPrintServiceAdapter: PrintServiceAdapter;
  private readonly mSession: LocalDiscoverySession;
  private readonly mPrinterId: string; // number类型

  private mTracking: boolean = false; //是否正在执行连接
  private mCapabilities: PrinterCapability;
  private mDiscoveredPrinter: DiscoveredPrinter;
  private mP2pPrinterConnection: P2PPrinterConnection;
  private getCapsFailedTimes: number = 0;

  constructor(printServiceAdapter: PrintServiceAdapter, session: LocalDiscoverySession,
              discoveredPrinter: DiscoveredPrinter) {
    this.mPrintServiceAdapter = printServiceAdapter;
    this.mSession = session;
    this.mDiscoveredPrinter = discoveredPrinter;
    this.mPrinterId = discoveredPrinter.getId();
  }

  /**
   * get capabilities
   *
   * @return Return capabilities or null if not present
   */
  getCapabilities(): void {
    if (CheckEmptyUtils.isEmpty(this.mDiscoveredPrinter)) {
      Log.error(TAG, 'discovery printer is undefined');
      return;
    }
    Log.info(TAG, 'caps is empty, now to request');
    let capabilitiesCache: CapabilitiesCache = this.mPrintServiceAdapter.capabilitiesCache;
    capabilitiesCache.requestCapabilities(this.mDiscoveredPrinter, this);
  }

  /**
   * Create a PrinterInfo from this record or null if not possible
   *
   * @param knownGood boolean
   * @return PrinterInfo or null
   */
  createPrinterInfo(): PrinterInfo {
    //创建PrinterInfo对象 返回给打印框架
    let printerInfo: PrinterInfo = new PrinterInfo(this.mPrinterId, this.mDiscoveredPrinter.getDeviceName(), print.PrinterState.PRINTER_ADDED);
    if (!CheckEmptyUtils.isEmpty(this.mCapabilities)) {
      let printerCapability: PrinterCapability = new PrinterCapability();
      LocalPrinterCapabilities.buildPrinterCapability(printerCapability, this.mCapabilities);
      printerInfo.capability = printerCapability;
      printerInfo.description = LocalPrinter.p2pDiscoveryProtocol +
      LocalPrinter.descriptionSplit +
      this.mDiscoveredPrinter.getUri().host;
      let options: string = LocalPrinterCapabilities.buildExtraCaps(this.mCapabilities, this.mDiscoveredPrinter.getUri().toString());
      printerInfo.options = options;
    }
    return printerInfo;
  }


  /**
   * 开始连接打印机
   */
  public startTracking(): void {
    Log.debug(TAG, 'start connect to printer, track is: ' + this.mTracking);
    if (!P2PUtils.isP2p(this.mDiscoveredPrinter)) {
      Log.debug(TAG, 'mdns printer');
      this.getCapabilities();
      return;
    }
    if (this.mTracking) {
      Log.error(TAG, 'ERROR: isTracking: ' + this.mTracking);
      return;
    }
    this.mTracking = true;
    Log.debug(TAG, 'p2p printer');
    if (!CheckEmptyUtils.isEmpty(this.mP2pPrinterConnection)) {
      Log.error(TAG, 'ERROR: connection in progress');
      this.mP2pPrinterConnection = undefined;
      return;
    }
    this.mSession.addConnectingId(<string> this.mDiscoveredPrinter.getId());
    this.mP2pPrinterConnection = new P2PPrinterConnection(this.mPrintServiceAdapter, this.mDiscoveredPrinter, this);
    this.mP2pPrinterConnection.connectToPeer();
  }

  /**
   * 停止连接打印机
   */
  public stopTracking(): void {
    if (!P2PUtils.isP2p(this.mDiscoveredPrinter)) {
      Log.debug(TAG, 'mdns printer, no need stop tracking');
      return;
    }
    if (this.mP2pPrinterConnection !== undefined) {
      Log.info(TAG, 'printer is connecting, close');
      this.mSession.removeConnectedId(this.mPrinterId);
      this.mP2pPrinterConnection.close();
    } else {
      Log.info(TAG, 'mP2pPrinterConnection is undefined, remove p2p group');
      this.mPrintServiceAdapter.wifiModel.getP2pLinkInfo().then((linkInfo: wifi.WifiP2pLinkedInfo) => {
        if (linkInfo.connectState === wifi.P2pConnectState.CONNECTED) {
          this.mPrintServiceAdapter.wifiModel.disconnectToPrinter();
        } else {
          Log.info(TAG, 'p2p is not connected');
          this.mPrintServiceAdapter.wifiModel.stopConnection();
        }
      });
    }
    this.mP2pPrinterConnection = undefined;
    this.mTracking = false;
  }

  /**
   * get printerId
   *
   * @return PrinterId
   */
  public getPrinterId(): string {
    return this.mPrinterId;
  }

  public setDiscoveryPrinter(printer: DiscoveredPrinter): void {
    this.mDiscoveredPrinter = printer;
  }

  public getDiscoveryPrinter(): DiscoveredPrinter {
    Log.debug(TAG, 'getDiscoveryPrinter: ' + this.mDiscoveredPrinter.toString());
    return this.mDiscoveredPrinter;
  }


  /**
   * 获取打印机能力成功的回调
   *
   * @param printerCaps
   */
  onCapabilities(printerCaps: PrinterCapability): void {
    if (!CheckEmptyUtils.isEmpty(printerCaps)) {
      this.mCapabilities = printerCaps;
      this.getCapsFailedTimes = 0;
      // 上报打印机获取能力成功的回调
      let printerInfo: PrinterInfo = this.createPrinterInfo();
      print.updatePrinters([printerInfo]).catch((error) => {
        Log.error(TAG, 'update error: ' + JSON.stringify(error));
      });
    } else {
      if (this.getCapsFailedTimes < LocalPrinter.maxRetryTimes) {
        Log.error(TAG, `getCapabilities failed, retry ${this.getCapsFailedTimes} times`);
        this.getCapsFailedTimes++;
        this.getCapabilities();
      } else {
        Log.error(TAG, 'printerCaps is null');
        this.getCapsFailedTimes = 0;
        print.updateExtensionInfo(JSON.stringify(IPP_CONNECT_ERROR));
      }
    }
  }


  /**
   * 打印机连接成功回调
   * @param printer
   */
  onConnectionComplete(printer: DiscoveredPrinter): void {
    this.mTracking = false;
    this.mP2pPrinterConnection = undefined;
    if (CheckEmptyUtils.isEmpty(printer)) {
      Log.error(TAG, 'connect failed');
      return;
    }
    this.mDiscoveredPrinter = printer;
    this.mSession.updateLocalPrinter(printer);
    // 上报打印机机连接成功的状态
    // @ts-ignore
    print.updatePrinterState(this.mPrinterId, PrinterState.PRINTER_CONNECTED);
    this.mSession.removeConnectedId(this.mPrinterId);

    //连接成功获取打印机能力
    if (CheckEmptyUtils.isEmpty(this.mCapabilities)) {
      this.getCapabilities();
    } else {
      this.onCapabilities(this.mCapabilities);
    }
  }

  /**
   * 打印机连接超时回调
   * @param delayed
   */
  onConnectionDelayed(): void {
    this.mTracking = false;
    this.mP2pPrinterConnection = undefined;
    // 通知打印框架连接失败
    Log.error(TAG, 'connect delay');
    print.updatePrinterState(this.mPrinterId, print.PrinterState.PRINTER_DISCONNECTED);
    this.mSession.removeConnectedId(this.mPrinterId);
  }
}