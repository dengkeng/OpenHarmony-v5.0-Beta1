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

import { WIFI_POWER_CLOSED } from '@ohos/common';
import { CONNECTION_POP } from '@ohos/common';
import type DiscoveredPrinter from '../discovery/DiscoveredPrinter';
import type { PrintServiceAdapter } from '../PrintServiceAdapter';
import type ConnectionListener from '../connect/ConnectionListener';
import { Log } from '@ohos/common';
import { WifiModel } from '../model/WifiModel';
import wifi from '@ohos.wifi';
import CheckEmptyUtils from '@ohos/common';
import CommonUtils from '../utils/CommonUtils';
import type { WifiListener } from '../model/WifiModel';
import CommonEventManager from '@ohos.commonEventManager';
// @ts-ignore
import print from '@ohos.print';

const TAG: string = 'P2PPrinterConnection';
const CONNECT_DELAYED_TIME: number = 30000;
const P2P_CONNECT_DELAYED_PERIOD: number = 3000;

export default class P2PPrinterConnection implements WifiListener {

  private static readonly connectStateInit: number = 1;
  private static readonly connectStateDiscovery: number = 2;
  private static readonly connectStaConnected: number = 3;

  private readonly mPrintServiceAdapter: PrintServiceAdapter;
  private readonly mPrinter: DiscoveredPrinter;
  private mListener: ConnectionListener;
  private connectState: number;
  private mWifiModel: WifiModel;
  private delayTimer: number;
  private invited: boolean = false;
  private inviteDelayTimer: number;

  constructor(printServiceAdapter: PrintServiceAdapter, printer: DiscoveredPrinter, listener: ConnectionListener) {
    this.mPrintServiceAdapter = printServiceAdapter;
    this.mWifiModel = this.mPrintServiceAdapter.wifiModel;
    this.mListener = listener;
    this.mPrinter = printer;
    this.mWifiModel.addListener(this);
  }

  /**
  * 连接打印机
  *
  * @param p2pLinkInfo 连接信息
  */
  public connectToPeer(): void {
    Log.info(TAG, 'connectToPeer enter, state: ' + this.connectState);
    this.mWifiModel.getP2pLinkInfo().then((p2pLinkInfo: wifi.WifiP2pLinkedInfo) => {
      if (p2pLinkInfo.connectState === wifi.P2pConnectState.CONNECTED) {
        //当前状态已连接
        Log.info(TAG, 'client state is connecting');
        wifi.getCurrentGroup().then((groupInfo: wifi.WifiP2pGroupInfo) => {
          Log.info(TAG, 'get group info success');
          if (groupInfo.ownerInfo.deviceAddress === this.mPrinter.getDeviceAddress()) {
            //当前打印机已经处在连接状态
            Log.info(TAG, 'The printer is already connected.');
            this.mPrinter.setUri(<string>groupInfo.goIpAddress);
            this.mListener.onConnectionComplete(this.mPrinter);
          } else {
            //当前状态已连接, 断开连接, 连接其它打印机
            Log.info(TAG, 'connect to other printers');
            this.mWifiModel.registerWifiP2pEvent(WifiModel.p2pConnectionChange, this.handleP2pCancelConnectChange);
            this.mWifiModel.disconnectToPrinter();
          }
        }).catch((error) => {
          Log.error(TAG, 'getCurrentGroup error: ' + JSON.stringify(error));
        });
      } else if (p2pLinkInfo.connectState === wifi.P2pConnectState.DISCONNECTED) {
        //当前状态未连接
        Log.info(TAG, 'client state is not connecting, start to connect');
        this.connectToPrinter();
      } else {
        Log.error(TAG, 'unknown error');
      }
    }).catch((error) => {
      Log.error(TAG, 'getP2pLinkInfo error: ' + JSON.stringify(error));
    });
  }

  public close(): void {
    if (this.inviteDelayTimer !== undefined) {
      clearTimeout(this.inviteDelayTimer);
    }
    if (this.delayTimer !== undefined) {
      clearTimeout(this.delayTimer);
    }
    Log.debug(TAG, 'stop connect to: ' + CommonUtils.getSecurityMac(this.mPrinter.getDeviceAddress()));
    this.mWifiModel.stopConnection();
  }

  /**
  * 取消连接的状态回调
  *
  * @param p2pLinkedInfo
  */
  private handleP2pCancelConnectChange = (p2pLinkedInfo: wifi.WifiP2pLinkedInfo): void => {
    if (this.connectState === P2PPrinterConnection.connectStateInit) {
      Log.debug(TAG, 'cancel connect msg has report, ignore');
      return;
    }
    Log.error(TAG, `p2p printer cancel Connect Change enter, state: ${p2pLinkedInfo.connectState}`);
    if (p2pLinkedInfo.connectState === wifi.P2pConnectState.DISCONNECTED) {
      Log.error(TAG, 'cancel connect success');
      this.connectState = P2PPrinterConnection.connectStateInit;
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pConnectionChange, this.handleP2pCancelConnectChange);
      this.connectToPrinter();
    } else {
      Log.error(TAG, 'p2pConnectState is not false');
    }
  };

  /**
  * 连接的状态回调
  *
  * @param p2pLinkedInfo
  */
  private p2pConnectionChangeReceive = (p2pLinkedInfo: wifi.WifiP2pLinkedInfo): void => {
    if (this.connectState === P2PPrinterConnection.connectStaConnected) {
      Log.debug(TAG, 'connect msg has report, ignore');
      return;
    }
    Log.error(TAG, 'p2p printer Connect state change: ' + p2pLinkedInfo.connectState + ', ip: ' + CommonUtils.getSecurityIp(<string>p2pLinkedInfo.groupOwnerAddr));
    if (p2pLinkedInfo.connectState === wifi.P2pConnectState.CONNECTED) {
      // 连接成功, 清除邀请弹窗的的定时器
      if (this.inviteDelayTimer !== undefined) {
        clearTimeout(this.inviteDelayTimer);
      }
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange);
      if (p2pLinkedInfo.groupOwnerAddr.length === 0) {
        Log.error(TAG, 'p2pConnectState is true, groupOwnerAddr is null');
      } else {
        this.connectState = P2PPrinterConnection.connectStaConnected;
        // 获取打印机ip成功, 清除连接失败的定时器
        if (this.delayTimer !== undefined) {
          clearTimeout(this.delayTimer);
        }
        let printerIp: string = <string>p2pLinkedInfo.groupOwnerAddr;
        Log.info(TAG, 'printer is ' + CommonUtils.getSecurityIp(printerIp));
        this.mPrinter.setUri(printerIp);
        // 取消连接状态变化的监听事件
        this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pConnectionChange, this.p2pConnectionChangeReceive);
        this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.p2pPeersChangeReceive);
        this.mWifiModel.removeListener(this);
        // 通知连接成功
        this.mListener.onConnectionComplete(this.mPrinter);
      }
    } else {
      Log.error(TAG, 'p2pConnectState is false');
    }
  };

  private p2pPeersChangeReceive = (p2pDevicesLists: wifi.WifiP2pDevice[]): void => {
    Log.debug(TAG, 'p2pPeersChangeReceive, device len: ' + p2pDevicesLists.length);
    if (CheckEmptyUtils.isEmptyArr<wifi.WifiP2pDevice>(p2pDevicesLists)) {
      Log.error(TAG, 'p2pDevicesLists is empty');
      return;
    }
    let device = p2pDevicesLists.find((p2pDevice) => {
      return p2pDevice.deviceAddress === this.mPrinter.getDeviceAddress();
    });
    if (CheckEmptyUtils.isEmpty(device)) {
      return;
    }
    // @ts-ignore
    if (!this.invited && device.devStatus === wifi.P2pDeviceStatus.INVITED) {
      this.invited = true;
      this.inviteDelayTimer = setTimeout(() => {
        Log.info(TAG, 'printer is invite, notify the user');
        print.updateExtensionInfo(JSON.stringify(CONNECTION_POP));
      }, P2P_CONNECT_DELAYED_PERIOD);
    }
  };

  private discoveryPrinterCallback = (p2pDevices: wifi.WifiP2pDevice[]): void => {
    let device = p2pDevices.find((device: wifi.WifiP2pDevice) => {
      return device.deviceAddress === this.mPrinter.getDeviceAddress();
    });
    if (CheckEmptyUtils.isEmpty(device)) {
      return;
    }
    // 打印机存在，执行连接
    Log.info(TAG, 'printer is found');
    if (this.connectState === P2PPrinterConnection.connectStateDiscovery) {
      Log.info(TAG, 'printer has found, ignore');
      return;
    }
    this.connectState = P2PPrinterConnection.connectStateDiscovery;
    this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.discoveryPrinterCallback);
    this.startConnect(this.mPrinter);
  };

  /**
   * 开始连接打印机
   *
   * @param printer
   */
  private connectToPrinter(): void {
    Log.info(TAG, 'start find printer');
    this.delayTimer = setTimeout(this.connectTimeOutOperation, CONNECT_DELAYED_TIME);
    // 发现打印机
    this.mWifiModel.registerWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.discoveryPrinterCallback);
    this.mWifiModel.discoveryP2pDevices();
    this.mWifiModel.getP2pDevices(this.discoveryPrinterCallback);
  }

  /**
   *  30s后连接超时，清除资源
   */
  private connectTimeOutOperation = (): void => {
    this.mWifiModel.removeListener(this);
    if (this.connectState === P2PPrinterConnection.connectStaConnected) {
      Log.error(TAG, 'printer is connected, timer close fail');
    } else if (this.connectState === P2PPrinterConnection.connectStateInit) {
      // 打印机未发现
      Log.error(TAG, 'discovery delayed, printer is not found');
      this.mWifiModel.removeListener(this);
      this.mListener.onConnectionDelayed();
    } else {
      // 连接超时
      Log.error(TAG, 'connection delayed');
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pConnectionChange, this.p2pConnectionChangeReceive);
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.p2pPeersChangeReceive);
      this.mWifiModel.removeListener(this);
      this.mWifiModel.stopConnection();
      this.mListener.onConnectionDelayed();
    }
  };

  private startConnect(printer: DiscoveredPrinter): void {
    Log.debug(TAG, 'connect to ' + CommonUtils.getSecurityMac(printer.getDeviceAddress()));
    let config: wifi.WifiP2PConfig = this.configForPeer(printer);
    this.mWifiModel.registerWifiP2pEvent(WifiModel.p2pConnectionChange, this.p2pConnectionChangeReceive);
    this.mWifiModel.registerWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.p2pPeersChangeReceive);
    let connectionOperation: boolean = this.mWifiModel.connectToPrinter(config);
    if (!connectionOperation) {
      Log.error(TAG, 'connection operation failed');
      if (this.delayTimer !== undefined) {
        clearTimeout(this.delayTimer);
      }
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pConnectionChange, this.p2pConnectionChangeReceive);
      this.mWifiModel.unregisterWifiP2pEvent(WifiModel.p2pPeerDeviceChange, this.p2pPeersChangeReceive);
      this.mListener.onConnectionDelayed();
      return;
    }
    Log.error(TAG, 'connection operation success');
  }

  /**
   * 获取连接设置项
   * @param printer
   */
  private configForPeer(printer: DiscoveredPrinter): wifi.WifiP2PConfig {
    return {
      deviceAddress: printer.getDeviceAddress(),
      netId: NetId.TEMPORARY_GROUP,
      passphrase: '',
      groupName: '',
      goBand: wifi.GroupOwnerBand.GO_BAND_AUTO,
    };
  }

  onConnectionStateChanged(data): void {
    if (data.event === CommonEventManager.Support.COMMON_EVENT_WIFI_POWER_STATE && data.code === WIFI_POWER_CLOSED) {
      // 上报wifi关闭事件
      Log.error(TAG, 'wifi state is closed, eventData: ' + JSON.stringify(data));
      if (this.connectState === P2PPrinterConnection.connectStateDiscovery) {
        Log.info(TAG, 'p2p is connecting');
        this.mListener.onConnectionComplete(null);
        this.close();
      }
    }
  }
}

enum NetId {
  TEMPORARY_GROUP = -1,
  PERMANENT_GROUP = -2
}