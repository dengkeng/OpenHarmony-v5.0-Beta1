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

import mdns from '@ohos.net.mdns';
import DiscoveredPrinter from '../discovery/DiscoveredPrinter';
import { Log } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey } from '@ohos/common';
import { SERVICE_IPP, SERVICE_IPPS, MDNS_EMITTER_EVENT_ID } from '@ohos/common';
import Discovery from './Discovery';
import type common from '@ohos.app.ability.common';
import CheckEmptyUtils from '@ohos/common';
import emitter from '@ohos.events.emitter';
import socket from '@ohos.net.socket';
import CommonUtils from '../utils/CommonUtils';
import uri from '@ohos.uri';
import wifi from '@ohos.wifi';

const TAG = 'MdnsDiscovery';

export class MdnsDiscovery extends Discovery {

  private readonly _serviceName: string;
  private _discoveryService: mdns.DiscoveryService;
  private context: common.ExtensionContext;
  private resolveEvent: emitter.InnerEvent;

  constructor(scheme: string) {
    super();
    switch (scheme) {
      case SERVICE_IPP:
        this._serviceName = SERVICE_IPP;
        break;
      case SERVICE_IPPS:
        this._serviceName = SERVICE_IPPS;
        break;
      default:
        throw new Error('unrecognized scheme ' + scheme);
    }
    this.resolveEvent = { eventId: MDNS_EMITTER_EVENT_ID };
    emitter.on(this.resolveEvent, this.resolveService);
  }

  private static toMdnsPrinter(info): DiscoveredPrinter {
    Log.debug(TAG, 'toMdnsPrinter enter');
    if (CheckEmptyUtils.isEmpty(info)) {
      Log.error(TAG, 'serviceInfo is undefined');
      return undefined;
    }
    const path = MdnsDiscovery.getServiceAttribute(info, 'rp');
    Log.debug(TAG, 'path is: ' + path);
    if (CheckEmptyUtils.checkStrIsEmpty(path)) {
      Log.error(TAG, 'rp is missing');
      return undefined;
    }
    if (path.startsWith('/')) {
      path === path.substring(1);
    }
    const uuid = MdnsDiscovery.getServiceAttribute(info, 'UUID');
    const printerId = `mdns://${uuid}`;
    let printer: DiscoveredPrinter = new DiscoveredPrinter(<string>info.serviceName, printerId, 0, uuid);
    printer.setUri(<string>info.host.address, <number>info.host.port, path);
    return printer;
  }

  private static getServiceAttribute(serviceInfo, key: string): string {
    const arr = serviceInfo.serviceAttribute;
    let result = arr.find((attr) => {
      return attr.key === key;
    });
    if (result === undefined) {
      Log.error(TAG, `key: ${key}, result is undefined`);
      return '';
    }
    let value: string = '';
    for (let num of result.value) {
      value += String.fromCharCode(<number>num);
    }
    return value;
  }

  /**
  * 开始查找打印机
   */
  onStartDiscovery(): void {
    if (mdns === undefined) {
      Log.error(TAG, 'mdns is undefined');
      return;
    }
    Log.info(TAG, 'createDiscoveryService: ' + this._serviceName);
    this.context = GlobalThisHelper.getValue(GlobalThisStorageKey.KEY_ABILITY_CONTEXT);
    if (CheckEmptyUtils.isEmpty(this._discoveryService)) {
      this._discoveryService = mdns.createDiscoveryService(this.context, this._serviceName);
    }
    if (this._discoveryService === undefined) {
      Log.error(TAG, 'discoveryService is undefined');
      return;
    }
    Log.info(TAG, 'register callback');
    this._discoveryService.on('serviceFound', this.onServiceFound);
    this._discoveryService.on('serviceLost', this.onServiceLost);
    Log.info(TAG, 'startSearchingMDNS');
    this._discoveryService.startSearchingMDNS();
  }

  /**
  * onServiceFound callback
   */
  private onServiceFound = (data): void => {
    Log.debug(TAG, `onServiceFound, data: ${JSON.stringify(data)} `);
    emitter.emit(this.resolveEvent, {data: data.serviceInfo});
  };

  private onServiceLost = (data): void => {
    Log.debug(TAG, `onServiceLost, data: ${CommonUtils.getSecurityPrinterName(data.serviceInfo.serviceName)} `);
    if (this.mCachePrinters.size === 0) {
      Log.error(TAG, 'cache printer is empty');
      return;
    }
    for (let key of this.mCachePrinters.keys()) {
      if (this.mCachePrinters.get(key).getDeviceName() === data.serviceInfo.serviceName) {
        this.printerLost(this.mCachePrinters.get(key)?.getPath());
      }
    }
  };

  private resolveService = (eventData: emitter.EventData): void => {
    Log.debug(TAG, 'resolveService enter');
    mdns.resolveLocalService(this.context, <mdns.LocalServiceInfo>eventData.data).then((data) => {
      Log.debug(`${TAG}, resolveLocalService, host is ${CommonUtils.getSecurityIp(data.host.address)}`);
      if (CheckEmptyUtils.checkStrIsEmpty(data.serviceName)) {
        Log.info(TAG, 'serviceName is empty');
        data.serviceName = eventData.data.serviceName;
      }
      let printer = MdnsDiscovery.toMdnsPrinter(data);
      this.printerFound(printer);
    }).catch((error) => {
      Log.error(TAG, `resolveLocalService, err is ${JSON.stringify(error)}`);
    });
    Log.debug(TAG, 'resolveService end');
  };

  /**
   * 停止搜索打印机，释放所有与搜索相关的资源
  */
  onStopDiscovery(): void {
    Log.info(TAG, 'onStopDiscovery enter');
    if (this._discoveryService === undefined) {
      Log.info(TAG, 'discoveryService is undefined');
      return;
    }
    this._discoveryService.stopSearchingMDNS();
  }
}