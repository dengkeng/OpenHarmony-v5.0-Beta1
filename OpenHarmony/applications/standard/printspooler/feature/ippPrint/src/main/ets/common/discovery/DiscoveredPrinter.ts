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

import CommonUtils from '../utils/CommonUtils';
import uri from '@ohos.uri';
import { Log } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import { IPP_PORT, IPP_PATH, SCHEME_IPP, SCHEME_IPPS, EPSON_PRINTER, BISHENG_PRINTER } from '@ohos/common';

const TAG = 'DiscoveredPrinter';

export default class DiscoveredPrinter {

  /** Device name */
  private deviceName: string;

  /** Device mac address */
  private deviceAddress: string;

  /** Device status */
  private deviceStatus: number;

  /** Device path */
  private path: string;

  /** Device location */
  private location: string;

  /** Device connect uri */
  private uri: uri.URI;

  constructor(deviceName: string, path: string, deviceStatus: number, deviceAddress: string) {
    this.deviceName = deviceName;
    this.deviceStatus = deviceStatus;
    this.path = <string>path;
    this.deviceAddress = deviceAddress;
  }

  getId(): string {
    return this.path;
  }

  public getDeviceName(): string {
    return this.deviceName;
  }

  public setDeviceName(deviceName: string): void {
    this.deviceName = deviceName;
  }

  public getPath(): string {
    return this.path;
  }

  public setPath(path: string): void {
    this.path = path;
  }

  public getDeviceAddress(): string {
    return this.deviceAddress;
  }

  public setDeviceAddress(deviceAddress: string): void {
    this.deviceAddress = deviceAddress;
  }

  public getDeviceStatus(): number {
    return this.deviceStatus;
  }

  public setDeviceStatus(deviceStatus: number): void {
    this.deviceStatus = deviceStatus;
  }

  public getUri(): uri.URI {
    return this.uri;
  }

  public setUri(ip: string, port ?: number, path?: string): void {
    let portIt = port === undefined ? IPP_PORT : port;
    let pathIt = path === undefined ? IPP_PATH : path;
    Log.debug(TAG, 'portIt 2: ' + portIt);
    Log.debug(TAG, 'pathIt 2: ' + pathIt);
    this.uri = new uri.URI(`${SCHEME_IPP}://${ip}:${portIt}/${pathIt}`);
  }

  public isBiSheng(): boolean {
    if (CheckEmptyUtils.checkStrIsEmpty(this.deviceName)) {
      return false;
    }
    return this.deviceName.includes(BISHENG_PRINTER);
  }

  public toString(): string {
    let printerName = CommonUtils.getSecurityPrinterName(this.deviceName);
    if (CheckEmptyUtils.isEmpty<uri.URI>(this.uri)) {
      return `deviceName: ${printerName}, uri: undefined`;
    }
    let uri = CommonUtils.getSecurityIp(this.uri.toString());
    return `deviceName: ${printerName}, uri: ${uri}`;
  }
}