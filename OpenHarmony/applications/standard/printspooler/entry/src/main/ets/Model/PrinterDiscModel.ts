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
import { Constants, AppCommonEvent, AppStorageKeyName } from '@ohos/common';
import AppStorageHelper from '../Common/Adapter/AppStorageHelper';
import { PrinterCapability, PrinterInfo } from '@ohos/common';
import emitter from '@ohos.events.emitter';
import { StringUtil } from '@ohos/common';
import Util from '../Common/Utils/Util';

const TAG = '[DeviceDiscModel]:';

/**
 * PrinterDiscModel
 */

/**
 * Printer discovery model
 */
export class PrinterDiscModel {
  public mPrinters: Array<PrinterInfo> = new Array<PrinterInfo>();

  /**
   * reset
   */
  public reset(): void {
    this.mPrinters = [];
    AppStorageHelper.setValue<Array<PrinterInfo>>(this.mPrinters, AppStorageKeyName.PRINTER_QUEUE_NAME);
  }

  /**
   * remove device
   *
   * @param deviceId device id
   */
  public removePrinter(printerId: string): void {
    this.mPrinters = this.mPrinters.filter((printer) => printer.printerId !== printerId);
    Log.info(TAG, 'remove printer, printerId = ' + StringUtil.splitMac(printerId) + ', printer num = ' + JSON.stringify(this.mPrinters.length));
    AppStorageHelper.setValue<Array<PrinterInfo>>(this.mPrinters, AppStorageKeyName.PRINTER_QUEUE_NAME);
  }

  public findPrinter(printerId: string): boolean {
    Log.info(TAG, 'find printer');
    let printer = this.mPrinters.find((printer)=> printer.printerId === printerId);
    Log.debug(TAG, 'find printer, printerId = ' + StringUtil.splitMac(printerId) + ', printer = ' + JSON.stringify(printer));
    if (printer !== undefined && printer !== null) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * add device
   *
   * @param device Device
   * @return true for added
   */
  public addPrinter(printer: PrinterInfo): boolean {
    for (let index = 0; index < this.mPrinters.length; index++) {
      if (this.mPrinters[index].printerId === printer.printerId) {
        Log.info(TAG, 'printer is already added, printer = ' + StringUtil.encodeCommonString(printer.printerName));
        return false;
      }
    }
    if (Util.isMdnsPrinter(<string> printer.printerId)) { //eprint打印机置顶
      this.mPrinters.unshift(printer);
    } else {
      this.mPrinters.push(printer);
    }
    let printerJSON = JSON.stringify(printer);
    let innerEvent = {
      eventId: AppCommonEvent.ADD_PRINTER_EVENT,
      priority: emitter.EventPriority.HIGH
    };
    let eventData = {
      data: {
        'printer': printerJSON
      }
    };
    emitter.emit(innerEvent, eventData);
    Log.info(TAG, 'add printer, printer :' + StringUtil.encodeCommonString(printer.printerName) + ', printer num = ' + JSON.stringify(this.mPrinters.length));
    AppStorageHelper.setValue<Array<PrinterInfo>>(this.mPrinters, AppStorageKeyName.PRINTER_QUEUE_NAME);
    return true;
  }

  /**
   * printer state change
   *
   * @param printerId printer id
   * @param state printer state
   * @return true for change
   */
  public printerStateChange(printerId: string, state: number): boolean {
    Log.error(TAG, 'PrinterStateChange printerId: ' + StringUtil.splitMac(printerId) + ' state : ' + JSON.stringify(state));
    for (let index = 0; index < this.mPrinters.length; index++) {
      if (this.mPrinters[index].printerId === printerId) {
        Log.info(TAG, 'printer: ' + StringUtil.splitMac(printerId) + ' state : ' + JSON.stringify(this.mPrinters[index].printerState) + ' change to :' + JSON.stringify(state));
        this.mPrinters[index].printerState = state;
        AppStorageHelper.setValue<Array<PrinterInfo>>(this.mPrinters, AppStorageKeyName.PRINTER_QUEUE_NAME);

        let innerEvent = {
          eventId: AppCommonEvent.PRINTER_STATE_CHANGE_EVENT,
          priority: emitter.EventPriority.HIGH
        };
        emitter.emit(innerEvent);
      }
    }
    return true;
  }

  /**
   * printer capability update
   *
   * @param printerId  printer id
   * @param capability printer capability
   * @param options printer capability
   * @param description printer descriptions
   * @return true for update
   */
  public printerUpdateCapability(printerId: string, capability: PrinterCapability, options: string, description: string): boolean {
    Log.info(TAG, 'PrinterUpdateCapability printerId: ' + StringUtil.splitMac(printerId) + ' capability : ' + JSON.stringify(capability));
    for (let index = 0; index < this.mPrinters.length; index++) {
      if (this.mPrinters[index].printerId === printerId) {
        this.mPrinters[index].capability = capability;
        this.mPrinters[index].options = options;
        this.mPrinters[index].description = description;
        AppStorageHelper.setValue<Array<PrinterInfo>>(this.mPrinters, AppStorageKeyName.PRINTER_QUEUE_NAME);
        let innerEvent = {
          eventId: AppCommonEvent.PRINTER_UPDATE_CAPABILITY_EVENT,
          priority: emitter.EventPriority.HIGH
        };
        emitter.emit(innerEvent);
      }
    }
    return true;
  }
}
