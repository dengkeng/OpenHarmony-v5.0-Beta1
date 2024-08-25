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

import { AppStorageKeyName, Log, PrinterExtensionInfo } from '@ohos/common'
import AppStorageHelper from '../Common/Adapter/AppStorageHelper'

const TAG = '[PrintExtensionModel]:'

export class PrintExtensionModel {
  private mPrintExtensions: Array<PrinterExtensionInfo> = []

  get getPrintExtensions():Array<PrinterExtensionInfo> {
    return this.mPrintExtensions;
  }

  set setPrintExtensions(array: Array<PrinterExtensionInfo>) {
    this.mPrintExtensions = array;
  }

  /**
   * get all PrintExtension
   */
  public dealGetAllPrintExtension(data: Array<PrinterExtensionInfo>) {
    if (data === undefined) {
      Log.error(TAG, 'dealGetAllPrintExtension return for null data');
      return;
    }
    this.mPrintExtensions = [];
    for (let index = 0; index < data.length; index++) {
      let newInfo = new PrinterExtensionInfo(data[index].extensionId, data[index].vendorId,
      data[index].vendorName, data[index].vendorIcon, data[index].version);
      this.mPrintExtensions.push(newInfo);
    }
    AppStorageHelper.setValue<Array<PrinterExtensionInfo>>(this.getPrintExtensions, AppStorageKeyName.PRINT_EXTENSION_LIST_NAME);
  }
}