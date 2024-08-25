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

import { PrinterDiscController } from '../../Controller/PrinterDiscController';
import { PrintExtensionController } from '../../Controller/PrintExtensionController';
import { Log } from '@ohos/common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';

const TAG: string = '[PrintAdapter]:';

export default class PrintAdapter {
  private mPrinterDiscController?: PrinterDiscController;
  private mPrintExtensionController?: PrintExtensionController;

  constructor() {
    this.init();
  }

  public static getInstance(): PrintAdapter {
    if (GlobalThisHelper.getValue<PrintAdapter>(GlobalThisStorageKey.KEY_PRINT_ADAPTER) !== undefined) {
      return GlobalThisHelper.getValue<PrintAdapter>(GlobalThisStorageKey.KEY_PRINT_ADAPTER);
    }
    return GlobalThisHelper.createValue<PrintAdapter>(new PrintAdapter(), GlobalThisStorageKey.KEY_PRINT_ADAPTER);
  }

  init(): void {
    Log.info(TAG, 'PrintAdapter init');
    this.mPrinterDiscController = new PrinterDiscController();
    this.mPrinterDiscController.init();
    this.mPrintExtensionController = new PrintExtensionController();
    this.mPrintExtensionController.init();
  }

  public destroy(): void {
    Log.info(TAG, 'onDestroy');
    if (this.mPrinterDiscController !== undefined) {
      this.mPrinterDiscController.destroy();
    }
  }

  /**
   * get device discovery controller
   *
   * @return DeviceDiscController
   */
  public getPrinterDiscCtl(): PrinterDiscController | undefined {
    return this.mPrinterDiscController;
  }

  /**
   * get PrintExtension controller
   *
   * @return PrintExtensionController
   */
  public getPrintExtensionCtl(): PrintExtensionController | undefined {
    return this.mPrintExtensionController;
  }
}