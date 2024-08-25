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

import { PrinterFoundType } from '../model/PrintBean';

/**
 * printer utils
 */
export class PrinterUtils {
  private static usb: string = 'USB';
  private static p2p: string = 'P2P';

  /**
   * convert printer type
   *
   * @param printerId printerId
   */
  public static getPrinterFoundType(printerId: string): PrinterFoundType {
    if (printerId == null || printerId.length < 0) {
      return PrinterFoundType.FROM_P2P;
    }

    let upPrinterId = printerId.toUpperCase();
    if (upPrinterId.includes(this.usb)) {
      return PrinterFoundType.FROM_USB;
    } else if (upPrinterId.includes(this.p2p)) {
      return PrinterFoundType.FROM_P2P;
    } else {
      return PrinterFoundType.FROM_LOCAL_NET;
    }
  }
}