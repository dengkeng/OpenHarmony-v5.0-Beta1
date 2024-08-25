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

import type { PrinterCapability } from '@ohos/common';
import { MediaSizeUtil, Log, PrinterCapsOptions } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';

const TAG = 'LocalPrinterCapabilities';

export default class LocalPrinterCapabilities {
  /**
   * 构造PrinterCapability对象
   *
   * @param printerCapability
   */
  static buildPrinterCapability(printerCapability: PrinterCapability, caps: PrinterCapability): void {
    printerCapability.colorMode = caps.colorMode;
    printerCapability.duplexMode = caps.duplexMode;
    //set printPageSize
    let sizeList: string[] = caps.pageSize.map((size) => {
      return size.name;
    });
    const codes: number[] = MediaSizeUtil.getCodesBySizes(sizeList);
    printerCapability.pageSize = MediaSizeUtil.getMediaSizeArrayByCodes(LocalPrinterCapabilities.removeDuplicates(codes));
  }

  /**
   * 构造额外的参数, 传递给UI
   */
  static buildExtraCaps(caps: PrinterCapability, printerUri: string): string {
    let optionObject: PrinterCapsOptions = LocalPrinterCapabilities.parseOption(caps.options);
    if (optionObject === undefined) {
      return '';
    }
    let options: object = {
      supportedMediaTypes: LocalPrinterCapabilities.removeDuplicates(optionObject.supportedMediaTypes),
      supportedQuality: optionObject.supportedQualities,
      make: optionObject.make,
      printerUri: printerUri
    };
    return JSON.stringify(options);
  }

  private static parseOption(options: string): PrinterCapsOptions {
    if (CheckEmptyUtils.checkStrIsEmpty(options)) {
      return undefined;
    }
    let result: PrinterCapsOptions = undefined;
    try {
      result = JSON.parse(options);
    } catch (error) {
      Log.error(TAG, 'json parse error: ' + error);
    }
    return result;
  }

  /**
   * remove duplicates
   *
   * @param array
   */
  private static removeDuplicates(array: number[]): number[] {
    return [...new Set<number>(array)] as number[];
  }
}