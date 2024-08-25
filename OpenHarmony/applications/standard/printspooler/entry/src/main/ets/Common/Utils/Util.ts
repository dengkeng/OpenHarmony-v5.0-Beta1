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

import { Constants } from '@ohos/common';
import FileUtil from './FileUtil';
import type common from '@ohos.app.ability.common';
import CheckEmptyUtils, { Log, PrinterInfo } from '@ohos/common';

const usedPrinterFileName: string = 'lastUsedPrinter';
const TAG = 'Util';
/**
 * Util class
 */
export default class Util {

  /**
   * 是否为mdns打印
   *
   * @param printerId printerId
   * @return result
   */
  public static isMdnsPrinter(printerId: string): boolean {
    if (CheckEmptyUtils.checkStrIsEmpty(printerId)) {
      return false;
    }
    return printerId.includes(Constants.MDNS_PRINTER);
  }

  /**
   * 查询当前连接的Printer信息
   *
   * @param context 应用上下文
   * @return printerInfo Printer信息
   */
  public static queryLastUsedPrinter(context: common.Context): string {
    if (CheckEmptyUtils.isEmpty(context)) {
      Log.warn(TAG, 'queryLastUsedPrinter failed:invalid param.');
      return null;
    }
    let printerInfo = FileUtil.readStringFromFile(usedPrinterFileName, context);
    if (!CheckEmptyUtils.checkStrIsEmpty(printerInfo)) {
      return printerInfo;
    }
    return null;
  }

  /**
   * 查询当前连接的PrinterId
   *
   * @param context 应用上下文
   * @return PrinterId
   */
  public static getLastUsedPrinterId(context: common.Context): string {
    let printerInfo = this.queryLastUsedPrinter(context);
    if (CheckEmptyUtils.checkStrIsEmpty(printerInfo)) {
      return null;
    }
    try {
      let printer = JSON.parse(printerInfo);
      return printer?.printerId?? null;
    } catch (err) {
      Log.error(TAG, 'getLastUsedPrinterId failed: parse error.');
      return null;
    }
  }

  /**
   * 查询当前连接的PrinterInfo
   *
   * @param context 应用上下文
   * @return PrinterId
   */
  public static getLastUsedPrinterInfo(context: common.Context): PrinterInfo {
    let printerInfo = this.queryLastUsedPrinter(context);
    if (CheckEmptyUtils.checkStrIsEmpty(printerInfo)) {
      return null;
    }
    try {
      let printer:PrinterInfo = JSON.parse(printerInfo);
      return printer;
    } catch (err) {
      Log.error(TAG, 'getLastUsedPrinterInfo failed: parse error.');
      return null;
    }
  }
}