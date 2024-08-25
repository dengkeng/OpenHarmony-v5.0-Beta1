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

import CheckEmptyUtils from '@ohos/common';

export default class CommonUtils {

  private static readonly two: number = 2;
  private static readonly four: number = 4;
  private static readonly asterisk: string = '***';

  /**
   * convert String to return a SecureString half_substring
   */
  public static getSecurityMac(str: string): string {
    if (str === undefined || str === null || str.length === 0) {
      return '';
    }
    if (str.length < CommonUtils.two) {
      return CommonUtils.asterisk;
    }
    return str.substring(0, CommonUtils.two) + CommonUtils.asterisk + str.substring(str.length - CommonUtils.two, str.length);
  }

  /**
  * convert String to return a SecureString
  */
  public static getSecurityIp(str: string): string {
    if (str === undefined || str === null || str.length === 0) {
      return '';
    }

    return str.substring(0, str.length / CommonUtils.two).toString() + CommonUtils.asterisk;
  }

  /**
  * convert String to return a SecureString
  */
  public static getSecurityPath(str: string): string {
    if (str === undefined || str === null || str.length === 0) {
      return '';
    }
    let split: string[] = str.split('/');
    if (CheckEmptyUtils.isEmptyArr(split)) {
      return '';
    }
    return split[split.length - 1];
  }

  /**
  * convert String to return a SecureString
  */
  public static getSecurityPrinterName(str: string): string {
    if (str === undefined || str === null || str.length === 0) {
      return '';
    }
    if (str.length < CommonUtils.four) {
      return CommonUtils.asterisk;
    }
    return str.substring(0, CommonUtils.four) + CommonUtils.asterisk + str.substring(str.length - CommonUtils.four, str.length);
  }
}