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

import { Constants } from '../model/Constants';
import { GlobalThisHelper } from '../model/GlobalThisHelper';
import { GlobalThisStorageKey} from '../model/GlobalThisStorageKey';
import type common from '@ohos.app.ability.common';
import CheckEmptyUtils from './CheckEmptyUtils';
import { Log } from './Log';

export class StringUtil {
  private static readonly DEFAULT_LEN_OF_COMMON_STR: number = 6;
  private static readonly HALF_LEN_OF_COMMON_STR: number = 3;
  private static readonly LINK_OF_COMMON_STR: string = '****';
  /**
   * Get String from resources.
   *
   * @param {string} name - name of string.json
   * @return {string} - string from res
   */
  public static getString(name: string, ...args: Array<string | number>): string {
    let abilityContext = GlobalThisHelper.getValue<common.UIAbilityContext>(GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT);
    Log.info('getString abilityContext: ' +abilityContext)
    if (abilityContext !== undefined && !CheckEmptyUtils.checkStrIsEmpty(name)) {
      return <string> abilityContext?.resourceManager?.getStringByNameSync(name, ...args) ?? '';
    }
    return '';
  }
  /**
   * Get String from resources.
   *
   * @param name string code
   * @param context context
   * @param args variable args
   * @returns string value
   */
  public static getStringByName(name: string, context: common.Context,  ...args: Array<string | number>): string {
    if (CheckEmptyUtils.isEmpty(context) || CheckEmptyUtils.checkStrIsEmpty(name)) {
      return '';
    }
    return context!.resourceManager?.getStringByNameSync(name, ...args) ?? '';
  }
  /**
   * get anonymization string
   *
   * @param {string} originStr - string
   * @return {string} - anonymization string
   */
  public static encodeCommonString(originStr: string):string {
    if (!originStr) {
      return originStr;
    }
    if (originStr.length <= this.DEFAULT_LEN_OF_COMMON_STR) {
      return originStr;
    }
    return originStr.substring(0, this.HALF_LEN_OF_COMMON_STR) +
    this.LINK_OF_COMMON_STR +
    originStr.substring(originStr.length - this.HALF_LEN_OF_COMMON_STR);
  }

  /**
   * get split mac
   *
   * @param {string} str - string
   * @return {string} - anonymization mac string
   */
  public static splitMac(str: string):string {
    if (!str) {
      return str;
    }
    let strSplit = str.split('://');
    if (strSplit.length > 1) {
      return strSplit[0] + '://' + this.encodeCommonString(strSplit[1]);
    } else if (str.length > this.DEFAULT_LEN_OF_COMMON_STR) {
      return this.encodeCommonString(str);
    } else {
      return str;
    }
  }

  public static getNetTypeByPrintId(printId: string):string {
    if (!printId) {
      return printId;
    }
    let printIdSplit = printId.split(':');
    let minLength = 2;
    if (printIdSplit.length > minLength) {
      return printIdSplit[1];
    } else {
      return '';
    }
  }

}