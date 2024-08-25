/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

export class EnumUtils {
  /**
   * 将枚举值转换为一个数组
   *
   * @static
   * @param {(any[] | Record<string, any>)} valueEnum
   * @return { any[] }
   * @memberof EnumUtils
   */
  static enum2arr(valueEnum: any[] | Record<string, any>): any[] {
    let values: any[] = Array.isArray(valueEnum) ? valueEnum : Object.values(valueEnum);
    // 如果 enum 值为 number 类型，ts 生成的 js 对象会同时包含枚举的名称，针对该情形需提出枚举名称
    const hasNum: boolean = values.some((v) => typeof v === 'number');
    if (hasNum) {
      values = values.filter((v) => typeof v === 'number');
    }
    return values;
  }
}
