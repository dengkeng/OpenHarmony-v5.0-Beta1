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

const TAG: string = 'PrintUtil';
/**
 * 打印通用工具类
 */
export class PrintUtil {
  /**
   * 获取默认长度数据，填充为1,2,...,num
   * @param num 数组长度
   * @returns 数值型数组
   */
  public static getDefaultArray(num: number): Array<number> {
    return Array.from({ length: num }, (_, i) => i + 1);
  }

  /**
   * check value in enum
   *
   * @param value value
   * @param enumClass enum name
   * @returns result result
   */
  public static isValueInEnum<T>(value: number, enumClass: T): boolean{
    return Object.values(enumClass).includes(value as T);
  }
}