/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import ObjectUtil from "./ObjectUtil"

/**
 * 字符串工具类
 */
export class ArrayUtil {
  public static readonly INDEX_INVALID: number = -1;

  /**
   * 判断array是否为空
   *
   * @param collection collection
   * @return boolean
   */
  public static isEmpty<T>(array: T[]): boolean {
    if (ObjectUtil.isNullOrUndefined(array)) {
      return true;
    }
    return array.length === 0;
  }

  /**
   * 判断array是否包含item
   *
   * @param array
   * @param item
   */
  public static contains<T>(array: T[], item: T): boolean {
    if (this.isEmpty(array) || ObjectUtil.isNullOrUndefined(item)) {
      return false;
    }
    return array.indexOf(item) !== this.INDEX_INVALID;
  }

  /**
   * 查找 array 中最大值
   * @param array
   */
  public static max(array: number[]): number {
    return Math.max.apply(null, array);
  }

  /**
   * 查找 array 中最小值
   * @param array
   */
  public static min(array: number[]): number {
    return Math.min.apply(null, array);
  }
}
