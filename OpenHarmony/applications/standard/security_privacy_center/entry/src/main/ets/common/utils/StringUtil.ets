/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

/**
 * String Tool Class
 */
export class StringUtil {
  /**
   * Determine whether a character is an empty string
   * @Param stringValue character string
   */
  public static isEmpty(stringValue: string | null | undefined): boolean {
    return stringValue === undefined || stringValue === null || stringValue.length === 0;
  }

  /**
   * Determine whether character conversion is a non empty string
   * @params stringValue character string
   */
  public static isNotEmpty(stringValue: string | null | undefined): boolean {
    return stringValue !== undefined && stringValue !== null && stringValue.length !== 0;
  }
}