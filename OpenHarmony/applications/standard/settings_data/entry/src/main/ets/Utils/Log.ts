/**
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

import hiLog from '@ohos.hilog';

const DOMAIN: number = 0x0500;
const TAG = 'SettingsData';

/**
 * Basic log class
 */
export class Log {
  /**
   * Outputs info-level logs.
   *
   * @param tag Identifies the log tag.
   * @param format Indicates the log format string.
   * @param args Indicates the log parameters.
   * @since 7
   */
  static info(format: string, ...args: string[]): void {
    if (Log.isLoggable(hiLog.LogLevel.INFO)) {
      hiLog.info(DOMAIN, TAG, format, args);
    }
  }

  /**
   * Outputs debug-level logs.
   *
   * @param tag Identifies the log tag.
   * @param format Indicates the log format string.
   * @param args Indicates the log parameters.
   * @since 7
   */
  static debug(format: string, ...args: string[]): void {
    if (Log.isLoggable(hiLog.LogLevel.DEBUG)) {
      hiLog.debug(DOMAIN, TAG, format, args);
    }
  }

  /**
   * Outputs warning-level logs.
   *
   * @param tag Identifies the log tag.
   * @param format Indicates the log format string.
   * @param args Indicates the log parameters.
   * @since 7
   */
  static warn(format: string, ...args: string[]): void {
    if (Log.isLoggable(hiLog.LogLevel.WARN)) {
      hiLog.warn(DOMAIN, TAG, format, args);
    }
  }

  /**
   * Outputs error-level logs.
   *
   * @param tag Identifies the log tag.
   * @param format Indicates the log format string.
   * @param args Indicates the log parameters.
   * @since 7
   */
  static error(format: string, ...args: string[]): void {
    if (Log.isLoggable(hiLog.LogLevel.ERROR)) {
      hiLog.error(DOMAIN, TAG, format, args);
    }
  }

  /**
   * Outputs fatal-level logs.
   *
   * @param tag Identifies the log tag.
   * @param format Indicates the log format string.
   * @param args Indicates the log parameters.
   * @since 7
   */
  static fatal(format: string, ...args: string[]): void {
    if (Log.isLoggable(hiLog.LogLevel.FATAL)) {
      hiLog.fatal(DOMAIN, TAG, format, args);
    }
  }

  /**
   * Checks whether logs of the specified tag, and level can be printed.
   *
   * @param tag Identifies the log tag.
   * @param level log level
   * @since 7
   */
  private static isLoggable(level: hiLog.LogLevel): boolean {
    return hiLog.isLoggable(DOMAIN, TAG, level);
  }
}
