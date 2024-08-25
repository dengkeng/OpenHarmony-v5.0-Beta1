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

export enum LogLevel {
  DEBUG,
  INFO,
  WARN,
  ERR,
}

export class LogLevelUtil {
  static get(level: string): LogLevel {
    for (let v = LogLevel.DEBUG; v <= LogLevel.ERR; v++) {
      if (level === LogLevel[v]) {
        return v;
      }
    }
    return LogLevel.ERR;
  }
}

export class LogUtil {
  static logLevel: LogLevel = process.env.NODE_ENV === 'development' ? LogLevel.DEBUG : LogLevel.ERR;

  static e(tag: string, message?: any): void {
    if (LogUtil.logLevel <= LogLevel.ERR) {
      console.error(`${tag}: ${message}`);
    }
  }

  static w(tag: string, message?: any): void {
    if (LogUtil.logLevel <= LogLevel.WARN) {
      console.warn(`${tag}: ${message}`);
    }
  }

  static i(tag: string, message?: any): void {
    if (LogUtil.logLevel <= LogLevel.INFO) {
      console.info(`${tag}: ${message}`);
    }
  }

  static d(tag: string, message?: any): void {
    if (LogUtil.logLevel <= LogLevel.DEBUG) {
      console.debug(`${tag}: ${message}`);
    }
  }
}
