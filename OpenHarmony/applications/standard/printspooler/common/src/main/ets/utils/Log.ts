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

import hilog from '@ohos.hilog';

const DOMAIN = 0xFFFF;
const TAG = 'PrintSpooler';

/**
 * Log Util
 */
export class Log {

  static warn(...args: string[]): void {
    hilog.warn(DOMAIN, TAG, '%{public}s', `${args.join(' ')}`);
  }

  static info(...args: string[]): void {
    hilog.info(DOMAIN, TAG, '%{public}s', `${args.join(' ')}`);
  }

  static debug(...args: string[]): void {
    hilog.debug(DOMAIN, TAG, '%{private}s', `${args.join(' ')}`);
  }

  static error(...args: string[]): void {
    hilog.error(DOMAIN, TAG, '%{public}s', `${args.join(' ')}`);
  }
}