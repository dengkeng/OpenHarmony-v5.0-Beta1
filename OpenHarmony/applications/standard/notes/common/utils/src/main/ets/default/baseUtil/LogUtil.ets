/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
import hilog from '@ohos.hilog'

export class LogUtil {
  private static readonly IS_DEBUG_ON: boolean = false;
  private static readonly CONTACTS_DOMAIN: number = 0x0927;
  private static readonly SLASH: string = "/";
  private static readonly COLON: string = ": ";
  constructor() {
  }

  private static prefix(tag: string) {
    return this.SLASH + tag + this.COLON;
  }

  static debug(tag: string, msg: string, ...args: any[]) {
    if (this.IS_DEBUG_ON) {
      hilog.info(this.CONTACTS_DOMAIN, this.prefix(tag), msg, args);
    } else {
      hilog.debug(this.CONTACTS_DOMAIN, this.prefix(tag), msg, args);
    }
  }

  static info(tag: string, msg: string, ...args: any[]) {
    hilog.info(this.CONTACTS_DOMAIN, this.prefix(tag), msg, args);
  }

  static warn(tag: string, msg: string, ...args: any[]) {
    hilog.warn(this.CONTACTS_DOMAIN, this.prefix(tag), msg, args);
  }

  static error(tag: string, msg: string, ...args: any[]) {
    hilog.error(this.CONTACTS_DOMAIN, this.prefix(tag), msg, args);
  }
}