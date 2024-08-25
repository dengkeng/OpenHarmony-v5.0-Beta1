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
import hilog from '@ohos.hilog';

/**
 * Log printing tool class
 */
class Logger {
  private domain: number;

  private preTag: string;

  private format: string = '%{public}s';

  constructor() {
    this.preTag = 'PrivacyCenter_';
    this.domain = 0x5616;
  }

  debug(tag: string, logInfo: string) {
    hilog.debug(this.domain, this.preTag + tag, this.format, logInfo);
  }

  info(tag: string, logInfo: string) {
    hilog.info(this.domain, this.preTag + tag, this.format, logInfo);
  }

  warn(tag: string, logInfo: string) {
    hilog.warn(this.domain, this.preTag + tag, this.format, logInfo);
  }

  error(tag: string, logInfo: string) {
    hilog.error(this.domain, this.preTag + tag, this.format, logInfo);
  }
}

export default new Logger()