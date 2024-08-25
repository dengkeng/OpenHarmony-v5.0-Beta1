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

import window from '@ohos.window';
import Logger from '../log/Logger';
import ObjectUtil from './ObjectUtil';

const TAG = 'UiUtil';

export class UiUtil {

  public static setWindowBackground(color: string): void {
    let windowClass: window.Window = globalThis.windowClass;
    if (!ObjectUtil.isNullOrUndefined(windowClass)) {
      try {
        windowClass.setWindowBackgroundColor(color);
      } catch (err) {
        Logger.e(TAG, 'setWindowBackgroundColor error: ' + JSON.stringify(err));
      }
    }
  }
}