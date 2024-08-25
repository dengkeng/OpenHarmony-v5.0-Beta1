/**
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

import LogUtils from '../common/utils/LogUtils';
import UserAuthExtensionAbility from '@ohos.app.ability.UserAuthExtensionAbility';
import WindowPrivacyUtils from '../common/utils/WindowPrivacyUtils';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import { WantParams } from '../common/vm/Constants';

const TAG = 'UserAuthAbility';
// The current interface only support string type
const TRANSPARENT_COLOR = '#00000000';
const MASK_THIN_COLOR = '#33182431';

export default class UserAuthAbility extends UserAuthExtensionAbility {
  onCreate() {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onCreate');
    AppStorage.setOrCreate('context', this.context);
  }

  onForeground(): void {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onForeground');
  }

  onBackground(): void {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onBackground');
    (AppStorage.get("session") as UIExtensionContentSession)?.terminateSelf();
  }

  onDestroy(): void | Promise<void> {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onDestroy');
  }

  onSessionCreate(want, session): void {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onSessionCreate');
    AppStorage.setOrCreate("wantParams", want?.parameters?.useriamCmdData);
    AppStorage.setOrCreate("session", session);
    (session as UIExtensionContentSession)?.loadContent('pages/Index');
    try {
      if ((AppStorage.get("wantParams") as WantParams)?.windowModeType === 'DIALOG_BOX') {
        (session as UIExtensionContentSession)?.setWindowBackgroundColor(MASK_THIN_COLOR);
      } else {
        (session as UIExtensionContentSession)?.setWindowBackgroundColor(TRANSPARENT_COLOR);
      }
    } catch (error) {
      LogUtils.error(TAG, 'UserAuthExtensionAbility onSessionCreate error: ' + error?.code);
      (session as UIExtensionContentSession)?.terminateSelf();
    }
    WindowPrivacyUtils.setWindowPrivacyMode(session, true);
  }

  onSessionDestroy(session): void {
    LogUtils.info(TAG, 'UserAuthExtensionAbility onSessionDestroy');
    WindowPrivacyUtils.setWindowPrivacyMode(session, false);
  }
}
