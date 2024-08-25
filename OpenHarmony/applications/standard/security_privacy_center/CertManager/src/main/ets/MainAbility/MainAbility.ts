/**
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

import Ability from '@ohos.app.ability.UIAbility';
import type Want from '@ohos.app.ability.Want';
import type Window from '@ohos.window';
import { GlobalContext, PwdStore } from '../common/GlobalContext';

export default class MainAbility extends Ability {
  onCreate(want: Want, launchParam): void {
    console.log('[CertManager] MainAbility onCreate');

    if (want === null || want === undefined) {
      console.error('[CertManager] invalid want param');
      return;
    }
    let pwdStore = new PwdStore();
    GlobalContext.getContext().setCmContext(this.context);
    GlobalContext.getContext().setPwdStore(pwdStore);
    GlobalContext.getContext().setAbilityWant(want);
    GlobalContext.getContext().setFlag(false);
  }

  onDestroy(): void {
    console.log('[CertManager] MainAbility onDestroy');
  }

  onWindowStageCreate(windowStage: Window.WindowStage): void {
    // Main window is created, set main page for this ability
    console.log('[CertManager] MainAbility onWindowStageCreate');
    windowStage.loadContent('pages/certManagerFa', (err, data) => {
      if (err.code) {
        console.error('onWindowStageCreate failed, cause:' + JSON.stringify(err));
        return;
      }
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    console.log('[CertManager] MainAbility onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    console.log('[CertManager] MainAbility onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    console.log('[CertManager] MainAbility onBackground');
  }

  onNewWant(want: Want): void {
    console.log('[CertManager] MainAbility onNewWant');

    if (want === null || want === undefined) {
      console.error('[CertManager] invalid want param');
      return;
    }
    GlobalContext.getContext().setAbilityWant(want);
  }
};
