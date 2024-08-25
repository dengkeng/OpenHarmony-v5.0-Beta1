/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
import { BusinessError } from '@ohos.base';
import { GlobalContext } from '../common/GlobalContext';
import type UIAbilityContext from 'application/UIAbilityContext';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';

const TAG: string = 'PreventScreenshotsModel';

export default class PreventScreenshotsModel {
  private static sInstance: PreventScreenshotsModel;

  public static getInstance(): PreventScreenshotsModel {
    if (PreventScreenshotsModel.sInstance == null) {
      PreventScreenshotsModel.sInstance = new PreventScreenshotsModel();
    }
    return PreventScreenshotsModel.sInstance;
  }

  PreventScreenshots(flag: boolean) {
    let isPrivacyMode: boolean = flag;
    let session: UIExtensionContentSession = GlobalContext.getContext().getSession();
    if (session !== undefined) {
      session.setWindowPrivacyMode(isPrivacyMode);
      return;
    }

    let windowClass: window.Window | undefined = undefined;
    let context: UIAbilityContext = GlobalContext.getContext().getCmContext();
    if (context === undefined) {
      console.error(TAG, 'context is undefined!');
      return;
    }

    window.getLastWindow(context).then((window) => {
      windowClass = window;
      console.info(TAG,'Success in obtaining the top window data');
      windowClass.setWindowPrivacyMode(isPrivacyMode).catch((err: BusinessError) => {
        console.error(TAG, 'setWindowPrivacyMode failed: ' + JSON.stringify(err));
      })
    }).catch((err: BusinessError) => {
      console.info(TAG + 'getLastWindow failed: ' + JSON.stringify(err));
    })
  }
}