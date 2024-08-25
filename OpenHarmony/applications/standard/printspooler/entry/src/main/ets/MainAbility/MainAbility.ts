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

import UIAbility from '@ohos.app.ability.UIAbility';
import { configMgr, GlobalThisHelper, GlobalThisStorageKey, MediaSizeHelper } from '@ohos/common';
import AppStorageHelper from '../Common/Adapter/AppStorageHelper';
import { Log } from '@ohos/common';
import { Constants, AppStorageKeyName, PreferencesKey } from '@ohos/common';
import type common from '@ohos.app.ability.common';
import PreferencesAdapter from '../Common/Adapter/PreferencesAdapter';
import bundleManager from '@ohos.bundle.bundleManager';
import PrintAdapter from '../Common/Adapter/PrintAdapter';
import { Configuration } from '@ohos.app.ability.Configuration';
import image from '@ohos.multimedia.image';
import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import window from '@ohos.window';

const TAG = '[MainAbility]:';

export default class MainAbility extends UIAbility {
  private readonly PRIVACY_STATEMENT_STORE: string = 'privacyStatementStore';
  private storage: LocalStorage = new LocalStorage();
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    Log.info(TAG, 'onCreate: ' + JSON.stringify(want) + ' launchParam : ' + JSON.stringify(launchParam));
    let jobId = want.parameters[Constants.WANT_JOB_ID_KEY] as string;
    let fileList = want.parameters[Constants.WANT_FILE_LIST_KEY] as Array<string>;
    let pkgName = want.parameters[Constants.WANT_PKG_NAME_KEY] as string;
    Log.info(TAG, 'fileList = ' + JSON.stringify(fileList));
    GlobalThisHelper.createValue<common.UIAbilityContext>(this.context, GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT, true);
    MediaSizeHelper.init(this.context);
    this.storage.setOrCreate<string>(Constants.WANT_JOB_ID_KEY, jobId);
    this.storage.setOrCreate<Array<string>>(Constants.WANT_FILE_LIST_KEY, fileList);
    this.context.resourceManager.getConfiguration((error, value) => {
      AppStorageHelper.createValue<string>(<string> value.locale, AppStorageKeyName.CONFIG_LANGUAGE);
    });
    AppStorageHelper.createValue<string>(pkgName, AppStorageKeyName.INGRESS_PACKAGE);

    bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_DEFAULT)
      .then((bundleInfo) => {
        AppStorageHelper.createValue<string>(<string> bundleInfo.versionName, AppStorageKeyName.APP_VERSION);
      });
    configMgr.onStart(this.context);
  }

  onDestroy() {
    Log.info(TAG, 'onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    Log.info(TAG, 'onWindowStageCreate');

    this.isFirstUsePrint().then((flag) => {
      windowStage.getMainWindow().then((window) => {
        window.resetSize(vp2px(Constants.MAIN_WINDOW_WIDTH), vp2px(Constants.MAIN_WINDOW_HEIGHT));
      }).catch((err) => {

      });

      Log.info(TAG, 'onWindowStageCreate flag: ' + JSON.stringify(flag));
      if (flag) {
        windowStage.loadContent('pages/PrivacyStatementPage', this.storage);
      } else {
        windowStage.loadContent('pages/PrintPage', this.storage);
      }
    });

    GlobalThisHelper.createValue(windowStage, GlobalThisStorageKey.KEY_MAIN_ABILITY_WINDOW_STAGE, true);
  }

  onWindowStageDestroy() {
    // Main window is destroyed, release UI related resources
    Log.info(TAG, 'onWindowStageDestroy');
    let adapter = GlobalThisHelper.getValue<PrintAdapter>(GlobalThisStorageKey.KEY_PRINT_ADAPTER);
    adapter.getPrinterDiscCtl().stopDiscovery('');
    let pixelMap = GlobalThisHelper.getValue<image.PixelMap>(GlobalThisStorageKey.KEY_CURRENT_PIXELMAP);
    if (pixelMap !== undefined) {
      pixelMap.release().then(() => {
        Log.info(TAG, 'onWindowStageDestroy currentPixelMap release success');
      });
    }
    this.storage.clear();
    configMgr.onStop();
  }

  onConfigurationUpdated(config: Configuration): void {
    Log.info(TAG, 'onConfigurationUpdated, language:' + config.language);
    AppStorageHelper.createValue<string>(<string> config.language, AppStorageKeyName.CONFIG_LANGUAGE);
  }

  onForeground() {
    // Ability has brought to foreground
    Log.info(TAG, 'onForeground');
  }

  onBackground() {
    // Ability has back to background
    Log.info(TAG, 'onBackground');
  }

  async isFirstUsePrint(): Promise<boolean> {
    Log.info(TAG, 'isFirstUsePrint start');
    const success = await PreferencesAdapter.getInstance().getOrCreatePreferencesSync(this.PRIVACY_STATEMENT_STORE);
    Log.info(TAG, 'isFirstUsePrint getOrCreatePreferencesSync success: ' + success);
    if (success) {
      const agreePrivacyStatement = await PreferencesAdapter.getInstance().getValue(PreferencesKey.KEY_PRIVACY_STATEMENT_PREFERENCES);
      Log.info(TAG, 'isFirstUsePrint getValue agreePrivacyStatement: ' + agreePrivacyStatement);
      if (agreePrivacyStatement) {
        return false;
      } else {
        return true;
      }
    } else {
      Log.info(TAG, 'isFirstUsePrint success is not');
      return true;
    }
  }
};
