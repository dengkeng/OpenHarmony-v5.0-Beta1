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

import UIAbility from '@ohos.app.ability.UIAbility'
import window from '@ohos.window'
import AbilityCommonUtil from '../base/utils/AbilityCommonUtil'
import Logger from '../base/log/Logger'
import { FileUtil } from '../base/utils/FileUtil'

const TAG = 'MainAbility'

export default class MainAbility extends UIAbility {
  onCreate(want, launchParam) {
    Logger.i(TAG, 'onCreate')
    globalThis.action = want.action;
    globalThis.abilityContext = this.context;
    globalThis.startMode = want.parameters.startMode;
    globalThis.saveFile = want.parameters.saveFile ? [want.parameters.saveFile] : [];
    Logger.i(TAG, 'globalThis.startMode: ' + globalThis.startMode + ', ' + (globalThis.startMode == 'choose'));
    const parameters = want.parameters
    if (globalThis.action == 'ohos.want.action.OPEN_FILE' || globalThis.startMode == 'choose') {
      // 文件选择器
      // 选择文件的类型列表
      globalThis.keyPickTypeList = AbilityCommonUtil.getKeyPickTypeList(parameters.key_pick_type, parameters.key_pick_type_list);
      // 选择文件个数
      globalThis.filePickNum = AbilityCommonUtil.getPickFileNum(parameters.key_pick_num);
      // 文件选择范围：0-本地 1-云盘 不传则默认展示全部路径(未实现)
      globalThis.filePickLocation = parameters.key_pick_location;
      // 选择指定目录下的文件
      globalThis.keyFileDefaultPickPath = FileUtil.getUriPath(parameters.key_pick_dir_path);
      // 选择文件模式，默认只支持文件选择
      globalThis.keySelectMode = AbilityCommonUtil.getKeySelectMode(parameters.key_select_mode);
      // 指定文件后缀,string[]
      if (parameters.key_file_suffix_filter instanceof Array) {
        globalThis.keyFileSuffixFilter = AbilityCommonUtil.getKeyFileSuffixFilter(parameters.key_file_suffix_filter);
      }
      globalThis.pickerCallerUid = parameters[AbilityCommonUtil.CALLER_UID];
      globalThis.pickerCallerBundleName = parameters[AbilityCommonUtil.CALLER_BUNDLE_NAME]
      globalThis.filePickerViewFlag = true;
    } else {
      // 路径选择器
      globalThis.pathAbilityContext = this.context
      // 保存文件时的文件名列表
      globalThis.keyPickFileName = parameters.key_pick_file_name || globalThis.saveFile || []
      // 保存位置，[本地、云盘](未实现)
      globalThis.keyPickFileLocation = parameters.key_pick_file_location
      // 保存云盘文件到本地时云盘文件的uri列表(未实现)
      globalThis.keyPickFilePaths = parameters.key_pick_file_paths
      globalThis.keyPathDefaultPickDir = FileUtil.getUriPath(parameters.key_pick_dir_path);
      // 指定文件后缀,只获取第一个有效的后缀
      if (parameters.key_file_suffix_choices instanceof Array) {
        globalThis.keyFileSuffixChoices = AbilityCommonUtil.getKeyFileSuffixChoices(parameters.key_file_suffix_choices);
      }
      globalThis.pathCallerUid = parameters[AbilityCommonUtil.CALLER_UID]
      globalThis.pathCallerBundleName = parameters[AbilityCommonUtil.CALLER_BUNDLE_NAME]
    }
    Logger.i(TAG, ' onCreate, parameters: ' + JSON.stringify(want.parameters))
  }

  onDestroy() {
    Logger.i(TAG, 'onDestroy')
    AbilityCommonUtil.releaseMediaLibrary()
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    // Main window is created, set main page for this ability
    Logger.i(TAG, 'onWindowStageCreate')
    AbilityCommonUtil.init().then(() => {
      globalThis.windowClass = windowStage.getMainWindowSync();
      if (globalThis.action == 'ohos.want.action.OPEN_FILE' || globalThis.startMode == 'choose') {
        // 文件选择器
        windowStage.loadContent('pages/browser/storage/MyPhone', (err, data) => {
          if (err.code) {
            Logger.e(TAG, 'Failed to load the content: ' + JSON.stringify(err));
            return
          }
          Logger.i(TAG, 'data: ' + JSON.stringify(data));
        })
      } else {
        // 路径选择器
        windowStage.loadContent('pages/PathPicker', (err, data) => {
          if (err.code) {
            Logger.e(TAG, 'Failed to load the content. Cause: ' + JSON.stringify(err))
            return;
          }
          Logger.i(TAG, 'Succeeded in loading the content. Data: ' + JSON.stringify(data))
        })
      }
    })

  }

  onWindowStageDestroy() {
    // Main window is destroyed, release UI related resources
    Logger.i(TAG, 'onWindowStageDestroy')
  }

  onForeground() {
    // Ability has brought to foreground
    Logger.i(TAG, 'onForeground')
  }

  onBackground() {
    // Ability has back to background
    Logger.i(TAG, 'onBackground')
  }
}
