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

import {Log} from '../utils/Log';
import {GlobalThisStorageKey} from './GlobalThisStorageKey';

const TAG = 'GlobalThisHelper';

export class GlobalThisHelper {
  private static registerKeys = [
    GlobalThisStorageKey.KEY_PRINT_ADAPTER,
    GlobalThisStorageKey.KEY_MEDIA_SIZE_UTIL,
    GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT,
    GlobalThisStorageKey.KEY_MAIN_ABILITY_WINDOW_STAGE,
    GlobalThisStorageKey.KEY_JOB_MANAGER_ABILITY_CONTEXT,
    GlobalThisStorageKey.KEY_NOTIFICATION_PRINTER_NAME,
    GlobalThisStorageKey.KEY_SERVICE_FIRST_START,
    GlobalThisStorageKey.KEY_PRINTER_SELECT_DIALOG_OPEN,
    GlobalThisStorageKey.KEY_CURRENT_PIXELMAP,
    GlobalThisStorageKey.KEY_PREFERENCES_ADAPTER,
    GlobalThisStorageKey.KEY_SECURITY_GUARD,
    GlobalThisStorageKey.KEY_IMAGE_ERROR_COUNT,
    GlobalThisStorageKey.KEY_IMAGE_ERROR_NAME,
    GlobalThisStorageKey.KEY_ABILITY_CONTEXT,
    GlobalThisStorageKey.KEY_FILES_DIR
  ];

  /**
   * 将变量value挂载到globalThis实例上，key需要先注册到registerKeys，否则挂载失败
   * 注意本接口可保存原对象
   *
   * @param value 变量值
   * @param storageKey 保存的key值
   * @param forceChange
   * @returns 挂载成功返回value，失败返回undefined
   */
  public static createValue<T>(value: T, storageKey: string, forceChange: boolean = false): T {
    const element = GlobalThisHelper.registerKeys.find((ele) => ele === storageKey);
    if (element === undefined) {
      Log.error(TAG, 'Can not find register storageKey: ' + JSON.stringify(storageKey));
      return undefined;
    }
    if ((globalThis[storageKey] === undefined) || forceChange) {
      globalThis[storageKey] = value;
      Log.error(TAG, 'GlobalThisHelper Create key of ' + JSON.stringify(storageKey));
    }
    return <T>(globalThis[storageKey]);
  }

  /**
   * 将变量value挂载到AppStorage实例上，key需要先注册到registerKeys，否则挂载失败
   * 注意本接口重新new了一个新对象，如需保存原对象不要使用本接口
   *
   * @returns 挂载成功返回value，失败返回undefined
   */
  public static createObject<T>(objectClass: { new(...input): T }, storageKey: string, ...input): T {
    const element = GlobalThisHelper.registerKeys.find((ele) => ele === storageKey);
    if (element === undefined) {
      Log.error(TAG, 'Can not find register storageKey: ' + JSON.stringify(storageKey));
      return undefined;
    }
    if (globalThis[storageKey] === undefined) {
      globalThis[storageKey] = new objectClass(...input);
      Log.error(TAG, 'GlobalThisHelper Create key of ' + JSON.stringify(storageKey));
    }

    // 通过globalThis存取值
    return (globalThis[storageKey] as T);
  }

  /**
   * 获取挂载到globalThis上的全局变量
   *
   * @returns 成功返回value，若之前未挂载则返回undefined
   */
  public static getValue<T>(storageKey: string): T {
    if (globalThis[storageKey] === undefined) {
      Log.error(TAG, 'The storageKey is not exist, key = ' + storageKey);
      return undefined;
    }
    return (globalThis[storageKey] as T);
  }
}