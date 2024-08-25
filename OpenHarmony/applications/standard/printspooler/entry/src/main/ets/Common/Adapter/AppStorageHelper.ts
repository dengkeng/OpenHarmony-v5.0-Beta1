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

import { Log } from '@ohos/common';
import { AppStorageKeyName } from '@ohos/common'

const TAG = '[AppStorageHelper]:'

/**
 * AppStorageHelper
 *
 * @since 2022-08-02
 */
export default class AppStorageHelper {
  private static registerKeys = [
    AppStorageKeyName.JOB_QUEUE_NAME,
    AppStorageKeyName.PRINTER_QUEUE_NAME,
    AppStorageKeyName.PRINT_EXTENSION_LIST_NAME,
    AppStorageKeyName.CONFIG_LANGUAGE,
    AppStorageKeyName.START_PRINT_TIME,
    AppStorageKeyName.INGRESS_PACKAGE,
    AppStorageKeyName.APP_VERSION
  ];

  /**
   * 将变量value保存到AppStorage对象中，key需要先注册到registerKeys，否则挂载失败
   * 注意本接口在AppStorage对象中不包含key时，会在AppStorage对象中新增该key值
   *
   * @returns 挂载成功返回value，失败返回undefined
   */
  public static createValue<T>(value: T, storageKey: string): T {
    Log.info(TAG, 'createValue' + JSON.stringify(storageKey) + ' : ' + JSON.stringify(value))
    const element = AppStorageHelper.registerKeys.find((ele) => ele === storageKey);
    if (element === undefined) {
      Log.error(TAG, 'Can not find register storageKey: ' + JSON.stringify(storageKey));
      return undefined;
    }
    if (!AppStorage.has(storageKey)) {
      AppStorage.setOrCreate<T>(storageKey, value)
      Log.error(TAG, 'AppStorageHelper Create key of ' + JSON.stringify(storageKey));
    } else {
      Log.info(TAG, 'setValue' + JSON.stringify(storageKey) + ' : ' + JSON.stringify(value))
      AppStorage.set<T>(storageKey, value)
    }
    return AppStorageHelper.getValue<T>(storageKey)
  }

  /**
   * 将变量value保存到AppStorage对象中，key需要先注册到registerKeys，否则挂载失败
   * 注意本接口在AppStorage对象中不包含key时，不会在AppStorage对象中新增该key值，需新增key值不要使用本接口
   *
   * @returns 挂载成功返回value，失败返回undefined
   */
  public static setValue<T>(value: T, storageKey: string): boolean {
    const element = AppStorageHelper.registerKeys.find((ele) => ele === storageKey);
    if (element === undefined) {
      Log.error(TAG, 'Can not find register storageKey: ' + JSON.stringify(storageKey));
      return false
    }
    if (AppStorage.has(storageKey)) {
      AppStorage.set<T>(storageKey, value)
      return true
    }
    return false
  }

  /**
   * 获取挂载到AppStorage上的全局变量
   *
   * @returns 成功返回value，若之前未挂载则返回undefined
   */
  public static getValue<T>(storageKey: string): T {
    if (!AppStorage.has(storageKey)) {
      Log.error(TAG, 'The storageKey is not exist, key =  ' + JSON.stringify(storageKey));
      return undefined
    }
    return (AppStorage.get<T>(storageKey) as T)
  }
}