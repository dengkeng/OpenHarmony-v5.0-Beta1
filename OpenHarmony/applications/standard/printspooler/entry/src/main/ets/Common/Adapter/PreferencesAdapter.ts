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
import data_preferences from '@ohos.data.preferences';
import type common from '@ohos.app.ability.common';
import { GlobalThisHelper, GlobalThisStorageKey} from '@ohos/common';
import { PreferencesKey } from '@ohos/common';

const TAG = '[PreferencesAdapter]:';
type ValueType = number | string | boolean | Array<number> | Array<string> | Array<boolean>;

/**
 * StorageHelper
 */
export default class PreferencesAdapter {
  private static preferencesAdapterKey = [
    PreferencesKey.KEY_PRIVACY_STATEMENT_PREFERENCES
  ];
  private preferences: data_preferences.Preferences = undefined;

  private validKey(key: string) : boolean {
    const element = PreferencesAdapter.preferencesAdapterKey.find((ele) => ele === key);
    if (element === undefined) {
      Log.error(TAG, 'Can not find PREFERENCES_KEY key: ' + JSON.stringify(key));
      return false;
    }
    return true;
  }

  public static getInstance() : PreferencesAdapter {
    if (GlobalThisHelper.getValue<PreferencesAdapter>(GlobalThisStorageKey.KEY_PREFERENCES_ADAPTER) !== undefined) {
      return GlobalThisHelper.getValue<PreferencesAdapter>(GlobalThisStorageKey.KEY_PREFERENCES_ADAPTER);
    }
    return GlobalThisHelper.createValue<PreferencesAdapter>(new PreferencesAdapter(), GlobalThisStorageKey.KEY_PREFERENCES_ADAPTER);
  }

  /**
   * 创建preferences对象
   */
  public async getOrCreatePreferencesSync(preferencesName: string): Promise<boolean> {
    Log.info(TAG, 'getOrCreatePreferencesSync start');
    const ABILITY_CONTEXT = GlobalThisHelper.getValue<common.UIAbilityContext>(GlobalThisStorageKey.KEY_MAIN_ABILITY_CONTEXT);
    if (preferencesName) {
      try {
        Log.info(TAG, 'getOrCreatePreferencesSync getValue');
        const preferences = await data_preferences.getPreferences(ABILITY_CONTEXT, preferencesName);
        Log.info(TAG, 'getOrCreatePreferencesSync getPreferences: ' + JSON.stringify(preferences));
        if (this.setPreferences(preferences)) {
          return true;
        } else {
          return false;
        }
      } catch (err) {
        Log.error('Failed to get preferences. code =' + err.code + ', message =' + err.message);
        return false;
      }
    } else {
      Log.error('getOrCreatePreferencesSync preferencesName is undefined');
      return false;
    }
  }

  /**
   * 设置preferences对象
   */
  public setPreferences(preferences: data_preferences.Preferences): boolean {
    this.preferences = preferences;
    return true;
  }

  /**
   * 通过key获取对应value
   */
  public async getValue(key: string): Promise<ValueType> {
    Log.info(TAG, 'getValue key: ' + JSON.stringify(key));
    if (this.preferences) {
      try {
        return <ValueType>(await this.preferences.get(key, false));
      } catch (err) {
        Log.error(TAG, 'Failed to get value of getValue. code =' + err.code + ', message =' + err.message);
        return undefined;
      }
    } else {
      Log.error(TAG, 'getValue preferences is undefined, please set preferences');
      return undefined;
    }
  }

  /**
   * 设置value
   */
  public async putValue(key: string, value: ValueType): Promise<boolean> {
    Log.info(TAG, 'putValue start');
    if (!this.validKey(key)) {
      return false;
    }
    if (this.preferences) {
      try {
        await this.preferences.put(key, value);
        Log.info(TAG, 'putValue success');
        return true;
      } catch (err) {
        Log.error(TAG, 'Failed to put value of putValue. code =' + err.code + ', message =' + err.message);
        return false;
      }
    } else {
      Log.error(TAG, 'putValue preferences is undefined, please set preferences');
      return false;
    }
  }

  /**
   * 删除preferences中的值
   */
  public async deleteValue(key: string): Promise<boolean> {
    if (!this.validKey(key)) {
      return false;
    }
    if (this.preferences) {
      try {
        await this.preferences.delete(key);
        Log.info(TAG, 'deleteValue success');
        return true;
      } catch (err) {
        Log.error(TAG, 'Failed to delete value of deleteValue. code =' + err.code + ', message =' + err.message);
        return false;
      }
    } else {
      Log.error(TAG, 'deleteValue preferences is undefined, please set preferences');
      return false;
    }
  }

  /**
   * 持久化存储
   */
  public async flush(): Promise<boolean> {
    Log.info(TAG, 'flush start');
    if (this.preferences) {
      try {
        await this.preferences.flush();
        Log.info(TAG, 'flush success');
        return true;
      } catch (err) {
        Log.error(TAG, 'Failed to flush value of flush. code =' + err.code + ', message =' + err.message);
        return false;
      }
    } else {
      Log.error(TAG, 'flush preferences is undefined, please set preferences');
      return false;
    }
  }
}