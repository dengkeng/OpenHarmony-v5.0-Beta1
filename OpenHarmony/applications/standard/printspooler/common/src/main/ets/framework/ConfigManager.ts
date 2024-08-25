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
import { Configuration } from '@ohos.app.ability.Configuration';
import type common from '@ohos.app.ability.common'
import { ConfigChangeListener } from './Interfaces';
import EnvironmentCallback from '@ohos.app.ability.EnvironmentCallback';
import { Log } from '../utils/Log';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import { SingletonHelper } from '../utils/SingletonHelper';

const TAG: string = 'ConfigManager';
/**
 * 环境配置信息变化管理类
 */
class ConfigManager {
  /**
   * 属性变化事件
   */
  private mConfigInfo?: Configuration;
  /**
   * 应用上下文
   */
  private mContext?: common.UIAbilityContext;
  /**
   * EnviornmentCallback id
   */
  private mCallbackId: number = -1;
  private mListeners: Map<string, ConfigChangeListener> = new Map();
  private isStarted: boolean = false;
  /**
   * 环境变化回调
   */
  private mEnivornmentCallback: EnvironmentCallback = {
    onConfigurationUpdated(config: Configuration): void {
      Log.info(TAG, 'onConfigurationUpdated configChange');
      configMgr.notifyListeners(config);
    },
    onMemoryLevel(level: AbilityConstant.MemoryLevel): void {
      Log.info(TAG, 'Method to trim memory yet not in use, NULL METHOD');
    }
  };

  /**
   * 初始化
   *
   * @param context context
   */
  onStart(context: common.UIAbilityContext) :void {
    if (this.isStarted) {
      return;
    }
    this.isStarted = true;
    this.mConfigInfo = context?.config;
    this.mContext = context;
    Log.debug(TAG, `onStart config: ${JSON.stringify(this.mConfigInfo)}`);
    // 注册环境回调
    this.mCallbackId = context?.getApplicationContext()?.on('environment', this.mEnivornmentCallback);
  }

  onStop(): void {
    if (!this.isStarted) {
      return;
    }
    this.isStarted = false;
    // 解注册环境回调
    this.mContext?.getApplicationContext()?.off('environment', this.mCallbackId, (error, data) =>{
      if (error && error.code !== 0) {
        Log.error(TAG, `unregisterEnvironmentCallback fail, error: ${JSON.stringify(error)}`);
      } else {
        Log.info(TAG, `unregisterEnvironmentCallback success, data: ${JSON.stringify(data)}`);
      }
    });
  }

  registerConfigManager(key: string, listener: ConfigChangeListener): void {
    Log.info(TAG, `registerConfigManager key: ${key}`);
    if (key === null || listener === null) {
      return;
    }
    this.mListeners?.set(key, listener);
  }

  unregisterConfigManager(key: string): void {
    if (key === null) {
      return;
    }
    this.mListeners?.delete(key);
  }

  /**
   * 通知其他listener
   *
   * @param config config
   */
  notifyListeners(config: Configuration): void {
    this.mConfigInfo = config;
    Log.info(TAG, 'notifyListeners enter.');
    this.mListeners?.forEach((listener, key) => {
      Log.debug(TAG, `notifyListeners key: ${key}`);
      listener?.notifyConfigurationChanged(this.mConfigInfo);
    });
    Log.info(TAG, 'notifyListeners end.');
  }

  /**
   * 获取当前属性
   *
   * @returns
   */
  getConfiguration(): Configuration {
    return this.mConfigInfo;
  }
}

export let configMgr = SingletonHelper.getInstance(ConfigManager, TAG);