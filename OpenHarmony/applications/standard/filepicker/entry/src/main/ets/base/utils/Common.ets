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
import prompt from '@ohos.prompt';
import { getResourceString } from './Tools';
import { MILLISECOND, FILENAME_REGEXP } from '../constants/Constant';
import Logger from '../log/Logger';
import MediaLibrary from '@ohos.multimedia.mediaLibrary';

const TAG = 'commonUtil';

let mediaLibrary: MediaLibrary.MediaLibrary = null;

export const toast = (text: string | Resource, time = MILLISECOND.ONE_SECOND) => {
  let resourceString = undefined;
  if (typeof text !== 'string') {
    resourceString = getResourceString(text);
  } else {
    resourceString = text;
  }
  prompt.showToast({ message: resourceString, duration: time });
}

/**
 * 设置导航栏、状态栏背景、文字颜色
 *
 * @param navigationBarColor 导航栏背景颜色
 * @param statusBarColor 状态栏背景颜色
 * @param navigationBarContentColor 导航栏文字颜色
 * @param statusBarContentColor 状态栏文字颜色
 */
export const setSystemBar = async (navigationBarColor?: string, statusBarColor?: string,
                                   navigationBarContentColor?: string, statusBarContentColor?: string) => {
  let w = await window.getTopWindow(getContext(this));
  await w.setSystemBarProperties({
    navigationBarColor,
    statusBarColor,
    navigationBarContentColor,
    statusBarContentColor
  });
}

/**
 * 设置沉浸式
 *
 * @param isImmersion 是否沉浸式
 */
export const setImmersion = (isImmersion: boolean) => {
  let TAG = 'setImmersion';
  if (!globalThis.windowClass) {
    return;
  }
  globalThis.windowClass.setFullScreen(isImmersion, (err, data) => {
    if (err.code) {
      Logger.e(TAG, 'Failed to enable the full-screen mode. Cause:' + JSON.stringify(err));
      return;
    }
    Logger.i(TAG, 'Succeeded in enabling the full-screen mode. Data: ' + JSON.stringify(data));
  })
}

/**
 * 校验文件名合法性
 *
 * @param fileName 文件名
 * @return 是否合法
 */
export function isValidFileName(fileName): boolean {
  return FILENAME_REGEXP.test(fileName);
}

