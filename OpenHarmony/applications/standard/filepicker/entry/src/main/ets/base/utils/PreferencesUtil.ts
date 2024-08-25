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

import dataPreferences from '@ohos.data.preferences'
import Logger from '../log/Logger'

const TAG = 'PreferencesUtil'

export const getPreferences = (preferenceName: string) => {
  return dataPreferences.getPreferences(globalThis.abilityContext, preferenceName)
}

export const deletePreferences = (preferenceName: string) => {
  return dataPreferences.deletePreferences(globalThis.abilityContext, preferenceName)
}

export const removePreferencesFromCache = (preferenceName: string) => {
  return dataPreferences.removePreferencesFromCache(globalThis.abilityContext, preferenceName)
}

export const setPreferencesValue = (name: string, key: string, newVal) => {
  return getPreferences(name).then(async preferences => {
    await preferences.put(key, newVal)
    await preferences.flush()
  }).catch(err => {
    Logger.e(TAG, 'setPreferencesValue error: ' + JSON.stringify(err))
  })
}
