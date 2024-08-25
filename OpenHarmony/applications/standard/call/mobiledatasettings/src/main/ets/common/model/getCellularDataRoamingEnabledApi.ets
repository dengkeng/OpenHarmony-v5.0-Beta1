/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @file: Move data interface call
 */

import telephonyData from '@ohos.telephony.data';
import radio from '@ohos.telephony.radio';
import LogUtils from '../utils/LogUtils'

const TAG = 'getCellularDataRomingEnabledApi'
/**
 * Whether to enable cellular data roaming
 *
 * @return {Promise}
 */
export function isCellularDataRoamingEnabledCardOne(slotId = 0) {
  return telephonyData.isCellularDataRoamingEnabled(slotId);
}

export function isCellularDataRoamingEnabledCardTwo(slotId = 1) {
  return telephonyData.isCellularDataRoamingEnabled(slotId);
}

export function getSupportNetwork(slotId = 0) {
  return new Promise(function (resolve, reject) {
    try {
      let isSupported = radio.isNrSupported();
      LogUtils.i(TAG, 'getSupportNetwork success data:' + JSON.stringify(isSupported))
      resolve(isSupported);
    } catch (error) {
      LogUtils.i(TAG, 'getSupportNetwork success catch:' + JSON.stringify(error))
      reject(error);
    }
  });
};

/**
 * Enabling Data Roaming
 *
 * @return {Promise}
 */
export function enableCellularDataRoaming(slotId = 0) {
  return telephonyData.enableCellularDataRoaming(slotId);
}

/**
 * Enabling Data Roaming
 *
 * @return {Promise}
 */
export function disableCellularDataRoaming(slotId = 0) {
  return telephonyData.disableCellularDataRoaming(slotId);
}