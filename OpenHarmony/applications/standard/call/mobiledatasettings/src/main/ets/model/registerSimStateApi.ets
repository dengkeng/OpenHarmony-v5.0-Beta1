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
 * @file: registerSimStateApi
 */
import observer from '@ohos.telephony.observer';
import LogUtils from '../common/utils/LogUtils';
import sim from '@ohos.telephony.sim';

const TAG = 'registerSimStateAPi';

/**
 * Monitor the SIM card status
 *
 * @param {function} callBack - call-back
 * @param {string} slotId - card The slot id
 */
export function registerSimStateChange(slotId, callBack) {
  return observer.on('simStateChange', {
    slotId: slotId
  }, (callStateInfo) => {
    LogUtils.i(TAG, 'registerSimStateChange: then ' + JSON.stringify(callStateInfo));
    callBack(callStateInfo);
    return callStateInfo;
  });
}

export function getMaxSimCount() {
  return sim.getMaxSimCount();
}
