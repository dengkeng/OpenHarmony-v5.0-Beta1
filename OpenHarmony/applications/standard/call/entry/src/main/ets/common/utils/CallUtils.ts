/**
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
 * Call Util
 *
 * standard:
 * 1. define TAG, recommend class name.
 * 2. switch IS_DEBUG_ON as true, when debugging.
 * 3. msg should be short and valuable.
 * 4. choose appropriate function.
 * 5. the function execute many times can not print.
 * 6. uniqueness.
 */
import call from '@ohos.telephony.call';
import sim from '@ohos.telephony.sim';
import LogUtils from './LogUtils';

const TAG = 'CallUtils';

/**
 *  calllog package tool class
 */
export class CallUtils {
  /**
   * Judge whether there is a sim card.
   *
   * @param { accountId } accountId
   *
   * @return { boolean } - return success true fail false
   */
  public hasSimeCard: Function = (accountId) => new Promise((resolve, reject) => {
    sim.hasSimCard(accountId).then((res) => {
      resolve(res);
      if (accountId === 0) {
        AppStorage.SetOrCreate('hasSimCard1', res);
      } else if (accountId === 1) {
        AppStorage.SetOrCreate('hasSimCard2', res);
      }
    })
      .catch((err) => {
        reject(err);
        LogUtils.i(TAG, 'catch:hasSimeCard :' + JSON.stringify(err));
      });
  });

  /**
   * Determine whether the call is an emergency call.
   *
   * @param { phoneNumber } phoneNumber-number
   *
   * @return { boolean } - return success true fail false
   */
  public isEmergencyPhoneNumber: Function = (phoneNumber) => new Promise((resolve, reject) => {
    call.isEmergencyPhoneNumber(phoneNumber, {
      slotId: 0
    }).then((res) => {
      resolve(res);
      AppStorage.SetOrCreate('IsEmergencyPhoneNumber', res)
      LogUtils.i(TAG, 'then:isEmergencyPhoneNumber :' + JSON.stringify(res));
    }).catch((err) => {
      reject(err);
      LogUtils.i(TAG, 'catch:isEmergencyPhoneNumber :' + JSON.stringify(err));
    });
  });
}

let mCallUtil = new CallUtils();

export default mCallUtil as CallUtils;

