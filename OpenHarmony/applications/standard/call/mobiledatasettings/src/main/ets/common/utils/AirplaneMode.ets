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
 * Message/AirplaneMode utils
 */
const SETTING_AIRPLANE_MODE_URI = 'datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true';
const QUERY_AIRPLANE_MODE_KEY = 'airplane_mode';
const TAG = 'AirplaneMode';

import dataShare from '@ohos.data.dataShare';
import dataSharePredicates from '@ohos.data.dataSharePredicates';
import LogUtils from './LogUtils';

let dataShareHelper;

/**
 * add AirPlaneMode Listener.
 */
export function addAirPlaneModeListener(callback) {
  LogUtils.i(TAG, 'addAirPlaneModeListener');
  try {
    dataShare.createDataShareHelper(globalThis.settingsAbilityContext, SETTING_AIRPLANE_MODE_URI, (err, data) => {
      if (err != undefined) {
        LogUtils.e(TAG, 'addAirPlaneModeListener error: code: ' + err.code + ', message: ' + err.message);
        return;
      }
      dataShareHelper = data;
      try {
        dataShareHelper.on('dataChange', SETTING_AIRPLANE_MODE_URI, () => {
          LogUtils.i(TAG, 'addAirPlaneModeListener dataChange');
          queryAirPlaneMode(callback);
        });
        queryAirPlaneMode(callback);
      } catch (err) {
        LogUtils.e(TAG, 'addAirPlaneModeListener error: code: ' + err.code + ', message: ' + err.message);
      }
    });
  } catch (err) {
    LogUtils.e(TAG, 'addAirPlaneModeListener error: code: ' + err.code + ', message: ' + err.message);
  }
}

/**
 * remove AirPlaneMode Listener.
 */
export function removeAirPlaneModeListener() {
  LogUtils.i(TAG, 'removeAirPlaneModeListener');
  if (!dataShareHelper) {
    LogUtils.e(TAG, 'removeAirPlaneModeListener dataShareHelper null');
    return;
  }
  try {
    dataShareHelper.off('dataChange', SETTING_AIRPLANE_MODE_URI, () => {
      LogUtils.i(TAG, 'removeAirPlaneModeListener dataChange');
    });
  } catch (err) {
    LogUtils.e(TAG, 'removeAirPlaneModeListener error: code: ' + err.code + ', message: ' + err.message);
  }
}

/**
 * query AirPlaneMode.
 */
export function queryAirPlaneMode(callback) {
  LogUtils.i(TAG, 'queryAirPlaneMode');
  if (!dataShareHelper) {
    LogUtils.e(TAG, 'queryAirPlaneMode dataShareHelper null');
    return;
  }
  let condition = new dataSharePredicates.DataSharePredicates();
  condition.equalTo('KEYWORD', 'airplane_mode');
  try {
    // ID, KEYWORD, VALUE
    dataShareHelper.query(SETTING_AIRPLANE_MODE_URI, condition, null).then((data) => {
      LogUtils.i(TAG, 'queryAirPlaneMode query succeed');
      if (data && data.goToFirstRow()) {
        LogUtils.i(TAG, 'queryAirPlaneMode query succeed return key');
        callback(data.getLong(data.getColumnIndex('VALUE')));
        return;
      }
      callback(-1);
    }).catch((err) => {
      LogUtils.e(TAG, 'queryAirPlaneMode query in error: err: ' + JSON.stringify(err));
    });
  } catch (err) {
    LogUtils.e(TAG, 'queryAirPlaneMode query out error: code: ' + err.code + ', message: ' + err.message);
  }
}