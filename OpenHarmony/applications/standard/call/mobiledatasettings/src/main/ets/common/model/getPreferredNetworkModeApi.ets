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
 * @file: Network mode interface
 */
import radio from '@ohos.telephony.radio';
import LogUtils from '../utils/LogUtils'

const TAG = 'getPreferredNetworkModelApi'

/**
 * Get the preferred network mode
 *
 * @param {string} val - card The slot id
 * @return {Promise} promise object
 */
export function getPreferredNetwork(val) {
    return new Promise((resolve) => {
        radio.getPreferredNetwork(val).then((res) => {
            LogUtils.i(TAG, 'getPreferredNetwork success data then:' + JSON.stringify(res))
            resolve(res);
        }).catch((err) => {
            LogUtils.i(TAG, 'getPreferredNetwork success catch:' + JSON.stringify(err))
        });
    });
}