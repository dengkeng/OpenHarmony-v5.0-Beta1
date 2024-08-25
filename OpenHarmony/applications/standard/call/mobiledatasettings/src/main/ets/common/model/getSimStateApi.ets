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
 * @file: Obtaining card status
 */

import sim from '@ohos.telephony.sim';

const TAG = 'GetSimStateApi'

/**
 * Get cardOne status
 *
 * @param {number} slotId - return card The slot id
 * @return {Promise} promise object
 */
export function getSimStateCardOne(slotId = 0) {
  if (sim.getSimState) {
    return sim.getSimState(slotId);
  }
}

/**
 * Get cardTwo status
 *
 * @param {string} slotId - card The slot id
 * @return {Promise} promise object
 */
export function getSimStateCardTwo(slotId = 1) {
  if (sim.getSimState) {
    return sim.getSimState(slotId);
  }
}


