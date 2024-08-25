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
 * @file: mobileData constants
 */

const ON_SIM_STATE_UPDATE_PULL = '1';
const ON_SIM_STATE_UPDATE_INSERT = '4';

const networkStateObj = {
  NETWORK_FIVE: 0,
  NETWORK_FOUR: 4,
  NETWORK_THREE: 6,
  NETWORK_TWO: 1
};

const simStateObj = {
  SIM_STATE_UNKNOWN: 0,
  SIM_STATE_NOT_PRESENT: 1,
  SIM_STATE_LOCKED: 2,
  SIM_STATE_NOT_READY: 3,
  SIM_STATE_READY: 4,
  SIM_STATE_LOADED: 5
};
const MOBILE_DATA_STATUS = {
  DATA_STATE_UNKNOWN: -1,
  DATA_STATE_DISCONNECTED: 0,
  DATA_STATE_CONNECTING: 1,
  DATA_STATE_CONNECTED: 2,
  DATA_STATE_SUSPENDED: 3
}

export {
  networkStateObj,
  simStateObj,
  ON_SIM_STATE_UPDATE_PULL,
  ON_SIM_STATE_UPDATE_INSERT,
  MOBILE_DATA_STATUS
};