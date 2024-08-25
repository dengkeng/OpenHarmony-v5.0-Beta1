/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 * @file: sim card status
 */
export default class SimStateConst {
  // SIM card status unknown
  public static SIM_STATE_UNKNOWN: number = 0;

  // SIM card is not present
  public static SIM_STATE_NOT_PRESEN: number = 1;

  // SIM card is locked
  public static SIM_STATE_LOCKED: number = 2;

  // SIM card is not ready
  public static SIM_STATE_NOT_READY: number = 3;

  // SIM card is in ready state
  public static SIM_STATE_READY: number = 4;

  // M card is in loading state
  public static SIM_STATE_LOADED: number = 5;

  public static getSimStateObj = {
    SIM_STATE_UNKNOWN: SimStateConst.SIM_STATE_UNKNOWN,
    SIM_STATE_NOT_PRESEN: SimStateConst.SIM_STATE_NOT_PRESEN,
    SIM_STATE_LOCKED: SimStateConst.SIM_STATE_LOCKED,
    SIM_STATE_NOT_READY: SimStateConst.SIM_STATE_NOT_READY,
    SIM_STATE_READY: SimStateConst.SIM_STATE_READY,
    SIM_STATE_LOADED: SimStateConst.SIM_STATE_LOADED
  };
}



