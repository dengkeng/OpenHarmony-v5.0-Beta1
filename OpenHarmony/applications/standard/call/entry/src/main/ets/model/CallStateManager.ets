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
 * @file: Call status management
 */

/**
 * class CallStateManager
 */
export default class CallStateManager {
  private callData = [];
  private static sCallStateManager: CallStateManager;

  constructor(callData) {
    this.callData = callData;
  }

  /**
   * update callData
   *
   * @param { Object } data - callData
   */
  public static getInstance(): CallStateManager {
    return CallStateManager.sCallStateManager;
  }

  public update(data) {
    Object.assign(this.callData, {
      ...data
    });
  }
}