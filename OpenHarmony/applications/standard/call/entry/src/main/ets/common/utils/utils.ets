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
 * @file: Tools
 */


/**
 * Carry when the time is greater than 9 seconds
 */
const NINE_MAX = 9;

/**
 * Divide by 60 to get minutes and seconds
 */
const SIXTY_SECONDS = 60;
const SEC_VAL = 1000;
const MIN_VAL = SIXTY_SECONDS * SEC_VAL

export default class Utils {
  private static sUtils: Utils

  public static getInstance(): Utils {
    if (Utils.sUtils == null) {
      Utils.sUtils = new Utils()
    }
    return Utils.sUtils;
  }

  /**
   * format phone number
   *
   * @param { string } phoneNumber
   */
  public formatPhoneNum(phoneNumber) {
    if (/^1\d{10}$/.test(phoneNumber)) {
      const str01 = phoneNumber.substring(0, 3);
      const str02 = phoneNumber.substring(3, 7);
      const str03 = phoneNumber.substring(7, 11);
      return `${str01} ${str02} ${str03}`;
    }
    return phoneNumber;
  }

  /**
   * format time
   *
   * @param { number } count
   */
  public formatTime(count) {
    const second = Math.floor((count % MIN_VAL) / SEC_VAL);
    const minute = Math.floor((count / MIN_VAL) % SIXTY_SECONDS);
    const hour = Math.floor(count / (SIXTY_SECONDS * MIN_VAL));
    const secondStr = second <= NINE_MAX ? '0' + second : second;
    const minuteStr = minute <= NINE_MAX ? '0' + minute : minute;
    return hour > 0 ? `${hour}:${minuteStr}:${secondStr}` : `${minuteStr}:${secondStr}`;
  }

  /**
   * debounce
   *
   * @param {Function} func
   *
   * @param {Number} delay
   *
   * @return function
   */
  public debounce(func, delay = 200) {
    let timer = null;
    return function () {
      clearTimeout(timer);
      timer = setTimeout(() => {
        func.apply(this, arguments);
      }, delay);
    };
  }
}