/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import { DateTimeFormat } from '../model/PrintBean';

/**
 * Date utils
 */
export class DateUtils {
  private static readonly NUMBER_TEN: Number = 10;

  /**
   * get curr date time
   */
  public static getCurrTime(): string {
    return DateUtils.getCurrentDate(DateTimeFormat.DATE_TIME);
  }

  /**
   * get curr date
   *
   * @param format DATE_TIME_FORMAT
   */
  public static getCurrentDate(format: DateTimeFormat): string {
    let now = new Date();

    let year = now.getFullYear(); //得到年份
    let month = now.getMonth() + 1; //得到月份
    let date = now.getDate(); //得到日期
    let hour = now.getHours(); //得到小时
    let minus = now.getMinutes(); //得到分钟
    let sec = now.getSeconds(); //得到秒

    let currMonth = DateUtils.completionZero(month);
    let currDate = DateUtils.completionZero(date);
    let currHour = DateUtils.completionZero(hour);
    let currMinus = DateUtils.completionZero(minus);
    let currSec = DateUtils.completionZero(sec);

    let time = '';
    switch (format) {
      case DateTimeFormat.DATE:
        time = year + '-' + currMonth + '-' + currDate;
        break;
      case DateTimeFormat.TIME:
        time = currHour + ':' + currMinus + ':' + currSec;
        break;
      case DateTimeFormat.DATE_TIME:
        time = year + '-' + currMonth + '-' + currDate + ' ' + currHour + ':' + currMinus + ':' + currSec;
        break;
      default:
        break;
    }
    return time;
  }

  static completionZero(data: number): string {
    let currDate = data.toString();
    if (data < DateUtils.NUMBER_TEN) {
      currDate = '0' + data;
    }
    return currDate;
  }
}