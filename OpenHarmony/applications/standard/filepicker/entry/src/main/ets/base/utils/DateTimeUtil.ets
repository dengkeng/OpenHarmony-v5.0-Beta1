/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import { MILLISECOND } from '../constants/Constant';
import StringUtil from './StringUtil';
import { getResourceString } from './Tools';
import Logger from '../../base/log/Logger';
import LanguageUtil from './LanguageUtil';

const TAG = 'DateTimeUtil';

namespace DateTimeUtil {
  /**
   * 日期格式常量
   */
  export const DATE_FORMAT = {
    YYYY_MM_DD: 'yyyy/mm/dd',
    MM_DD: 'mm/dd',
    DATE_TIME: 'yyyy/mm/dd HH:MM:SS',
    YYYY_MM_DD_CHINESE: 'yyyy年mm月dd日',
    MM_DD_CHINESE: 'm月d日',
    DATE_TIME_CHINESE: 'yyyy年mm月dd日 HH:MM'
  };

  /**
   * @description 获取指定时间戳当天0点的时间戳
   * @param timeStamp 指定时间戳
   * @return 当天0点的时间戳
   */
  export function getDayBeginTimeStamp(timeStamp: number) {
    const date = new Date(timeStamp);
    const year = date.getFullYear();
    const month = date.getMonth() + 1;
    const day = date.getDate();

    return new Date(`${year}-${month}-${day}`).getTime();
  }

  /**
   * @description 将时长转化成转化为时分秒
   * @param duration 时长
   * @param unit 时间单位
   * @return 格式化时长，如：08:20
   */
  export function formatDuration(duration: number): string {
    let remainTime = duration;
    const hours = Math.floor(remainTime / MILLISECOND.ONE_HOUR);
    remainTime -= hours * MILLISECOND.ONE_HOUR;
    const minutes = Math.floor(remainTime / MILLISECOND.ONE_MINUTE);
    remainTime -= minutes * MILLISECOND.ONE_MINUTE;
    const seconds = Math.floor(remainTime / MILLISECOND.ONE_SECOND);

    const minutesStr = StringUtil.padStart(minutes);
    const secondsStr = StringUtil.padStart(seconds);
    if (hours) {
      const hoursStr = StringUtil.padStart(hours);
      return `${hoursStr}:${minutesStr}:${secondsStr}`;
    } else {
      return `${minutesStr}:${secondsStr}`;
    }
  }

  /**
   * @description 格式化文件更新时间
   * @param timeStamp 时间戳,单位毫秒
   * @param 格式化时间，如：YYYY/MM/HH hh:mm:ss
   */
  export function formatFileModifiedTime(timeStamp: number): string {
    const dateTime = new Date(timeStamp);
    const year = dateTime.getFullYear();
    const month = StringUtil.padStart(dateTime.getMonth() + 1);
    const day = StringUtil.padStart(dateTime.getDate());
    const hour = StringUtil.padStart(dateTime.getHours());
    const minute = StringUtil.padStart(dateTime.getMinutes());
    const second = StringUtil.padStart(dateTime.getSeconds());
    return `${year}/${month}/${day} ${hour}:${minute}:${second}`;
  }

  /**
   * 日期格式转换
   * @param timestamp 时间戳
   * @param format 格式(可选)
   * @example formatDate(new Date(), "YYYY-mm-dd HH:MM:SS") => 2021-11-02 09:39:59
   */
  export function formatDate(timestamp, format = DATE_FORMAT.YYYY_MM_DD) {
    let res = '';
    try {
      const date = new Date(timestamp);
      const opt = {
        'y+': date.getFullYear().toString(), // 年
        'm+': (date.getMonth() + 1).toString(), // 月
        'd+': date.getDate().toString(), // 日
        'H+': date.getHours().toString(), // 时
        'M+': date.getMinutes().toString(), // 分
        'S+': date.getSeconds().toString(), // 秒
      };
      for (let key in opt) {
        const reg = new RegExp(key);
        let ret = reg.exec(format);
        if (ret) {
          format = format.replace(
            reg, ret[0].length == 1 ? opt[key] : opt[key].padStart(ret[0].length, '0')
          );
        }
      }
      res = format;
    } catch (error) {
      Logger.e(TAG, 'formatDate error: ' + error.toString());
    }
    return res;
  }

  /**
   * @description 获取YYYY/MM/DD格式的日期
   * @param timeStamp 时间戳,单位毫秒
   * @return 格式化时间，格式：中文显示“2022/10/08”，其他显示“08/10/2022”
   */
  export function getSimpleDateString(timeStamp: number, format: string = ''): string {
    return formatDate(timeStamp, format || DATE_FORMAT.YYYY_MM_DD);
  }

  /**
   * @description 格式化时间
   * @param timeStamp 时间戳,单位毫秒
   * @return 格式化时间，规则如下：
   *  当前日期同一天：今天
   *  当前日期前一天：昨天
   *  其他：YYYY/MM/DD
   */
  export function getDateStringForCategory(timeStamp: number): string {
    const now = Date.now();
    const current = getDayBeginTimeStamp(timeStamp);
    const today = getDayBeginTimeStamp(now);
    const yesterday = today - MILLISECOND.ONE_DAY;
    if (current === today) {
      return getResourceString($r('app.string.today'));
    } else if (current === yesterday) {
      return getResourceString($r('app.string.yesterday'));
    } else {
      return getSimpleDateString(timeStamp);
    }
  }

  /**
   * @description 获取最近卡片显示的格式日期
   * @param timeStamp 时间戳,单位毫秒
   * @return 格式化时间，规则如下：
   *  当前时间1分钟内：刚刚
   *  当前时间1小时内：XX分钟前
   *  当前日期同一天：上午 08:00
   *  当前日期前一天：昨天
   *  今年：MM月DD日
   *  往年：YYYY/MM/DD
   */
  export function getDateStringForRecentCard(timeStamp: number): Resource | string {
    let dateString = undefined;
    const date = new Date();
    const now = date.getTime();
    const nowYear = date.getFullYear();
    const cardYear = new Date(timeStamp).getFullYear();
    const timeGap = now - timeStamp;
    const todayBegin = getDayBeginTimeStamp(now);
    const yesterdayBegin = todayBegin - MILLISECOND.ONE_DAY;
    if (timeStamp > todayBegin) {
      if (timeGap < MILLISECOND.ONE_MINUTE) {
        dateString = $r('app.string.justNow');
      } else if (timeGap < MILLISECOND.ONE_HOUR) {
        const minute = Math.floor(timeGap / MILLISECOND.ONE_MINUTE);
        dateString = $r('app.plural.minute_ago', minute, minute);
      } else {
        dateString = $r('app.string.today');
      }
    } else if (timeStamp > yesterdayBegin) {
      dateString = $r('app.string.yesterday');
    } else if (cardYear === nowYear) {
      const format = LanguageUtil.isChineseLanguage() ? DATE_FORMAT.MM_DD_CHINESE : DATE_FORMAT.MM_DD;
      dateString = formatDate(timeStamp, format);
    } else {
      dateString = getSimpleDateString(timeStamp);
    }
    return dateString;
  }
}

export default DateTimeUtil;
