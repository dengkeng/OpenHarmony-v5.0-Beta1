/*
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

import {LogUtil} from './LogUtil'

const TAG = "DateUtil"

/**
 * 日期和时间均显示为2位数
 * @param time
 */
function getUnifiedTime(time: number): any {
  return time > 9 ? time : "0" + time
}

/**
 * 日期时间工具类, 中文暂时不写到string.json, $r("")取出来的是Resource, 转化为string困难
 */
export class DateUtil {
  /**
   * 获取笔记标题的格式化时间
   * @param date note modified time
   */
  formateDateForNoteTitle(date: Date): string{
    let nowDate = new Date()
    let diffMin = Math.floor((nowDate.getTime() - date.getTime()) / 1000 / 60)
    if (diffMin < 0) {
      LogUtil.info(TAG, "DateUtils, formateDateForNoteTitle : date is error")
      return this.formateDateForNoteContent(date)
    }

    let noteTitletTime = ""
    let year = date.getFullYear()
    let month = date.getMonth()
    let day = date.getDate()
    let hours = date.getHours()
    let mins = date.getMinutes()

    let nowYear = nowDate.getFullYear()
    let nowMonth = nowDate.getMonth()
    let nowDay = nowDate.getDate()

    if (diffMin < 1) {
      // 1分钟内, 显示“刚刚”
      noteTitletTime = "刚刚"
    } else if (diffMin < 60) {
      // 1小时内, 显示“X分钟前”
      noteTitletTime = diffMin + "分钟前"
    } else if (nowYear === year && nowMonth === month && nowDay === day) {
      // 今天, 显示“hh:mm”
      noteTitletTime = getUnifiedTime(hours) + ":" + getUnifiedTime(mins)
    } else if (nowYear === year && nowMonth === month && nowDay === (day + 1)) {
      // 昨天, 场景1: 2022年1月1日 - 2022年1月2日, 显示“昨天”
      noteTitletTime = "昨天"
    } else if (nowYear === year && nowDay === 1) {
      // 昨天, 场景2: 2022年1月31日 - 2022年2月1日, 显示“昨天”
      let now = new Date()
      now.setDate(0) // 设置为上个月的最后一天
      noteTitletTime = now.getDate() === day ? "昨天" : ""
    } else if (nowYear === year + 1 && nowDay === 1) {
      // 昨天, 场景3: 2022年12月31日 - 2023年1月1日, 显示“昨天”
      let now = new Date()
      now.setMonth(-1) // 设置为去年的最后一个月
      noteTitletTime = now.getMonth() === month ? "昨天" : ""
    } else if (nowYear === year) {
      // 今年, 显示“X月X日”
      noteTitletTime = getUnifiedTime(month + 1) + "月" + getUnifiedTime(day) + "日"
    } else {
      // 不是今年, 显示“X年X月X日”
      noteTitletTime = year + "年" + getUnifiedTime(month + 1) + "月" + getUnifiedTime(day) + "日"
    }
    return noteTitletTime
  }

  /**
   * 获取笔记内容的格式化时间
   * @param date note modified time
   */
  formateDateForNoteContent(date: Date): string{
    // formatted time
    let noteContentTime = ""
    // note modified time
    let year = date.getFullYear()
    let month = date.getMonth()
    let day = date.getDate()
    let hours = date.getHours()
    let mins = date.getMinutes()
    // now date
    let nowDate = new Date()
    let nowYear = nowDate.getFullYear()
    let nowMonth = nowDate.getMonth()
    let nowDay = nowDate.getDate()
    if (nowYear === year && nowMonth === month && nowDay === day) {
      // 今天, 显示“hh:mm”
      noteContentTime = "今天" + " " + getUnifiedTime(hours) + ":" + getUnifiedTime(mins)
    } else if (nowYear === year) {
      // 今年, 显示“X月X日 hh:mm”
      noteContentTime = getUnifiedTime(month + 1) + "月" + getUnifiedTime(day) + "日"
      + " " + getUnifiedTime(hours) + ":" + getUnifiedTime(mins)
    } else {
      // 不是今年, 显示“X年X月X日 hh:mm”
      noteContentTime = year + "年" + getUnifiedTime(month + 1) + "月" + getUnifiedTime(day) + "日"
      + " " + getUnifiedTime(hours) + ":" + getUnifiedTime(mins)
    }
    return noteContentTime
  }
}

let dateUtil = new DateUtil()

export default dateUtil as DateUtil