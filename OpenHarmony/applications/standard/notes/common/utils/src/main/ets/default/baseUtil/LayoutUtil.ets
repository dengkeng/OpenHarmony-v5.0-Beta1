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

import {WidthWeightMessage, widthWeightMessageMap} from '../model/NoteBaseData'
import {LogUtil} from './LogUtil'

const TAG = "LayoutUtil"

export class LayoutUtil {
  /**
  * Get Width Weight Message
  *
  * @param sectionStatus - page's section number
  * @return WidthWeightMessage
  */
  getWidthWeightMessage(sectionStatus: number): WidthWeightMessage {
    LogUtil.info(TAG, "sectionStatus " + sectionStatus.toString())
    return widthWeightMessageMap[sectionStatus]
  }
}

let layoutUtil = new LayoutUtil()

export default layoutUtil as LayoutUtil