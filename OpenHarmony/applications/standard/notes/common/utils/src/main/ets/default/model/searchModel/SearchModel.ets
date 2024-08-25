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

import { LogUtil } from '../../baseUtil/LogUtil'
import NoteData from '../../model/databaseModel/NoteData'
import util from '@ohos.util'

const TAG = "SearchModel"

/**
 * Search service class
 */
export class SearchModel {
  private rdbStore;

  /**
   * Search
   *
   * @param query - query content
   */
  public async search(noteDataArray: NoteData[], query: string): Promise<NoteData[]> {
    LogUtil.info(TAG, "query is " + query)
    if (!query) {
      LogUtil.info(TAG, "query is null")
      return []
    }
    let searchData: NoteData[] = [];
    noteDataArray.forEach((noteData) => {
      let base64regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/
      let contentTextValue: string
      if (base64regex.test(noteData.content_text) && noteData.content_text.length > 0) {
        let Base64 = new util.Base64()
        let textDecoder = new util.TextDecoder("utf-8", { ignoreBOM: true }) // utf-8:编码格式为utf-8,ignoreBOM:是否忽略BOM标记
        let decodeStr = Base64.decodeSync(noteData.content_text)
        contentTextValue = textDecoder.decode(decodeStr, { stream: false }) // stream:在随后的decode()调用中是否跟随附加数据块
      } else {
        contentTextValue = noteData.content_text
      }
      if (contentTextValue.replace(/<[^>]+>/g, "").toLowerCase().indexOf(query.toLowerCase()) != -1
      || noteData.title.toLowerCase().indexOf(query.toLowerCase()) != -1) {
        LogUtil.info(TAG, "uuid " + noteData.uuid)
        searchData.push(noteData);
      }
    })
    // 排序
    return searchData;
  }

  splitToHighlightText(text: string, highlightKeyword): any[] {
    let spans: any[] = []
    var lowerSpans: string[] = text.toLowerCase().split(highlightKeyword.toLowerCase())
    var keywordStartIndex = 0
    var keywordLength = highlightKeyword.length

    for (var i = 0; i < lowerSpans.length; i++) {
      var normalText = text.substr(keywordStartIndex, lowerSpans[i].length)
      spans.push({
        type: 0,
        text: normalText
      })
      // if not at last, append highlight keyword
      if (i != lowerSpans.length - 1) {
        keywordStartIndex += lowerSpans[i].length
        var keywordText = text.substr(keywordStartIndex, keywordLength)
        spans.push({
          type: 1,
          text: keywordText
        })
        keywordStartIndex += keywordLength
      }
    }

    return spans
  }
}

let searchModel = new SearchModel()

export default searchModel as SearchModel