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

import { ErrorTagFormat, ErrorMessage } from '../../../typedef/checker/result_type';
import { ClassInfo } from '../../../typedef/parser/ApiInfoDefination';
import { Comment } from '../../../typedef/parser/Comment';
import { CommonFunctions } from '../../../utils/checkUtils';
import { punctuationMarkSet } from '../../../utils/checkUtils';

export class ForbiddenWordsCheck {
  /**
   * forbidden words check-'any','this','unknow'
   * @param { ClassInfo } singleApi -single api info
   * @returns { ErrorTagFormat }
   */
  static forbiddenWordsCheck(singleApi: ClassInfo): ErrorTagFormat {
    const forbiddenWordsArr: string[] = ['any', 'this', 'unknown'];
    const forbiddenWordsResult: ErrorTagFormat = {
      state: true,
      errorInfo: '',
    };
    const apiFullText: string = singleApi.getDefinedText();
    const jsDocInfo: Comment.JsDocInfo[] = singleApi.getJsDocInfos();
    const publishVersion: string = jsDocInfo[0].getSince();
    const apiVersionToBeVerified: string = CommonFunctions.getCheckApiVersion();
    const reg = /\s{2,}/g;
    const regx = /(\/\*|\*\/|\*)|\\n|\\r/g;
    let fullText = apiFullText.replace(regx, ' ');
    punctuationMarkSet.forEach(punctuationMark => {
      const punctuationMarkReg = new RegExp(punctuationMark, 'g');
      if (punctuationMarkReg.test(fullText)) {
        fullText = fullText.replace(punctuationMarkReg, ' ').replace(reg, ' ');
      }
    });
    let apiTextWordsArr = fullText.split(/\s/g);
    apiTextWordsArr.forEach((apiTextWord) => {
      if (forbiddenWordsArr.includes(apiTextWord) && publishVersion === apiVersionToBeVerified) {
        forbiddenWordsResult.state = false;
        forbiddenWordsResult.errorInfo = CommonFunctions.createErrorInfo(ErrorMessage.ILLEGAL_USE_ANY, [apiTextWord]);
      }
    });
    return forbiddenWordsResult;
  }
}
