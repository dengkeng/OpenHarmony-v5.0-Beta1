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
import { Comment } from '../../../typedef/parser/Comment';
import { tagsArrayOfOrder, officialTagArr, CommonFunctions } from '../../../utils/checkUtils';
import { ErrorMessage, ErrorTagFormat } from '../../../typedef/checker/result_type';

export class TagNameCheck {
  /**
   * check jsdoc tag name.
   * @param { Comment.JsDocInfo } apiJsdoc
   * @returns { ErrorTagFormat }
   */
  static tagNameCheck(apiJsdoc: Comment.JsDocInfo): ErrorTagFormat {
    const tagNameCheckResult: ErrorTagFormat = {
      state: true,
      errorInfo: '',
    };
    const legalTagArr: string[] = tagsArrayOfOrder.concat(officialTagArr);
    const tagsName: Comment.CommentTag[] | undefined = apiJsdoc.tags;
    if (tagsName === undefined) {
      return tagNameCheckResult;
    }
    tagsName.forEach((tag) => {
      if (!legalTagArr.includes(tag.tag)) {
        tagNameCheckResult.state = false;
        tagNameCheckResult.errorInfo = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LABELNAME, [tag.tag]);
      }
    });
    return tagNameCheckResult;
  }
}
