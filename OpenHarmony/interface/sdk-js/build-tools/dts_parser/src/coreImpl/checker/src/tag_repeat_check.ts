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
import { ErrorTagFormat, ErrorMessage } from '../../../typedef/checker/result_type';
import { CommonFunctions } from '../../../utils/checkUtils';

export class TagRepeatCheck {
  /**
   * jsdoc tag repeat check
   * @param { Comment.JsDocInfo } apiJsdoc
   * @returns { ErrorTagFormat[] }
   */
  static tagRepeatCheck(apiJsdoc: Comment.JsDocInfo): ErrorTagFormat[] {
    const tagRepeatCheckResult: ErrorTagFormat[] = [];
    const multipleTags: string[] = ['throws', 'param'];
    const tagNameArr: string[] = [];
    apiJsdoc.tags?.forEach((tag) => {
      tagNameArr.push(tag.tag);
    });
    const duplicateArr: string[] = tagNameArr.filter((item) => {
      return tagNameArr.indexOf(item) !== tagNameArr.lastIndexOf(item);
    });
    const duplicateSet: Set<string> = new Set(duplicateArr);
    duplicateSet.forEach((duplicateTag) => {
      if (!multipleTags.includes(duplicateTag)) {
        const tagRepeatCheckFormat: ErrorTagFormat = {
          state: false,
          errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_REPEATLABEL, [duplicateTag]),
        };
        tagRepeatCheckResult.push(tagRepeatCheckFormat);
      }
    });
    return tagRepeatCheckResult;
  }
}
