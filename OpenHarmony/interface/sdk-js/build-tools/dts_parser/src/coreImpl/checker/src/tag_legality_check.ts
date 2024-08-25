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

import ts from 'typescript';
import { ApiInfo, ApiType, MethodInfo } from '../../../typedef/parser/ApiInfoDefination';
import {
  tagsArrayOfOrder,
  optionalTags,
  apiLegalityCheckTypeMap
} from '../../../utils/checkUtils';
import { Comment } from '../../../typedef/parser/Comment';
import { ErrorTagFormat, ErrorMessage } from '../../../typedef/checker/result_type';
import { CommonFunctions, conditionalOptionalTags } from '../../../utils/checkUtils';

export class LegalityCheck {
  /**
   * Tag's legality check
   * @param { ApiInfo } singleApi -Individual node information.
   * @param { Comment.JsDocInfo } apiJsdoc -Individual node JsDoc.
   * @returns { ErrorTagFormat[] }
   */
  static apiLegalityCheck(singleApi: ApiInfo, apiJsdoc: Comment.JsDocInfo): ErrorTagFormat[] {
    const apiLegalityCheckResult: ErrorTagFormat[] = [];
    const nodeInfo: ts.Node = singleApi.getNode() as ts.Node;
    const apiLegalityTagsArray: string[] = apiLegalityCheckTypeMap.get(nodeInfo.kind) as string[];
    const apiLegalityTagsSet: Set<string> = new Set(apiLegalityTagsArray);
    const illegalTagsArray: string[] = LegalityCheck.getIllegalTagsArray(apiLegalityTagsArray);
    let extendsApiValue = '';
    let implementsApiValue = '';
    if (singleApi.getApiType() === ApiType.CLASS || singleApi.getApiType() === ApiType.INTERFACE) {
      extendsApiValue = CommonFunctions.getExtendsApiValue(singleApi);
      implementsApiValue = CommonFunctions.getImplementsApiValue(singleApi);
    }
    if (extendsApiValue === '') {
      apiLegalityTagsSet.delete('extends');
      illegalTagsArray.push('extends');
    }
    if (implementsApiValue === '') {
      apiLegalityTagsSet.delete('implements');
      illegalTagsArray.push('implements');
    }

    // 判断api的jsdoc中是否存在非法标签，是否缺失必选标签
    if (!Array.isArray(apiLegalityTagsArray)) {
      return apiLegalityCheckResult;
    }
    const apiTags: Comment.CommentTag[] | undefined = apiJsdoc.tags;
    if (apiTags === undefined) {
      const sinceLost: ErrorTagFormat = {
        state: false,
        errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LOST_LABEL, ['since']),
      };
      const syscapLost: ErrorTagFormat = {
        state: false,
        errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LOST_LABEL, ['syscap']),
      };
      apiLegalityCheckResult.push(sinceLost, syscapLost);
      return apiLegalityCheckResult;
    }

    let paramTagNumber: number = 0;
    let paramApiNumber: number =
      singleApi.getApiType() === ApiType.METHOD ? (singleApi as MethodInfo).getParams().length : 0;
    apiTags.forEach((apiTag) => {
      paramTagNumber = apiTag.tag === 'param' ? paramTagNumber + 1 : paramTagNumber;
      const isUseinsteadLegalSituation: boolean = apiTag.tag === 'useinstead' && apiJsdoc.deprecatedVersion !== '-1';

      if (illegalTagsArray.includes(apiTag.tag) && (apiTag.tag !== 'useinstead' || !isUseinsteadLegalSituation)) {
        const apiRedundantResultFormat: ErrorTagFormat = {
          state: false,
          errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_USE, [apiTag.tag]),
        };
        apiLegalityCheckResult.push(apiRedundantResultFormat);
      }
      apiLegalityTagsSet.delete('param');
      if (apiLegalityTagsSet.has(apiTag.tag)) {
        apiLegalityTagsSet.delete(apiTag.tag);
      }
      if (singleApi.getApiType() === ApiType.INTERFACE && (apiTag.tag === 'typedef' || apiTag.tag === 'interface')) {
        apiLegalityTagsSet.delete('typedef');
        apiLegalityTagsSet.delete('interface');
      }
      if (singleApi.getApiType() === ApiType.METHOD && (singleApi as MethodInfo).getReturnValue().length === 0) {
        apiLegalityTagsSet.delete('returns');
      }
    });
    // param合法性单独进行校验
    LegalityCheck.paramLegalityCheck(paramTagNumber, paramApiNumber, apiLegalityCheckResult);
    // 缺失标签set合集
    apiLegalityTagsSet.forEach((apiLegalityTag) => {
      if (!conditionalOptionalTags.includes(apiLegalityTag)) {
        const apiLostResultFormat: ErrorTagFormat = {
          state: false,
          errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LOST_LABEL, [apiLegalityTag]),
        };
        apiLegalityCheckResult.push(apiLostResultFormat);
      }
    });

    return apiLegalityCheckResult;
  }

  /**
   * param tag  legality check
   * @param { number } paramTagNumber
   * @param { number } paramApiNumber
   * @param { ErrorTagFormat[] } apiLegalityCheckResult
   */
  static paramLegalityCheck(
    paramTagNumber: number,
    paramApiNumber: number,
    apiLegalityCheckResult: ErrorTagFormat[]
  ): void {
    if (paramTagNumber > paramApiNumber) {
      const apiRedundantResultFormat: ErrorTagFormat = {
        state: false,
        errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_MORELABEL, [
          JSON.stringify(paramTagNumber - paramApiNumber),
          'param',
        ]),
      };
      apiLegalityCheckResult.push(apiRedundantResultFormat);
    } else if (paramTagNumber < paramApiNumber) {
      const apiLostResultFormat: ErrorTagFormat = {
        state: false,
        errorInfo: CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LOST_LABEL, ['param']),
      };
      apiLegalityCheckResult.push(apiLostResultFormat);
    }
  }

  /**
   * Gets all illegal tags for the api.
   * @param { string[] } RequiredTagsArray
   * @returns { string[] }
   */
  static getIllegalTagsArray(requiredTagsArray: string[]): string[] {
    const illegalTagsArray: string[] = [];

    tagsArrayOfOrder.forEach((tag) => {
      if (!optionalTags.includes(tag) && !Array.isArray(requiredTagsArray)) {
        illegalTagsArray.push(tag);
      } else if (!optionalTags.includes(tag) && !requiredTagsArray.includes(tag)) {
        illegalTagsArray.push(tag);
      }
    });
    return illegalTagsArray;
  }
}
