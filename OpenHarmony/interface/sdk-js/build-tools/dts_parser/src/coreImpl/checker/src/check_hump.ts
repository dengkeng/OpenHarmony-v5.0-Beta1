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

import path from 'path';
import { AddErrorLogs } from './compile_info';
import { StringConstant } from '../../../utils/Constant';
import { ApiInfosMap, FileInfoMap } from '../../parser/parser';
import {
  ErrorType,
  ErrorID,
  LogType,
  ErrorLevel,
  ErrorMessage,
} from '../../../typedef/checker/result_type';
import { Comment } from '../../../typedef/parser/Comment';
import {
  ApiType,
  BasicApiInfo,
  ApiInfo,
  notJsDocApiTypes,
} from '../../../typedef/parser/ApiInfoDefination';
import { CommonFunctions } from '../../../utils/checkUtils';
import { compositiveResult, compositiveLocalResult } from '../../../utils/checkUtils';

export class CheckHump {
  /**
   * 大驼峰检查：
   * class、interface、枚举名
   *
   * @param {string} word 校验名称
   * @return { boolean }
   */
  static checkLargeHump(word: string): boolean {
    return /^([A-Z][a-z0-9]*)*$/g.test(word);
  }
  /**
   * 小驼峰检查:
   * 变量名、方法名、参数名、namespace
   *
   * @param {string} word 校验名称
   * @return { boolean }
   */
  static checkSmallHump(word: string): boolean {
    return /^[a-z]+[0-9]*([A-Z][a-z0-9]*)*$/g.test(word);
  }
  /**
   * 全大写检查:
   * 常量命名、枚举值
   *
   * @param {string} word 校验名称
   * @return { boolean }
   */
  static checkAllUppercaseHump(word: string): boolean {
    return /^[A-Z]+[0-9]*([\_][A-Z0-9]+)*$/g.test(word);
  }

  /**
   * 获取fileMap里的对应的apiinfos
   *
   * @param { FileInfoMap } fileMap 文件解析结果
   * @param { string } apiKey 获取api名称
   * @return {BasicApiInfo[]} apiInfo
   */
  static getApiInfosInFileMap(fileMap: FileInfoMap, apiKey: string): BasicApiInfo[] {
    if (apiKey === StringConstant.SELF) {
      return [];
    }
    const apiInfoMap: ApiInfosMap = fileMap.get(apiKey) as ApiInfosMap;
    return apiInfoMap.get(StringConstant.SELF) as BasicApiInfo[];
  }

  /**
   * 遍历所有api，进行api名称校验
   *
   * @param {BasicApiInfo[]} apiInfos
   */
  static checkAllAPINameOfHump(apiInfos: BasicApiInfo[]): void {
    apiInfos.forEach((apiInfo: BasicApiInfo) => {
      if (!notJsDocApiTypes.has(apiInfo.getApiType())) {
        CheckHump.checkAPINameOfHump(apiInfo as ApiInfo);
      }
    });
  }
  /**
   * api名称校验
   *
   * @param {ApiInfo} apiInfo api节点
   */
  static checkAPINameOfHump(apiInfo: ApiInfo): void {
    const jsDocInfo: Comment.JsDocInfo | undefined = apiInfo.getLastJsDocInfo();
    if (jsDocInfo) {
      if (jsDocInfo.getDeprecatedVersion() !== '-1') {
        return;
      }
      if (jsDocInfo.getSince() !== String(CommonFunctions.getCheckApiVersion())) {
        return;
      }
    }
    const apiType: string = apiInfo.getApiType();
    const filePath: string = apiInfo.getFilePath();
    const apiName: string = apiInfo.getApiName();
    let checkResult: string = '';
    if (
      apiType === ApiType.ENUM_VALUE ||
      (apiType === ApiType.CONSTANT && filePath.indexOf(`component${path.sep}ets${path.sep}`) === -1)
    ) {
      if (!CheckHump.checkAllUppercaseHump(apiName)) {
        checkResult = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_UPPERCASE_NAME, [apiName]);
      }
    } else if (
      apiType === ApiType.INTERFACE ||
      apiType === ApiType.CLASS ||
      apiType === ApiType.TYPE_ALIAS ||
      apiType === ApiType.ENUM
    ) {
      if (!CheckHump.checkLargeHump(apiName)) {
        checkResult = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_LARGE_HUMP_NAME, [apiName]);
      }
    } else if (
      apiType === ApiType.PROPERTY ||
      apiType === ApiType.METHOD ||
      apiType === ApiType.PARAM ||
      apiType === ApiType.NAMESPACE
    ) {
      if (!CheckHump.checkSmallHump(apiName)) {
        checkResult = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_SMALL_HUMP_NAME, [apiName]);
      }
    }

    if (checkResult !== '') {
      AddErrorLogs.addAPICheckErrorLogs(
        ErrorID.TS_SYNTAX_ERROR_ID,
        ErrorLevel.MIDDLE,
        filePath,
        apiInfo.getPos(),
        ErrorType.NAMING_ERRORS,
        LogType.LOG_API,
        -1,
        apiName,
        apiInfo.getDefinedText(),
        checkResult,
        compositiveResult,
        compositiveLocalResult
      );
    }
  }

  /**
   * 校验文件名称：
   * 只处理非component/ets/路径下的文件
   * 传入节点必须是文件的SourceFile节点
   *
   * @param {FileInfoMap} fileInfo 文件节点
   */
  static checkAPIFileName(fileInfo: FileInfoMap): void {
    const fileApiInfo: BasicApiInfo = (fileInfo.get(StringConstant.SELF) as BasicApiInfo[])[0];
    if (fileApiInfo.getApiType() !== ApiType.SOURCE_FILE) {
      return;
    }
    const filePath: string = fileApiInfo.getFilePath();
    if (filePath.indexOf(`component${path.sep}ets${path.sep}`) !== -1) {
      return;
    }
    let moduleName = '';
    let exportAssignment = '';
    let version = 'NA';
    for (const apiKey of fileInfo.keys()) {
      const apiInfos: BasicApiInfo[] = CheckHump.getApiInfosInFileMap(fileInfo, apiKey);
      apiInfos.forEach((apiInfo) => {
        if (!notJsDocApiTypes.has(apiInfo.getApiType())) {
          const jsDocInfos: Comment.JsDocInfo[] = (apiInfo as ApiInfo).getJsDocInfos();
          version = jsDocInfos[0] ? jsDocInfos[0].getSince() : version;
        }
        moduleName = apiInfo.getApiType() === ApiType.NAMESPACE ? apiInfo.getApiName() : moduleName;
        exportAssignment = apiInfo.getApiType() === ApiType.EXPORT_DEFAULT ? apiInfo.getApiName() : exportAssignment;
      });
    }
    const basename: string = path.basename(filePath).replace(new RegExp(StringConstant.DTS_EXTENSION, 'g'), '');

    const basenames: string[] = basename.split('.');
    const lastModuleName: string = basenames.length ? basenames[basenames.length - 1] : '';
    let checkResult: string = '';

    if (moduleName !== '' && exportAssignment === moduleName && !CheckHump.checkSmallHump(lastModuleName)) {
      checkResult = ErrorMessage.ERROR_SMALL_HUMP_NAME_FILE;
    } else if (moduleName === '' && exportAssignment !== moduleName && !CheckHump.checkLargeHump(lastModuleName)) {
      checkResult = ErrorMessage.ERROR_LARGE_HUMP_NAME_FILE;
    }
    if (checkResult !== '' && version === String(CommonFunctions.getCheckApiVersion())) {
      AddErrorLogs.addAPICheckErrorLogs(
        ErrorID.MISSPELL_WORDS_ID,
        ErrorLevel.MIDDLE,
        filePath,
        { line: -1, character: -1 },
        ErrorType.NAMING_ERRORS,
        LogType.LOG_API,
        -1,
        'NA',
        'NA',
        checkResult,
        compositiveResult,
        compositiveLocalResult
      );
    }
  }
}
