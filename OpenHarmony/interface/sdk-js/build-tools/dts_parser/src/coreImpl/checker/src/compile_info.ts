/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, softwarecheck{  }
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import ts from 'typescript';
import { ApiResultSimpleInfo, ApiResultInfo } from '../../../typedef/checker/result_type';

export class AddErrorLogs {
  /**
   * 按照格式生成错误信息
   * @param { number } id -error message id
   * @param { number } level -error level
   * @param { string } filePath -error message file path
   * @param { string } location -error message location
   * @param { string } errorType -error message wrong type
   * @param { string } apiType -error message log type
   * @param { number } version -error message version
   * @param { string } apiName -error message api name
   * @param { string } apiFullText -error message api text
   * @param { string } message -error infomation
   * @param { ApiResultSimpleInfo[] }  checkErrorInfos -array for storing error information
   */
  static addAPICheckErrorLogs(
    id: number,
    level: number,
    filePath: string,
    pos: ts.LineAndCharacter,
    errorType: string,
    apiType: string,
    version: number,
    apiName: string,
    apiFullText: string,
    message: string,
    checkErrorInfos: ApiResultSimpleInfo[],
    checkErrorAllInfos: ApiResultInfo[]
  ): void {
    const location = JSON.stringify(pos.line);
    const errorMessage: string = `API check error of [${errorType}]: ${message}`;
    const apiChecktSimpleErrorLog: ApiResultSimpleInfo = new ApiResultSimpleInfo();
    apiChecktSimpleErrorLog
      .setID(id)
      .setLevel(level)
      .setLocation(location)
      .setFilePath(filePath)
      .setMessage(errorMessage)
      .setApiText(apiFullText);

    const apiCheckErrorLog: ApiResultInfo = new ApiResultInfo();
    apiCheckErrorLog
      .setErrorType(errorType)
      .setLocation(location)
      .setApiType(apiType)
      .setMessage(errorMessage)
      .setVersion(version)
      .setLevel(level)
      .setApiName(apiName)
      .setApiFullText(apiFullText)
      .setBaseName(filePath.substring(filePath.lastIndexOf('/') + 1, filePath.length));
    checkErrorInfos.push(apiChecktSimpleErrorLog);
    checkErrorAllInfos.push(apiCheckErrorLog);
  }
}
