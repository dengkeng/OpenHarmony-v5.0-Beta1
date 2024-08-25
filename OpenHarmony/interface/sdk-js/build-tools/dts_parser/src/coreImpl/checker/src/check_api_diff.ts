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

import path from 'path';
import fs from 'fs';
import { FilesMap, Parser } from '../../parser/parser';
import { DiffHelper } from '../../diff/diff';
import { FileUtils } from '../../../utils/FileUtils';
import { BasicDiffInfo } from '../../../typedef/diff/ApiInfoDiff';
import { AddErrorLogs } from './compile_info';
import { compositiveResult, compositiveLocalResult } from '../../../utils/checkUtils';
import {
  ErrorType,
  ErrorID,
  LogType,
  ErrorLevel,
  ErrorMessage,
  incompatibleApiDiffTypes,
} from '../../../typedef/checker/result_type';
import { ApiDiffType } from '../../../typedef/diff/ApiInfoDiff';

export class ApiChangeCheck {
  static checkApiChange(prId?: string): void {
    const rootDir = path.resolve(
      FileUtils.getBaseDirName(),
      `../../../../../Archive/patch_info/openharmony_interface_sdk-js_${prId}`
    );
    if (!fs.existsSync(rootDir)) {
      return;
    }
    const oldFileDir: string = path.resolve(rootDir, './old');
    const newFileDir: string = path.resolve(rootDir, './new');

    const status: fs.Stats = fs.statSync(oldFileDir);
    let diffInfos: BasicDiffInfo[] = [];
    if (status.isDirectory()) {
      const oldSDKApiMap: FilesMap = Parser.parseDir(oldFileDir);
      const newSDKApiMap: FilesMap = Parser.parseDir(newFileDir);
      diffInfos = DiffHelper.diffSDK(oldSDKApiMap, newSDKApiMap, true);
    } else {
      const oldSDKApiMap: FilesMap = Parser.parseFile(path.resolve(oldFileDir, '..'), oldFileDir);
      const newSDKApiMap: FilesMap = Parser.parseFile(path.resolve(newFileDir, '..'), newFileDir);
      diffInfos = DiffHelper.diffSDK(oldSDKApiMap, newSDKApiMap, true);
    }
    diffInfos.forEach((diffInfo: BasicDiffInfo) => {
      if (diffInfo.getIsCompatible() !== false) {
        return;
      }
      const errorInfo: ErrorMessage | undefined = incompatibleApiDiffTypes.get(diffInfo.getDiffType());
      if (diffInfo.getDiffType() === ApiDiffType.REDUCE) {
        const dtsName = path.basename(diffInfo.getOldDtsName());
        AddErrorLogs.addAPICheckErrorLogs(
          ErrorID.API_CHANGE_ERRORS_ID,
          ErrorLevel.MIDDLE,
          dtsName,
          diffInfo.getOldPos(),
          ErrorType.API_CHANGE_ERRORS,
          LogType.LOG_API,
          -1,
          diffInfo.getOldApiName(),
          diffInfo.getOldApiDefinedText(),
          errorInfo as string,
          compositiveResult,
          compositiveLocalResult
        );
      } else {
        const dtsName = path.basename(diffInfo.getNewDtsName());
        AddErrorLogs.addAPICheckErrorLogs(
          ErrorID.API_CHANGE_ERRORS_ID,
          ErrorLevel.MIDDLE,
          dtsName,
          diffInfo.getOldPos(),
          ErrorType.API_CHANGE_ERRORS,
          LogType.LOG_API,
          -1,
          diffInfo.getNewApiName(),
          diffInfo.getNewApiDefinedText(),
          errorInfo as string,
          compositiveResult,
          compositiveLocalResult
        );
      }
    });
  }
}
