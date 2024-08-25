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
import { ApiResultSimpleInfo, ApiResultMessage } from '../../typedef/checker/result_type';
import { Check } from './src/api_check_plugin';
import { LogUtil } from '../../utils/logUtil';
import { GenerateFile } from '../../utils/checkUtils';
import { compositiveResult, compositiveLocalResult, apiCheckResult } from '../../utils/checkUtils';
import { DOC, DEFINE, CHANEGE } from './config/api_check_config.json';

/**
 * local entrance
 */
export class LocalEntry {
  static checkEntryLocal(filePathArr: string[], fileRuleArr: string[], output: string, excel: string): ApiResultMessage[] {
    let allResult: ApiResultMessage[] = apiCheckResult;
    try {
      Check.scanEntry(filePathArr);
      LocalEntry.maskAlarm(compositiveResult, fileRuleArr);
    } catch (error) {
      LogUtil.e('API_CHECK_ERROR', error);
    } finally {
      GenerateFile.writeFile(apiCheckResult, output, {});
      if (excel === 'true') {
        GenerateFile.writeExcelFile(compositiveLocalResult);
      }
    }
    return allResult;
  }

  static maskAlarm(allResultInfo: ApiResultSimpleInfo[], fileRuleArr: string[]): void {
    const localScan: boolean = (fileRuleArr.length === 1 && fileRuleArr[0] === 'all') ? true : false;
    const apiCheckInfos: Map<string, string> = new Map(Object.entries({ ...DOC, ...DEFINE, ...CHANEGE }));
    let apiCheckAdmissiveSet: Set<string> = new Set();
    if (localScan) {
      apiCheckAdmissiveSet = new Set([...apiCheckInfos.values()]);
    } else {
      fileRuleArr.forEach((apiCheckItem: string) => {
        const apiCheckItemMessage: string | undefined = apiCheckInfos.get(apiCheckItem);
        if (apiCheckItemMessage) {
          apiCheckAdmissiveSet.add(apiCheckItemMessage);
        }
      });
    }
    const maskResult: ApiResultSimpleInfo[] = LocalEntry.filterAllResultInfo(allResultInfo,
      apiCheckInfos, apiCheckAdmissiveSet);
    maskResult.forEach(resultItem => {
      const apiChecktErrorLog: ApiResultMessage = new ApiResultMessage();
      apiChecktErrorLog
        .setFilePath(resultItem.filePath)
        .setLocation(resultItem.location)
        .setLevel(resultItem.level)
        .setType(resultItem.type)
        .setMessage(resultItem.message)
        .setMainBuggyCode(resultItem.apiText)
        .setMainBuggyLine(resultItem.location);
      apiCheckResult.push(apiChecktErrorLog);
    });
  }

  static filterAllResultInfo(allResultInfo: ApiResultSimpleInfo[], apiCheckInfos: Map<string, string>,
    apiCheckAdmissiveSet: Set<string>): ApiResultSimpleInfo[] {
    return allResultInfo.filter((resultItem: ApiResultSimpleInfo) => {
      let resultItemInfo: string = resultItem.message.replace(/API check error of \[.*\]: /g, '');
      const regex1 = /Prohibited word in \[.*\]:{option}.The word allowed is \[.*\]\./g;
      const regex2 = /Prohibited word in \[.*\]:{ability} in the \[.*\] file\./g;
      if (/\d/g.test(resultItemInfo)) {
        resultItemInfo = resultItemInfo.replace(/\d+/g, '1');
      }
      if (regex1.test(resultItemInfo)) {
        resultItemInfo = JSON.stringify(apiCheckInfos.get('API_DEFINE_NAME_01')).replace(/\"/g, '');
      }
      if (regex2.test(resultItemInfo)) {
        resultItemInfo = JSON.stringify(apiCheckInfos.get('API_DEFINE_NAME_02')).replace(/\"/g, '');
      }
      if (/This name \[.*\] should be named by/g.test(resultItemInfo)) {
        resultItemInfo = resultItemInfo.replace(/\[.*\]/g, '[XXXX]');
      }
      if (apiCheckAdmissiveSet.has(resultItemInfo)) {
        const key: string = LocalEntry.filterApiCheckInfos(apiCheckInfos, resultItemInfo);
        if (key !== '') {
          resultItem.setType(key);
        }
      }
      return apiCheckAdmissiveSet.has(resultItemInfo);
    });
  }

  static filterApiCheckInfos(apiCheckInfos: Map<string, string>, resultItemInfo: string): string {
    for (let [key, value] of apiCheckInfos.entries()) {
      if (value === resultItemInfo) {
        return key;
      }
    }
    return '';
  }
}
