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
import {
  ErrorTagFormat,
  NameDictionaryType,
  NameScenarioType,
  ErrorMessage,
} from '../../../typedef/checker/result_type';
import { ApiInfo } from '../../../typedef/parser/ApiInfoDefination';
import { Comment } from '../../../typedef/parser/Comment';
import { CommonFunctions } from '../../../utils/checkUtils';
const nameDictionary = require('../config/name_dictionary.json');
const nameScenarioScope = require('../config/name_scenario_scope.json');

export class ApiNamingCheck {
  /**
   * Check if the Api name is correct.
   * @param { Comment.JsDocInfo } apiJsdoc -api jsdoc all infomation
   * @returns { boolean }
   */
  static namingCheck(singleApi: ApiInfo): ErrorTagFormat {
    const tagNameCheckResult: ErrorTagFormat = {
      state: true,
      errorInfo: '',
    };
    const jsDocInfo: Comment.JsDocInfo[] = singleApi.getJsDocInfos();
    const publishVersion: string = jsDocInfo[0].getSince();
    const apiVersionToBeVerified: string = CommonFunctions.getCheckApiVersion();
    const lowIdentifier: string = singleApi.getDefinedText().toLowerCase();
    if (publishVersion === apiVersionToBeVerified) {
      ApiNamingCheck.checkApiNamingWords(lowIdentifier, tagNameCheckResult);
      ApiNamingCheck.checkApiNamingScenario(lowIdentifier, tagNameCheckResult, singleApi);
    }
    return tagNameCheckResult;
  }

  /**
   *
   * @param { string } lowIdentifier
   * @param { ErrorTagFormat } tagNameCheckResult
   */
  static checkApiNamingWords(lowIdentifier: string, tagNameCheckResult: ErrorTagFormat): void {
    const lowercaseNamingMap: Map<string, NameDictionaryType> = ApiNamingCheck.getlowercaseNamingMap();
    for (const [key, value] of lowercaseNamingMap) {
      const prohibitedWordIndex: number = lowIdentifier.indexOf(key);
      if (prohibitedWordIndex === -1) {
        continue;
      }
      const lowercaseIgnoreWordArr: string[] = value.ignore.map((word: string) => word.toLowerCase());
      const internalWord: string = lowIdentifier.substring(prohibitedWordIndex, prohibitedWordIndex + key.length);
      if (lowercaseIgnoreWordArr.length === 0) {
        tagNameCheckResult.state = false;
        tagNameCheckResult.errorInfo = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_NAMING, [
          lowIdentifier,
          internalWord,
          value.suggestion,
        ]);
        break;
      } else {
        const isIgnoreWord: boolean = ApiNamingCheck.checkIgnoreWord(lowercaseIgnoreWordArr, lowIdentifier);
        if (isIgnoreWord === false) {
          tagNameCheckResult.state = false;
          tagNameCheckResult.errorInfo = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_NAMING, [
            lowIdentifier,
            internalWord,
            value.suggestion,
          ]);
        }
      }
    }
  }

  /**
   *
   * @param {string} lowIdentifier
   * @param {ErrorTagFormat} tagNameCheckResult
   * @param {ApiInfo} singleApi
   */
  static checkApiNamingScenario(lowIdentifier: string, tagNameCheckResult: ErrorTagFormat, singleApi: ApiInfo): void {
    const lowercaseNamingScenarioMap = ApiNamingCheck.getlowercaseNamingScenarioMap();
    for (const [key, value] of lowercaseNamingScenarioMap) {
      const prohibitedWordIndex: number = lowIdentifier.indexOf(key);
      if (prohibitedWordIndex !== -1 && !ApiNamingCheck.isInAllowedFiles(value.files, singleApi.getFilePath())) {
        const internalWord = lowIdentifier.substring(prohibitedWordIndex, key.length);
        tagNameCheckResult.state = false;
        tagNameCheckResult.errorInfo = CommonFunctions.createErrorInfo(ErrorMessage.ERROR_SCENARIO, [
          lowIdentifier,
          internalWord,
          singleApi.getFilePath(),
        ]);
      }
    }
  }

  /**
   *
   * @returns
   */
  static getlowercaseNamingMap(): Map<string, NameDictionaryType> {
    const lowercaseNamingMap: Map<string, NameDictionaryType> = new Map();
    for (const item of nameDictionary) {
      const namingKey: string = item.badWord.toLowerCase();
      const namingValue: NameDictionaryType = item;
      lowercaseNamingMap.set(namingKey, namingValue);
    }
    return lowercaseNamingMap;
  }

  /**
   *
   * @param { string[] } lowercaseIgnoreWordArr
   * @param { string }lowIdentifier
   * @returns { boolean }
   */
  static checkIgnoreWord(lowercaseIgnoreWordArr: string[], lowIdentifier: string): boolean {
    let isIgnoreWord: boolean = false;
    for (let i = 0; i < lowercaseIgnoreWordArr.length; i++) {
      if (lowercaseIgnoreWordArr[i] && lowIdentifier.indexOf(lowercaseIgnoreWordArr[i]) !== -1) {
        isIgnoreWord = true;
        break;
      }
    }
    return isIgnoreWord;
  }

  /**
   *
   * @returns { Map<string, NameScenarioType> }
   */
  static getlowercaseNamingScenarioMap(): Map<string, NameScenarioType> {
    const lowercaseNamingScenarioMap: Map<string, NameScenarioType> = new Map();
    for (const item of nameScenarioScope) {
      const scenarioKey = item.word.toLowerCase();
      const scenarioValue: NameScenarioType = item;
      lowercaseNamingScenarioMap.set(scenarioKey, scenarioValue);
    }
    return lowercaseNamingScenarioMap;
  }

  /**
   *
   * @param { string[] } files
   * @param { string } fileName
   * @returns { boolean }
   */
  static isInAllowedFiles(files: string[], fileName: string): boolean {
    for (const item of files) {
      const pattern: RegExp = new RegExp(item);
      pattern.test(fileName);
      if (pattern.test(fileName)) {
        return true;
      }
    }
    return false;
  }
}
