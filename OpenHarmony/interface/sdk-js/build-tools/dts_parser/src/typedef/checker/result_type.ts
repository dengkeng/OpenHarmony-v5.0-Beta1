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

import { ApiDiffType } from '../../typedef/diff/ApiInfoDiff';

/**
 * error message type 
 * @enum { string }
 */
export enum ErrorType {
  UNKNOW_DECORATOR = 'unknow decorator',
  MISSPELL_WORDS = 'misspell words',
  NAMING_ERRORS = 'naming errors',
  UNKNOW_PERMISSION = 'unknow permission',
  UNKNOW_SYSCAP = 'unknow syscap',
  UNKNOW_DEPRECATED = 'unknow deprecated',
  WRONG_ORDER = 'wrong order',
  WRONG_VALUE = 'wrong value',
  WRONG_SCENE = 'wrong scene',
  PARAMETER_ERRORS = 'wrong parameter',
  API_PAIR_ERRORS = 'limited api pair errors',
  FORBIDDEN_WORDS = 'forbidden word',
  API_CHANGE_ERRORS = 'api change errors',
  TS_SYNTAX_ERROR = 'TS syntax error',
  NO_JSDOC = 'No jsdoc',
}

/**
 * error message id
 * @enum { number }
 */
export enum ErrorID {
  UNKNOW_DECORATOR_ID = 0,
  MISSPELL_WORDS_ID = 1,
  NAMING_ERRORS_ID = 2,
  UNKNOW_PERMISSION_ID = 3,
  UNKNOW_SYSCAP_ID = 4,
  UNKNOW_DEPRECATED_ID = 5,
  WRONG_ORDER_ID = 6,
  WRONG_VALUE_ID = 7,
  WRONG_SCENE_ID = 8,
  PARAMETER_ERRORS_ID = 9,
  API_PAIR_ERRORS_ID = 10,
  FORBIDDEN_WORDS_ID = 11,
  API_CHANGE_ERRORS_ID = 12,
  TS_SYNTAX_ERROR_ID = 13,
  NO_JSDOC_ID = 14,
}

/**
 * error type
 * @enum { string }
 */
export enum LogType {
  LOG_API = 'Api',
  LOG_JSDOC = 'JsDoc',
  LOG_FILE = 'File',
}

/**
 * error message level
 * @enum { number }
 */
export enum ErrorLevel {
  HIGH = 3,
  MIDDLE = 2,
  LOW = 1,
}

/**
 * error message infomation
 * @enum { string }
 */
export enum ErrorMessage {
  ERROR_INFO_VALUE_EXTENDS = 'The [extends] tag value is incorrect. Please check if the tag value matches the inherited class name.',
  ERROR_INFO_VALUE_IMPLEMENTS = 'The [implements] tag value is incorrect. Please check if the tag value matches the inherited class name.',
  ERROR_INFO_VALUE_ENUM = 'The [enum] tag type is incorrect. Please check if the tag type is { string } or { number }.',
  ERROR_INFO_VALUE_SINCE = 'The [since] tag value is incorrect. Please check if the tag value is a numerical value.',
  ERROR_INFO_RETURNS = 'The [returns] tag was used incorrectly. The returns tag should not be used when the return type is void.',
  ERROR_INFO_VALUE_RETURNS = 'The [returns] tag type is incorrect. Please check if the tag type is consistent with the return type.',
  ERROR_INFO_VALUE_USEINSTEAD = 'The [useinstead] tag value is incorrect. Please check the usage method.',
  ERROR_INFO_VALUE_TYPE = 'The [type] tag type is incorrect. Please check if the type matches the attribute type.',
  ERROR_INFO_VALUE_DEFAULT = 'The [default] tag value is incorrect. Please supplement the default value.',
  ERROR_INFO_VALUE_PERMISSION = 'The [permission] tag value is incorrect. Please check if the permission field has been configured or update the configuration file.',
  ERROR_INFO_VALUE_DEPRECATED = 'The [deprecated] tag value is incorrect. Please check the usage method.',
  ERROR_INFO_VALUE_SYSCAP = 'The [syscap] tag value is incorrect. Please check if the syscap field is configured.',
  ERROR_INFO_VALUE_NAMESPACE = 'The [namespace] tag value is incorrect. Please check if it matches the namespace name.',
  ERROR_INFO_VALUE_INTERFACE = 'The [interface] label value is incorrect. Please check if it matches the interface name.',
  ERROR_INFO_VALUE_TYPEDEF = 'The [typedef] tag value is incorrect. Please check if it matches the interface name or type content.',
  ERROR_INFO_VALUE_STRUCT = 'The [struct] tag value is incorrect. Please check if it matches the struct name.',
  ERROR_INFO_TYPE_PARAM = 'The type of the [$$] [param] tag is incorrect. Please check if it matches the type of the [$$] parameter.',
  ERROR_INFO_VALUE_PARAM = 'The value of the [$$] [param] tag is incorrect. Please check if it matches the [$$] parameter name.',
  ERROR_INFO_VALUE1_THROWS = 'The type of the [$$] [throws] tag is incorrect. Please fill in [BusinessError].',
  ERROR_INFO_VALUE2_THROWS = 'The type of the [$$] [throws] tag is incorrect. Please check if the tag value is a numerical value.',
  ERROR_INFO_INHERIT = 'It was detected that there is an inheritable label [$$] in the current file, but there are child nodes without this label.',
  ERROR_ORDER = 'JSDoc label order error, please adjust the order of [$$] labels.',
  ERROR_LABELNAME = 'The [$$] tag does not exist. Please use a valid JSDoc tag.',
  ERROR_LOST_LABEL = 'JSDoc tag validity verification failed. Please confirm if the [$$] tag is missing.',
  ERROR_USE = 'JSDoc label validity verification failed. The [$$] label is not allowed. Please check the label usage method.',
  ERROR_MORELABEL = 'JSDoc tag validity verification failed.There are [$$] redundant [$$]. Please check if the tag should be deleted.',
  ERROR_REPEATLABEL = 'The validity verification of the JSDoc tag failed. The [$$] tag is not allowed to be reused, please delete the extra tags.',
  ERROR_USE_INTERFACE = 'The validity verification of the JSDoc tag failed. The [interface] tag and [typedef] tag are not allowed to be used simultaneously. Please confirm the interface class.',
  ERROR_EVENT_NAME_STRING = 'The event name should be string.',
  ERROR_EVENT_NAME_NULL = 'The event name cannot be Null value.',
  ERROR_EVENT_NAME_SMALL_HUMP = "The event name should be named by small hump. (Received ['$$']).",
  ERROR_EVENT_CALLBACK_OPTIONAL = 'The callback parameter of off function should be optional.',
  ERROR_EVENT_CALLBACK_MISSING = 'The off functions of one single event should have at least one callback parameter, and the callback parameter should be the last parameter.',
  ERROR_EVENT_ON_AND_OFF_PAIR = 'The on and off event subscription methods do not appear in pair.',
  ERROR_EVENT_WITHOUT_PARAMETER = 'The event subscription methods should has at least one parameter.',
  ILLEGAL_USE_ANY = 'Illegal [$$] keyword used in the API.',
  ERROR_CHANGES_VERSION = 'Please check if the changed API version number is 10.',
  ERROR_WORD = 'Error words in [$$]: {$$}. please confirm whether it needs to be corrected to a common word.',
  ERROR_NAMING = 'Prohibited word in [$$]:{$$}.The word allowed is [$$].',
  ERROR_SCENARIO = 'Prohibited word in [$$]:{$$} in the [$$] file.',
  ERROR_UPPERCASE_NAME = 'This name [$$] should be named by all uppercase.',
  ERROR_LARGE_HUMP_NAME = 'This name [$$] should be named by large hump.',
  ERROR_SMALL_HUMP_NAME = 'This name [$$] should be named by small hump.',
  ERROR_SMALL_HUMP_NAME_FILE = 'This API file should be named by small hump.',
  ERROR_LARGE_HUMP_NAME_FILE = 'This API file should be named by large hump.',
  ERROR_CHANGES_JSDOC_LEVEL = 'Forbid changes: API defectLevel change to system.',
  ERROR_CHANGES_JSDOC_MODEL = 'Forbid changes: API mode change.',
  ERROR_CHANGES_JSDOC_CARD = 'Forbid changes: API card delete.',
  ERROR_CHANGES_JSDOC_CROSS_PLATFORM = 'Forbid changes: API crossplatform delete.',
  ERROR_CHANGES_JSDOC_ERROR_CODE = 'Forbid changes: API errorcode cannot be created or modified.',
  ERROR_CHANGES_JSDOC_PERMISSION = 'Forbid changes: Permission tag cannot be created or modified.',
  ERROR_CHANGES_API_NAME = 'Forbid changes: API cannot be changed.',
  ERROR_CHANGES_FUNCTION_RETURN_TYPE = 'Forbid changes: Function return type cannot be changed.',
  ERROR_CHANGES_API_PARAM = 'Forbid changes: Parameters cannot be changed.',
  ERROR_CHANGES_PROPERTY = 'Forbid changes: Property cannot be changed.',
  ERROR_CHANGES_CONSTANT = 'Forbid changes: Constant value cannot be changed.',
  ERROR_CHANGES_TYPE_ALIAS = 'Forbid changes: Type alias cannot be changed.',
  ERROR_CHANGES_ENUM_MEMBER = 'Forbid changes: Enum number value cannot be changed.',
  ERROR_CHANGES_API = 'Forbid changes: API cannot be deleted.',
  ERROR_CHANGES_JSDOC_CHANGE = 'Forbid changes: Historical JSDoc cannot be changed.',
  ERROR_CHANGES_JSDOC_NUMBER = 'Forbid changes: API changes must add a new section of JSDoc.',
  ERROR_NO_JSDOC = 'Jsdoc needs to be added to the current API.',
  ERROR_NO_JSDOC_TAG = 'add  tags to the Jsdoc.'
}

export const incompatibleApiDiffTypes: Map<ApiDiffType, ErrorMessage> = new Map([
  [ApiDiffType.PUBLIC_TO_SYSTEM, ErrorMessage.ERROR_CHANGES_JSDOC_LEVEL],
  [ApiDiffType.NA_TO_STAGE, ErrorMessage.ERROR_CHANGES_JSDOC_MODEL],
  [ApiDiffType.NA_TO_FA, ErrorMessage.ERROR_CHANGES_JSDOC_MODEL],
  [ApiDiffType.FA_TO_STAGE, ErrorMessage.ERROR_CHANGES_JSDOC_MODEL],
  [ApiDiffType.STAGE_TO_FA, ErrorMessage.ERROR_CHANGES_JSDOC_MODEL],
  [ApiDiffType.CARD_TO_NA, ErrorMessage.ERROR_CHANGES_JSDOC_CARD],
  [ApiDiffType.CROSS_PLATFORM_TO_NA, ErrorMessage.ERROR_CHANGES_JSDOC_CROSS_PLATFORM],
  [ApiDiffType.ERROR_CODE_NA_TO_HAVE, ErrorMessage.ERROR_CHANGES_JSDOC_ERROR_CODE],
  [ApiDiffType.ERROR_CODE_CHANGE, ErrorMessage.ERROR_CHANGES_JSDOC_ERROR_CODE],
  [ApiDiffType.PERMISSION_NA_TO_HAVE, ErrorMessage.ERROR_CHANGES_JSDOC_PERMISSION],
  [ApiDiffType.PERMISSION_RANGE_SMALLER, ErrorMessage.ERROR_CHANGES_JSDOC_PERMISSION],
  [ApiDiffType.PERMISSION_RANGE_CHANGE, ErrorMessage.ERROR_CHANGES_JSDOC_PERMISSION],
  [ApiDiffType.API_NAME_CHANGE, ErrorMessage.ERROR_CHANGES_API_NAME],
  [ApiDiffType.FUNCTION_RETURN_TYPE_ADD, ErrorMessage.ERROR_CHANGES_FUNCTION_RETURN_TYPE],
  [ApiDiffType.FUNCTION_RETURN_TYPE_CHANGE, ErrorMessage.ERROR_CHANGES_FUNCTION_RETURN_TYPE],
  [ApiDiffType.FUNCTION_PARAM_POS_CHANGE, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.FUNCTION_PARAM_REQUIRED_ADD, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.FUNCTION_PARAM_REDUCE, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.FUNCTION_PARAM_TO_REQUIRED, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.FUNCTION_PARAM_TYPE_CHANGE, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.FUNCTION_PARAM_TYPE_REDUCE, ErrorMessage.ERROR_CHANGES_API_PARAM],
  [ApiDiffType.PROPERTY_READONLY_TO_REQUIRED, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_WRITABLE_TO_UNREQUIRED, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_WRITABLE_TO_REQUIRED, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_TYPE_CHANGE, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_READONLY_ADD, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_WRITABLE_ADD, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.PROPERTY_WRITABLE_REDUCE, ErrorMessage.ERROR_CHANGES_PROPERTY],
  [ApiDiffType.CONSTANT_VALUE_CHANGE, ErrorMessage.ERROR_CHANGES_CONSTANT],
  [ApiDiffType.TYPE_ALIAS_CHANGE, ErrorMessage.ERROR_CHANGES_TYPE_ALIAS],
  [ApiDiffType.TYPE_ALIAS_ADD, ErrorMessage.ERROR_CHANGES_TYPE_ALIAS],
  [ApiDiffType.TYPE_ALIAS_REDUCE, ErrorMessage.ERROR_CHANGES_TYPE_ALIAS],
  [ApiDiffType.ENUM_MEMBER_VALUE_CHANGE, ErrorMessage.ERROR_CHANGES_ENUM_MEMBER],
  [ApiDiffType.REDUCE, ErrorMessage.ERROR_CHANGES_API],
  [ApiDiffType.HISTORICAL_JSDOC_CHANGE, ErrorMessage.ERROR_CHANGES_JSDOC_CHANGE],
  [ApiDiffType.HISTORICAL_API_CHANGE, ErrorMessage.ERROR_CHANGES_JSDOC_NUMBER],
]);

/**
 * online error message format
 */
export class ApiResultSimpleInfo {
  id: number = -1;
  level: number = -1;
  filePath: string = '';
  location: string = '';
  message: string = '';
  type: string = '';
  apiText: string = '';

  setID(id: number): ApiResultSimpleInfo {
    this.id = id;
    return this;
  }

  getID(): number {
    return this.id;
  }

  setLevel(level: number): ApiResultSimpleInfo {
    this.level = level;
    return this;
  }

  getLevel(): number {
    return this.level;
  }

  setLocation(location: string): ApiResultSimpleInfo {
    this.location = location;
    return this;
  }

  getLocation(): string {
    return this.location;
  }

  setFilePath(fileFilePath: string): ApiResultSimpleInfo {
    this.filePath = fileFilePath;
    return this;
  }

  getFilePath(): string {
    return this.filePath;
  }

  setMessage(message: string): ApiResultSimpleInfo {
    this.message = message;
    return this;
  }

  getMessage(): string {
    return this.message;
  }

  setType(type: string): ApiResultSimpleInfo {
    this.type = type;
    return this;
  }

  getType(): string {
    return this.type;
  }

  setApiText(apiText: string): ApiResultSimpleInfo {
    this.apiText = apiText;
    return this;
  }

  getApiText(): string {
    return this.apiText;
  }
}

/**
 * local excel table error message format
 */
export class ApiResultInfo {
  errorType: string = '';
  location: string = '';
  apiType: string = '';
  message: string = '';
  version: number = -1;
  level: number = -1;
  apiName: string = '';
  apiFullText: string = '';
  baseName: string = '';

  setErrorType(errorType: string): ApiResultInfo {
    this.errorType = errorType;
    return this;
  }

  getErrorType(): string {
    return this.errorType;
  }

  setLocation(location: string): ApiResultInfo {
    this.location = location;
    return this;
  }

  getLocation(): string {
    return this.location;
  }
  setApiType(apiType: string): ApiResultInfo {
    this.apiType = apiType;
    return this;
  }

  getApiType(): string {
    return this.apiType;
  }

  setMessage(message: string): ApiResultInfo {
    this.message = message;
    return this;
  }

  getMessage(): string {
    return this.message;
  }

  setVersion(version: number): ApiResultInfo {
    this.version = version;
    return this;
  }

  getVersion(): number {
    return this.version;
  }

  setLevel(level: number): ApiResultInfo {
    this.level = level;
    return this;
  }

  getLevel(): number {
    return this.level;
  }

  setApiName(apiName: string): ApiResultInfo {
    this.apiName = apiName;
    return this;
  }

  getApiName(): string {
    return this.apiName;
  }

  setApiFullText(apiFullText: string): ApiResultInfo {
    this.apiFullText = apiFullText;
    return this;
  }

  getApiFullText(): string {
    return this.apiFullText;
  }
  setBaseName(baseName: string): ApiResultInfo {
    this.baseName = baseName;
    return this;
  }

  getBaseName(): string {
    return this.baseName;
  }
}

/**
 * error message format
 */
export interface ErrorTagFormat {
  state: boolean;
  errorInfo: string;
}

/**
 * permission message format
 */
export interface PermissionData {
  name: string;
  grantMode: string;
  since: number;
  deprecated: string;
  availableLevel: string;
  provisionEnable: boolean;
  distributedSceneEnable: boolean;
  label: string;
  description: string;
}

/**
 * naming dictionary format
 */
export interface NameDictionaryType {
  badWord: string;
  suggestion: string;
  ignore: string[];
}

/**
 * naming dictionary format for file
 */
export interface NameScenarioType {
  word: string;
  files: string[];
}

/**
 * error message format
 */
export class ApiResultMessage {
  analyzerName: string = 'apiengine';
  buggyFilePath: string = '';
  codeContextStaerLine: string = '';
  defectLevel: number = -1;
  defectType: string = '';
  description: string = '';
  language: string = 'ts';
  mainBuggyCode: string = '';
  mainBuggyLine: string = '';

  setLocation(codeContextStaerLine: string): ApiResultMessage {
    this.codeContextStaerLine = codeContextStaerLine;
    return this;
  }

  getLocation(): string {
    return this.codeContextStaerLine;
  }

  setLevel(defectLevel: number): ApiResultMessage {
    this.defectLevel = defectLevel;
    return this;
  }

  getLevel(): number {
    return this.defectLevel;
  }

  setType(defectType: string): ApiResultMessage {
    this.defectType = defectType;
    return this;
  }

  getType(): string {
    return this.defectType;
  }

  setFilePath(fileFilePath: string): ApiResultMessage {
    this.buggyFilePath = fileFilePath;
    return this;
  }

  getFilePath(): string {
    return this.buggyFilePath;
  }

  setMessage(description: string): ApiResultMessage {
    this.description = description;
    return this;
  }

  getMessage(): string {
    return this.description;
  }
  setMainBuggyCode(mainBuggyCode: string): ApiResultMessage {
    this.mainBuggyCode = mainBuggyCode;
    return this;
  }

  getMainBuggyCode(): string {
    return this.mainBuggyCode;
  }

  setMainBuggyLine(mainBuggyLine: string): ApiResultMessage {
    this.mainBuggyLine = mainBuggyLine;
    return this;
  }

  getMainBuggyLine(): string {
    return this.mainBuggyLine;
  }
}
