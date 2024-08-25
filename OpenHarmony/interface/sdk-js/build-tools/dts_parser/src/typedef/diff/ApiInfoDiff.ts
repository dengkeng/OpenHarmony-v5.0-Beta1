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
import { ApiInfo, MethodInfo } from '../parser/ApiInfoDefination';
import { Comment } from '../parser/Comment';
import { NumberConstant } from '../../utils/Constant';
export class BasicDiffInfo {
  private static EMPTY = '';
  //apiType
  apiType: string = BasicDiffInfo.EMPTY;
  statusCode: ApiStatusCode = ApiStatusCode.DEFAULT;
  // parentModuleName: string = 'global';
  //旧数据
  oldApiDefinedText: string = BasicDiffInfo.EMPTY;
  //新数据
  newApiDefinedText: string = BasicDiffInfo.EMPTY;
  //旧apiName
  oldApiName: string = BasicDiffInfo.EMPTY;
  //新apiName
  newApiName: string = BasicDiffInfo.EMPTY;
  //旧dts文件名
  oldDtsName: string = BasicDiffInfo.EMPTY;
  //新dts文件名
  newDtsName: string = BasicDiffInfo.EMPTY;
  //diff节点类型
  diffType: ApiDiffType = ApiDiffType.DEFAULT;
  //diff节点类型描述
  diffMessage: string = '';
  // 获取json的url
  changeLogUrl: string = '';
  // json中的数据
  changeLogs: string[] = [];
  //是否兼容
  isCompatible: boolean = true;
  //层次关系
  oldHierarchicalRelations: string[] = [];
  //层次关系
  newHierarchicalRelations: string[] = [];
  // api所在的位置信息
  oldPos: ts.LineAndCharacter = { line: -1, character: -1 };
  // api所在的位置信息
  newPos: ts.LineAndCharacter = { line: -1, character: -1 };
  oldDescription: string = '';
  newDescription: string = '';
  //syscap中用于区分子系统的字段
  oldSyscapField: string = '';
  newSyscapField: string = '';
  //kit信息
  oldKitInfo: string = '';
  newKitInfo:string = '';

  setApiType(apiType: string): BasicDiffInfo {
    if (apiType) {
      this.apiType = apiType;
    } else {
      this.apiType = BasicDiffInfo.EMPTY;
    }
    return this;
  }

  getApiType(): string {
    return this.apiType;
  }

  getStatusCode(): ApiStatusCode {
    return this.statusCode;
  }

  setStatusCode(statusCode: ApiStatusCode): BasicDiffInfo {
    this.statusCode = statusCode;
    return this;
  }

  setOldApiDefinedText(oldApiDefinedText: string): BasicDiffInfo {
    this.oldApiDefinedText = oldApiDefinedText;
    return this;
  }

  getOldApiDefinedText(): string {
    return this.oldApiDefinedText;
  }

  setNewApiDefinedText(newApiDefinedText: string): BasicDiffInfo {
    this.newApiDefinedText = newApiDefinedText;
    return this;
  }

  getNewApiDefinedText(): string {
    return this.newApiDefinedText;
  }

  setOldApiName(oldApiName: string): BasicDiffInfo {
    this.oldApiName = oldApiName;
    return this;
  }

  getOldApiName(): string {
    return this.oldApiName;
  }

  setNewApiName(newApiName: string): BasicDiffInfo {
    this.newApiName = newApiName;
    return this;
  }

  getNewApiName(): string {
    return this.newApiName;
  }

  setOldDtsName(oldDtsName: string): BasicDiffInfo {
    this.oldDtsName = oldDtsName;
    return this;
  }

  getOldDtsName(): string {
    return this.oldDtsName;
  }

  setNewDtsName(newDtsName: string): BasicDiffInfo {
    this.newDtsName = newDtsName;
    return this;
  }

  getNewDtsName(): string {
    return this.newDtsName;
  }

  setDiffType(diffType: ApiDiffType): BasicDiffInfo {
    this.diffType = diffType;
    return this;
  }

  getDiffType(): ApiDiffType {
    return this.diffType;
  }

  setDiffMessage(diffMessage: string): BasicDiffInfo {
    this.diffMessage = diffMessage;
    return this;
  }

  getDiffMessage(): string {
    return this.diffMessage;
  }

  setChangeLogUrl(changeLogUrl: string): BasicDiffInfo {
    this.changeLogUrl = changeLogUrl;
    return this;
  }

  getChangeLogUrl(): string {
    return this.changeLogUrl;
  }

  addChangeLogs(changeLogs: string): BasicDiffInfo {
    this.changeLogs.push(changeLogs);
    return this;
  }

  getChangeLogs(): string[] {
    return this.changeLogs;
  }

  setIsCompatible(isCompatible: boolean): BasicDiffInfo {
    this.isCompatible = isCompatible;
    return this;
  }

  getIsCompatible(): boolean {
    return this.isCompatible;
  }

  setOldHierarchicalRelations(oldHierarchicalRelations: string[]): BasicDiffInfo {
    this.oldHierarchicalRelations = oldHierarchicalRelations;
    return this;
  }

  getOldHierarchicalRelations(): string[] {
    return this.oldHierarchicalRelations;
  }

  setNewHierarchicalRelations(newHierarchicalRelations: string[]): BasicDiffInfo {
    this.newHierarchicalRelations = newHierarchicalRelations;
    return this;
  }

  getNewHierarchicalRelations(): string[] {
    return this.newHierarchicalRelations;
  }

  setOldPos(oldPos: ts.LineAndCharacter): BasicDiffInfo {
    this.oldPos = oldPos;
    return this;
  }

  getOldPos(): ts.LineAndCharacter {
    return this.oldPos;
  }

  setNewPos(newPos: ts.LineAndCharacter): BasicDiffInfo {
    this.newPos = newPos;
    return this;
  }

  getNewPos(): ts.LineAndCharacter {
    return this.newPos;
  }

  getOldDescription(): string {
    return this.oldDescription;
  }

  setOldDescription(oldDescription: string): BasicDiffInfo {
    this.oldDescription = oldDescription;
    return this;
  }

  getNewDescription(): string {
    return this.newDescription;
  }

  setNewDescription(newDescription: string): BasicDiffInfo {
    this.newDescription = newDescription;
    return this;
  }

  getOldApiInfo(): string {
    return '';
  }

  getParentModuleName(hierarchicalRelations: string[]): string {
    let parentModuleName: string = 'global';
    if (hierarchicalRelations.length > NumberConstant.RELATION_LENGTH) {
      parentModuleName = hierarchicalRelations[hierarchicalRelations.length - NumberConstant.RELATION_LENGTH];
    }
    return parentModuleName;
  }

  setOldSyscapField(syscapField: string): BasicDiffInfo {
    this.oldSyscapField = syscapField;
    return this;
  }

  getOldSyscapField(): string {
    return this.oldSyscapField;
  }

  setNewSyscapField(syscapField: string): BasicDiffInfo {
    this.newSyscapField = syscapField;
    return this;
  }

  getNewSyscapField(): string {
    return this.newSyscapField;
  }

  setOldKitInfo(kitInfo: string) {
    this.oldKitInfo = kitInfo;
    return this;
  }

  getOldKitInfo(): string {
    return this.oldKitInfo;
  }

  setNewKitInfo(kitInfo: string) {
    this.newKitInfo = kitInfo;
    return this;
  }

  getNewKitInfo(): string {
    return this.newKitInfo;
  }
}

export class DiffTypeInfo {
  private diffType: ApiDiffType = ApiDiffType.DEFAULT; //diff节点类型
  private statusCode: ApiStatusCode = ApiStatusCode.DEFAULT;
  private oldMessage: string = ''; //旧版本信息
  private newMessage: string = ''; //新版本信息

  constructor(statusCode?: ApiStatusCode, diffType?: ApiDiffType, oldMessage?: string, newMessage?: string) {
    if (statusCode !== undefined) {
      this.setStatusCode(statusCode);
    }
    if (diffType) {
      this.setDiffType(diffType);
    }
    if (oldMessage) {
      this.setOldMessage(oldMessage);
    }
    if (newMessage) {
      this.setNewMessage(newMessage);
    }
  }

  getStatusCode(): ApiStatusCode {
    return this.statusCode;
  }

  setStatusCode(statusCode: ApiStatusCode): DiffTypeInfo {
    this.statusCode = statusCode;
    return this;
  }

  getDiffType(): ApiDiffType {
    return this.diffType;
  }

  setDiffType(diffType: ApiDiffType): DiffTypeInfo {
    this.diffType = diffType;
    return this;
  }

  getOldMessage(): string {
    return this.oldMessage;
  }
  setOldMessage(oldMessage: string): DiffTypeInfo {
    this.oldMessage = oldMessage;
    return this;
  }

  getNewMessage(): string {
    return this.newMessage;
  }
  setNewMessage(newMessage: string): DiffTypeInfo {
    this.newMessage = newMessage;
    return this;
  }
}
export interface JsDocDiffProcessor {
  (oldJsDocInfo: Comment.JsDocInfo | undefined, newJsDocInfo: Comment.JsDocInfo | undefined): DiffTypeInfo | undefined;
}

export interface ApiSceneDiffProcessor {
  (oldApiInfo: ApiInfo, newApiInfo: ApiInfo): DiffTypeInfo | undefined;
}
export interface ApiScenesDiffProcessor {
  (oldApiInfo: MethodInfo, newApiInfo: MethodInfo): DiffTypeInfo[] | DiffTypeInfo | undefined;
}

export interface ApiNodeDiffProcessor {
  (oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void;
}

export enum ApiStatusCode {
  DEFAULT = -1,
  DELETE = 0,
  DELETE_DTS = 1,
  DELETE_CLASS = 2,
  NEW_API = 3,
  VERSION_CHNAGES = 4,
  DEPRECATED_CHNAGES = 5,
  NEW_ERRORCODE = 6,
  ERRORCODE_CHANGES = 7,
  SYSCAP_CHANGES = 8,
  SYSTEM_API_CHNAGES = 9,
  PERMISSION_DELETE = 10,
  PERMISSION_NEW = 11,
  PERMISSION_CHANGES = 12,
  MODEL_CHNAGES = 13,
  TYPE_CHNAGES = 14,
  CLASS_CHANGES = 15,
  FUNCTION_CHANGES = 16,
  CHANGELOG = 17,
  DTS_CHANGED = 18,
  FORM_CHANGED = 19,
  CROSSPLATFORM_CHANGED = 20,
  NEW_DTS = 21,
  NEW_CLASS = 22,
  NEW_DECORATOR = 23,
  DELETE_DECORATOR = 24,
  KIT_CHANGE = 26,
}

export enum ApiDiffType {
  DEFAULT = 0,
  SYSTEM_TO_PUBLIC,
  PUBLIC_TO_SYSTEM,
  NA_TO_STAGE,
  NA_TO_FA,
  FA_TO_STAGE,
  STAGE_TO_FA,
  STAGE_TO_NA,
  FA_TO_NA,
  NA_TO_CARD,
  CARD_TO_NA,
  NA_TO_CROSS_PLATFORM,
  CROSS_PLATFORM_TO_NA,
  SYSCAP_NA_TO_HAVE,
  SYSCAP_HAVE_TO_NA,
  SYSCAP_A_TO_B,
  DEPRECATED_NA_TO_HAVE,
  DEPRECATED_HAVE_TO_NA,
  DEPRECATED_A_TO_B,
  ERROR_CODE_NA_TO_HAVE,
  ERROR_CODE_ADD,
  ERROR_CODE_REDUCE,
  ERROR_CODE_CHANGE,
  PERMISSION_NA_TO_HAVE,
  PERMISSION_HAVE_TO_NA,
  /** 增加or或减少and权限 权限范围变大 */
  PERMISSION_RANGE_BIGGER,
  /** 减少or或增加and权限 权限范围变小 */
  PERMISSION_RANGE_SMALLER,
  /** 同时存在权限范围变大和变小的情况 */
  PERMISSION_RANGE_CHANGE,
  /** type范围变大 */
  TYPE_RANGE_BIGGER,
  /** type范围减小 */
  TYPE_RANGE_SMALLER,
  /** type范围改变，既有变大情况也有变小情况 */
  TYPE_RANGE_CHANGE,
  API_NAME_CHANGE,
  FUNCTION_RETURN_TYPE_ADD,
  FUNCTION_RETURN_TYPE_REDUCE,
  FUNCTION_RETURN_TYPE_CHANGE,
  FUNCTION_PARAM_POS_CHANGE,
  /** 函数新增可选参数 */
  FUNCTION_PARAM_UNREQUIRED_ADD,
  /** 函数新增必选参数 */
  FUNCTION_PARAM_REQUIRED_ADD,
  FUNCTION_PARAM_REDUCE,
  /** 函数中的必选参数变为可选参数 */
  FUNCTION_PARAM_TO_UNREQUIRED,
  /** 函数中的可选参数变为必选参数 */
  FUNCTION_PARAM_TO_REQUIRED,
  FUNCTION_PARAM_NAME_CHANGE,
  FUNCTION_PARAM_TYPE_CHANGE,
  /**  函数的参数类型范围扩大 */
  FUNCTION_PARAM_TYPE_ADD,
  /**  函数的参数类型范围缩小 */
  FUNCTION_PARAM_TYPE_REDUCE,
  PROPERTY_READONLY_TO_UNREQUIRED,
  PROPERTY_READONLY_TO_REQUIRED,
  PROPERTY_WRITABLE_TO_UNREQUIRED,
  PROPERTY_WRITABLE_TO_REQUIRED,
  PROPERTY_TYPE_CHANGE,
  PROPERTY_READONLY_ADD,
  PROPERTY_READONLY_REDUCE,
  PROPERTY_WRITABLE_ADD,
  PROPERTY_WRITABLE_REDUCE,
  CONSTANT_VALUE_CHANGE,
  TYPE_ALIAS_CHANGE,
  TYPE_ALIAS_ADD,
  TYPE_ALIAS_REDUCE,
  ENUM_MEMBER_VALUE_CHANGE,
  ADD,
  REDUCE,
  NEW_DECORATOR,
  DELETE_DECORATOR,
  SINCE_VERSION_NA_TO_HAVE,
  SINCE_VERSION_HAVE_TO_NA,
  SINCE_VERSION_A_TO_B,
  HISTORICAL_JSDOC_CHANGE,
  HISTORICAL_API_CHANGE,
  KIT_CHANGE,
}

export const diffTypeMap: Map<ApiDiffType, string> = new Map([
  [ApiDiffType.SYSTEM_TO_PUBLIC, 'API访问级别变更'],
  [ApiDiffType.PUBLIC_TO_SYSTEM, 'API访问级别变更'],
  [ApiDiffType.NA_TO_STAGE, 'API模型切换'],
  [ApiDiffType.NA_TO_FA, 'API模型切换'],
  [ApiDiffType.FA_TO_STAGE, 'API模型切换'],
  [ApiDiffType.STAGE_TO_FA, 'API模型切换'],
  [ApiDiffType.STAGE_TO_NA, 'API模型切换'],
  [ApiDiffType.FA_TO_NA, 'API模型切换'],
  [ApiDiffType.NA_TO_CARD, 'API卡片权限变更'],
  [ApiDiffType.CARD_TO_NA, 'API卡片权限变更'],
  [ApiDiffType.NA_TO_CROSS_PLATFORM, 'API跨平台权限变更'],
  [ApiDiffType.CROSS_PLATFORM_TO_NA, 'API跨平台权限变更'],
  [ApiDiffType.SYSCAP_NA_TO_HAVE, 'syscap变更'],
  [ApiDiffType.SYSCAP_HAVE_TO_NA, 'syscap变更'],
  [ApiDiffType.SYSCAP_A_TO_B, 'syscap变更'],
  [ApiDiffType.DEPRECATED_NA_TO_HAVE, 'API废弃版本变更'],
  [ApiDiffType.DEPRECATED_HAVE_TO_NA, 'API废弃版本变更'],
  [ApiDiffType.DEPRECATED_A_TO_B, 'API废弃版本变更'],
  [ApiDiffType.ERROR_CODE_NA_TO_HAVE, '错误码变更'],
  [ApiDiffType.ERROR_CODE_ADD, '错误码变更'],
  [ApiDiffType.ERROR_CODE_REDUCE, '错误码变更'],
  [ApiDiffType.ERROR_CODE_CHANGE, '错误码变更'],
  [ApiDiffType.PERMISSION_NA_TO_HAVE, '权限变更'],
  [ApiDiffType.PERMISSION_HAVE_TO_NA, '权限变更'],
  [ApiDiffType.PERMISSION_RANGE_BIGGER, '权限变更'],
  [ApiDiffType.PERMISSION_RANGE_SMALLER, '权限变更'],
  [ApiDiffType.PERMISSION_RANGE_CHANGE, '权限变更'],
  [ApiDiffType.TYPE_RANGE_BIGGER, '自定义类型变更'],
  [ApiDiffType.TYPE_RANGE_SMALLER, '自定义类型变更'],
  [ApiDiffType.TYPE_RANGE_CHANGE, '自定义类型变更'],
  [ApiDiffType.API_NAME_CHANGE, 'API名称变更'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_ADD, '函数变更'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_REDUCE, '函数变更'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_CHANGE, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_POS_CHANGE, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_UNREQUIRED_ADD, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_REQUIRED_ADD, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_REDUCE, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_TO_UNREQUIRED, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_TO_REQUIRED, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_NAME_CHANGE, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_CHANGE, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_ADD, '函数变更'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_REDUCE, '函数变更'],
  [ApiDiffType.PROPERTY_READONLY_TO_UNREQUIRED, '属性变更'],
  [ApiDiffType.PROPERTY_READONLY_TO_REQUIRED, '属性变更'],
  [ApiDiffType.PROPERTY_WRITABLE_TO_UNREQUIRED, '属性变更'],
  [ApiDiffType.PROPERTY_WRITABLE_TO_REQUIRED, '属性变更'],
  [ApiDiffType.PROPERTY_TYPE_CHANGE, '属性变更'],
  [ApiDiffType.PROPERTY_READONLY_ADD, '属性变更'],
  [ApiDiffType.PROPERTY_READONLY_REDUCE, '属性变更'],
  [ApiDiffType.PROPERTY_WRITABLE_ADD, '属性变更'],
  [ApiDiffType.PROPERTY_WRITABLE_REDUCE, '属性变更'],
  [ApiDiffType.CONSTANT_VALUE_CHANGE, '常量变更'],
  [ApiDiffType.TYPE_ALIAS_CHANGE, '自定义类型变更'],
  [ApiDiffType.TYPE_ALIAS_ADD, '自定义类型变更'],
  [ApiDiffType.TYPE_ALIAS_REDUCE, '自定义类型变更'],
  [ApiDiffType.ENUM_MEMBER_VALUE_CHANGE, '枚举赋值发生改变'],
  [ApiDiffType.ADD, '新增API'],
  [ApiDiffType.REDUCE, '删除API'],
  [ApiDiffType.DELETE_DECORATOR, '删除装饰器'],
  [ApiDiffType.NEW_DECORATOR, '新增装饰器'],
  [ApiDiffType.SINCE_VERSION_A_TO_B, '起始版本有变化'],
  [ApiDiffType.SINCE_VERSION_HAVE_TO_NA, '起始版本有变化'],
  [ApiDiffType.SINCE_VERSION_NA_TO_HAVE, '起始版本有变化'],
  [ApiDiffType.KIT_CHANGE, 'kit变更'],
]);

export const diffMap: Map<ApiDiffType, string> = new Map([
  [ApiDiffType.SYSTEM_TO_PUBLIC, '从系统API变更为公开API'],
  [ApiDiffType.PUBLIC_TO_SYSTEM, '从公开API变更为系统API'],
  [ApiDiffType.NA_TO_STAGE, '从无模型使用限制到仅在Stage模型下使用'],
  [ApiDiffType.NA_TO_FA, '从无模型使用限制到仅在FA模型下使用'],
  [ApiDiffType.FA_TO_STAGE, '从仅在FA模型下使用到仅在Stage模型下使用'],
  [ApiDiffType.STAGE_TO_FA, '从仅在Stage模型下使用到仅在FA模型下使用'],
  [ApiDiffType.STAGE_TO_NA, '从仅在Stage模型下使用到无模型使用限制'],
  [ApiDiffType.FA_TO_NA, '从仅在FA模型下使用到无模型使用限制'],
  [ApiDiffType.NA_TO_CARD, '从不支持卡片到支持卡片'],
  [ApiDiffType.CARD_TO_NA, '从支持卡片到不支持卡片'],
  [ApiDiffType.NA_TO_CROSS_PLATFORM, '从不支持跨平台到支持跨平台'],
  [ApiDiffType.CROSS_PLATFORM_TO_NA, '从支持跨平台到不支持跨平台'],
  [ApiDiffType.SYSCAP_NA_TO_HAVE, '从没有syscap到有syscap'],
  [ApiDiffType.SYSCAP_HAVE_TO_NA, '从有syscap到没有syscap'],
  [ApiDiffType.SYSCAP_A_TO_B, 'syscap发生改变'],
  [ApiDiffType.DEPRECATED_NA_TO_HAVE, '接口变更为废弃'],
  [ApiDiffType.DEPRECATED_HAVE_TO_NA, '废弃接口变更为不废弃'],
  [ApiDiffType.DEPRECATED_A_TO_B, '接口废弃版本发生变化'],
  [ApiDiffType.ERROR_CODE_NA_TO_HAVE, '错误码从无到有'],
  [ApiDiffType.ERROR_CODE_ADD, '错误码增加'],
  [ApiDiffType.ERROR_CODE_REDUCE, '错误码减少'],
  [ApiDiffType.ERROR_CODE_CHANGE, '错误码的code值发生变化'],
  [ApiDiffType.PERMISSION_NA_TO_HAVE, '权限从无到有'],
  [ApiDiffType.PERMISSION_HAVE_TO_NA, '权限从有到无'],
  [ApiDiffType.PERMISSION_RANGE_BIGGER, '增加or或减少and权限'],
  [ApiDiffType.PERMISSION_RANGE_SMALLER, '减少or或增加and权限'],
  [ApiDiffType.PERMISSION_RANGE_CHANGE, '权限发送改变无法判断范围变化'],
  [ApiDiffType.TYPE_RANGE_BIGGER, '类型范围变大'],
  [ApiDiffType.TYPE_RANGE_SMALLER, '类型范围变小'],
  [ApiDiffType.TYPE_RANGE_CHANGE, '类型范围改变'],
  [ApiDiffType.API_NAME_CHANGE, 'API名称变更'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_ADD, '函数返回值类型扩大'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_REDUCE, '函数返回值类型缩小'],
  [ApiDiffType.FUNCTION_RETURN_TYPE_CHANGE, '函数返回值类型改变'],
  [ApiDiffType.FUNCTION_PARAM_POS_CHANGE, '函数参数位置发生改变'],
  [ApiDiffType.FUNCTION_PARAM_UNREQUIRED_ADD, '函数新增可选参数'],
  [ApiDiffType.FUNCTION_PARAM_REQUIRED_ADD, '函数新增必选参数'],
  [ApiDiffType.FUNCTION_PARAM_REDUCE, '函数删除参数'],
  [ApiDiffType.FUNCTION_PARAM_TO_UNREQUIRED, '函数中的必选参数变为可选参数'],
  [ApiDiffType.FUNCTION_PARAM_TO_REQUIRED, '函数中的可选参数变为必选参数'],
  [ApiDiffType.FUNCTION_PARAM_NAME_CHANGE, '函数中的参数名称发生改变'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_CHANGE, '函数的参数类型变更'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_ADD, '函数的参数类型范围扩大'],
  [ApiDiffType.FUNCTION_PARAM_TYPE_REDUCE, '函数的参数类型范围缩小'],
  [ApiDiffType.PROPERTY_READONLY_TO_UNREQUIRED, '只读属性由必选变为可选'],
  [ApiDiffType.PROPERTY_READONLY_TO_REQUIRED, '只读属性由可选变为必选'],
  [ApiDiffType.PROPERTY_WRITABLE_TO_UNREQUIRED, '可写属性由必选变为可选'],
  [ApiDiffType.PROPERTY_WRITABLE_TO_REQUIRED, '可写属性由可选变为必选'],
  [ApiDiffType.PROPERTY_TYPE_CHANGE, '属性类型发生改变'],
  [ApiDiffType.PROPERTY_READONLY_ADD, '只读属性类型范围扩大'],
  [ApiDiffType.PROPERTY_READONLY_REDUCE, '只读属性类型范围缩小'],
  [ApiDiffType.PROPERTY_WRITABLE_ADD, '可写属性类型范围扩大'],
  [ApiDiffType.PROPERTY_WRITABLE_REDUCE, '可写属性类型范围缩小'],
  [ApiDiffType.CONSTANT_VALUE_CHANGE, '常量值发生改变'],
  [ApiDiffType.TYPE_ALIAS_CHANGE, '自定义类型值直接改变'],
  [ApiDiffType.TYPE_ALIAS_ADD, '自定义类型值范围扩大'],
  [ApiDiffType.TYPE_ALIAS_REDUCE, '自定义类型值范围缩小'],
  [ApiDiffType.ENUM_MEMBER_VALUE_CHANGE, '枚举赋值发生改变'],
  [ApiDiffType.ADD, '新增API'],
  [ApiDiffType.REDUCE, '删除API'],
  [ApiDiffType.DELETE_DECORATOR, '删除装饰器'],
  [ApiDiffType.NEW_DECORATOR, '新增装饰器'],
  [ApiDiffType.SINCE_VERSION_A_TO_B, '起始版本号变更'],
  [ApiDiffType.SINCE_VERSION_HAVE_TO_NA, '起始版本号删除'],
  [ApiDiffType.SINCE_VERSION_NA_TO_HAVE, '起始版本号新增'],
  [ApiDiffType.HISTORICAL_JSDOC_CHANGE, '历史版本jsdoc变更'],
  [ApiDiffType.HISTORICAL_API_CHANGE, '历史版本API变更'],
  [ApiDiffType.KIT_CHANGE, 'kit变更'],
]);

export const incompatibleApiDiffTypes: Set<ApiDiffType> = new Set([
  ApiDiffType.PUBLIC_TO_SYSTEM,
  ApiDiffType.NA_TO_STAGE,
  ApiDiffType.NA_TO_FA,
  ApiDiffType.FA_TO_STAGE,
  ApiDiffType.STAGE_TO_FA,
  ApiDiffType.CARD_TO_NA,
  ApiDiffType.CROSS_PLATFORM_TO_NA,
  ApiDiffType.ERROR_CODE_NA_TO_HAVE,
  ApiDiffType.ERROR_CODE_CHANGE,
  ApiDiffType.PERMISSION_NA_TO_HAVE,
  ApiDiffType.PERMISSION_RANGE_SMALLER,
  ApiDiffType.PERMISSION_RANGE_CHANGE,
  ApiDiffType.API_NAME_CHANGE,
  ApiDiffType.FUNCTION_RETURN_TYPE_ADD,
  ApiDiffType.FUNCTION_RETURN_TYPE_CHANGE,
  ApiDiffType.FUNCTION_PARAM_POS_CHANGE,
  ApiDiffType.FUNCTION_PARAM_REQUIRED_ADD,
  ApiDiffType.FUNCTION_PARAM_REDUCE,
  ApiDiffType.FUNCTION_PARAM_TO_REQUIRED,
  ApiDiffType.FUNCTION_PARAM_TYPE_CHANGE,
  ApiDiffType.FUNCTION_PARAM_TYPE_REDUCE,
  ApiDiffType.PROPERTY_READONLY_TO_REQUIRED,
  ApiDiffType.PROPERTY_WRITABLE_TO_UNREQUIRED,
  ApiDiffType.PROPERTY_WRITABLE_TO_REQUIRED,
  ApiDiffType.PROPERTY_TYPE_CHANGE,
  ApiDiffType.PROPERTY_READONLY_ADD,
  ApiDiffType.PROPERTY_WRITABLE_ADD,
  ApiDiffType.PROPERTY_WRITABLE_REDUCE,
  ApiDiffType.CONSTANT_VALUE_CHANGE,
  ApiDiffType.TYPE_ALIAS_CHANGE,
  ApiDiffType.TYPE_ALIAS_ADD,
  ApiDiffType.TYPE_ALIAS_REDUCE,
  ApiDiffType.ENUM_MEMBER_VALUE_CHANGE,
  ApiDiffType.REDUCE,
  ApiDiffType.HISTORICAL_JSDOC_CHANGE,
  ApiDiffType.HISTORICAL_API_CHANGE,
]);