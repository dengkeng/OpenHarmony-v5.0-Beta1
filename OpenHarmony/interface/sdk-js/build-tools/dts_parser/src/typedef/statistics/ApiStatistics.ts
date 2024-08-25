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

import { ApiType } from '../parser/ApiInfoDefination';
import { DecoratorInfo } from '../../typedef/parser/Decorator';
import { FunctionUtils } from '../../utils/FunctionUtils';

/**
 * 统计工具类，用于存取API相关信息
 */
export class ApiStatisticsInfo {
  filePath: string = '';
  packageName: string = '';
  parentModuleName: string = 'global';
  // @syscap标签--api的系统能力
  syscap: string = '';
  // @permission标签--api的权限
  permissions: string = '';
  // @since标签--api的起始版本
  since: string = '';
  // @form标签--api是否支持卡片应用
  isForm: boolean = false;
  // @crossplatform标签--api是否支持跨平台
  isCrossPlatForm: boolean = false;
  // @atomicservice标签--是否为高阶API
  isAutomicService: boolean = false;
  hierarchicalRelations: string = '';
  apiName: string = '';
  deprecatedVersion: string = '';
  useInstead: string = '';
  apiType: string = '';
  definedText: string = '';
  pos: ts.LineAndCharacter = { line: -1, character: -1 };
  isSystemapi: boolean = false;
  modelLimitation: string = '';
  decorators: Array<string> | undefined = [];
  errorCodes: number[] = [];
  kitInfo: string = '';
  setFilePath(fileFilePath: string): ApiStatisticsInfo {
    this.filePath = fileFilePath;
    this.packageName = FunctionUtils.getPackageName(fileFilePath);
    return this;
  }

  getPackageName(): string {
    return this.packageName;
  }

  getFilePath(): string {
    return this.filePath;
  }

  setApiType(apiType: string): ApiStatisticsInfo {
    this.apiType = apiType === ApiType.DECLARE_CONST ? ApiType.PROPERTY : apiType;
    return this;
  }

  getParentModuleName(): string {
    return this.parentModuleName;
  }

  setParentModuleName(parentModuleName: string): ApiStatisticsInfo {
    this.parentModuleName = parentModuleName;
    return this;
  }

  setSyscap(syscap?: string): ApiStatisticsInfo {
    if (syscap) {
      this.syscap = syscap;
    }
    return this;
  }

  getSyscap(): string {
    return this.syscap;
  }

  setPermission(permissions: string): ApiStatisticsInfo {
    this.permissions = permissions;
    return this;
  }

  getPermission(): string {
    return this.permissions;
  }

  setSince(since: string): ApiStatisticsInfo {
    this.since = since;
    return this;
  }

  getSince(): string {
    return this.since;
  }

  setIsForm(isForm: boolean): ApiStatisticsInfo {
    this.isForm = isForm;
    return this;
  }

  getIsForm(): boolean {
    return this.isForm;
  }

  setIsCrossPlatForm(isCrossPlatForm: boolean): ApiStatisticsInfo {
    this.isCrossPlatForm = isCrossPlatForm;
    return this;
  }

  getIsCrossPlatForm(): boolean {
    return this.isCrossPlatForm;
  }

  setIsAutomicService(isAutomicService: boolean): ApiStatisticsInfo {
    this.isAutomicService = isAutomicService;
    return this;
  }

  getIsAutomicService(): boolean {
    return this.isAutomicService;
  }

  getApiType(): string {
    return this.apiType;
  }

  setDefinedText(definedText: string): ApiStatisticsInfo {
    this.definedText = definedText;
    return this;
  }

  getDefinedText(): string {
    return this.definedText;
  }

  setPos(pos: ts.LineAndCharacter): ApiStatisticsInfo {
    this.pos = pos;
    return this;
  }

  getPos(): ts.LineAndCharacter {
    return this.pos;
  }

  setApiName(apiName: string): ApiStatisticsInfo {
    this.apiName = apiName;
    return this;
  }

  getApiName(): string {
    return this.apiName;
  }

  setHierarchicalRelations(hierarchicalRelations: string): ApiStatisticsInfo {
    this.hierarchicalRelations = hierarchicalRelations;
    return this;
  }

  getHierarchicalRelations(): string {
    return this.hierarchicalRelations;
  }

  setDeprecatedVersion(deprecatedVersion: string): ApiStatisticsInfo {
    this.deprecatedVersion = deprecatedVersion;
    return this;
  }

  getDeprecatedVersion(): string {
    return this.deprecatedVersion;
  }

  setUseInstead(useInstead: string): ApiStatisticsInfo {
    this.useInstead = useInstead;
    return this;
  }

  getUseInstead(): string {
    return this.useInstead;
  }

  setApiLevel(isSystemApi: boolean): ApiStatisticsInfo {
    this.isSystemapi = isSystemApi;
    return this;
  }

  getApiLevel(): boolean {
    return this.isSystemapi;
  }

  setModelLimitation(modelLimitation: string): ApiStatisticsInfo {
    this.modelLimitation = modelLimitation;
    return this;
  }

  getModelLimitation(): string {
    return this.modelLimitation;
  }

  setDecorators(decorators: DecoratorInfo[] | undefined): ApiStatisticsInfo {
    decorators?.forEach((decoratorInfo: DecoratorInfo) => {
      this.decorators?.push(decoratorInfo.expression);
    });
    return this;
  }

  getDecorators(): Array<string> | undefined {
    return this.decorators;
  }

  setErrorCodes(errorCodes: number[]): ApiStatisticsInfo {
    this.errorCodes = errorCodes;
    return this;
  }

  getErrorCodes(): number[] {
    return this.errorCodes;
  }

  setKitInfo(kitInfo: string): ApiStatisticsInfo {
    this.kitInfo = kitInfo;
    return this;
  }

  getKitInfo(): string {
    return this.kitInfo;
  }
}

/**
 * 需要统计为API的类型
 */
export const apiStatisticsType: Set<string> = new Set([
  ApiType.PROPERTY,
  ApiType.CLASS,
  ApiType.INTERFACE,
  ApiType.NAMESPACE,
  ApiType.METHOD,
  ApiType.CONSTANT,
  ApiType.ENUM_VALUE,
  ApiType.ENUM,
  ApiType.TYPE_ALIAS,
  ApiType.DECLARE_CONST,
  ApiType.STRUCT,
]);

/**
 * 不需要被统计成API的类型，但是子节点需要统计成API
 */
export const apiNotStatisticsType: Set<string> = new Set([ApiType.ENUM, ApiType.NAMESPACE]);

/**
 * 名字为on/off的函数，不合并API声明
 */
export const notMergeDefinedText: Set<string> = new Set(['on', 'off']);

/**
 * 需要进行同名函数合并的API类型
 */
export const mergeDefinedTextType: Set<number> = new Set([
  ts.SyntaxKind.MethodDeclaration,
  ts.SyntaxKind.MethodSignature,
  ts.SyntaxKind.FunctionDeclaration,
]);

export type StatisticsInfoValueType = {
  /**
   * 统计工具返回的经过筛选后的数据
   *
   * @type {ApiStatisticsInfo[]}
   */
  apiStatisticsInfos: ApiStatisticsInfo[];

  /**
   * 统计工具返回的未经筛选后的数据
   *
   * @type {ApiStatisticsInfo[]}
   */
  allApiStatisticsInfos?: ApiStatisticsInfo[];
};
