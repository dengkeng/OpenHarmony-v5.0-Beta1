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
  ApiInfo,
  ApiType,
  BasicApiInfo,
  ConstantInfo,
  EnumValueInfo,
  MethodInfo,
  ParamInfo,
  EnumInfo,
  PropertyInfo,
  TypeAliasInfo,
  ClassInfo,
} from '../../typedef/parser/ApiInfoDefination';
import { Comment } from '../../typedef/parser/Comment';
import {
  ApiDiffType,
  ApiStatusCode,
  ApiNodeDiffProcessor,
  ApiSceneDiffProcessor,
  ApiScenesDiffProcessor,
  BasicDiffInfo,
  DiffTypeInfo,
  diffMap,
  incompatibleApiDiffTypes,
  JsDocDiffProcessor,
} from '../../typedef/diff/ApiInfoDiff';
import { StringUtils } from '../../utils/StringUtils';
import { CharMapType, CompareReturnObjType, PermissionsProcessorHelper, RangeChange } from './PermissionsProcessor';
import { DecoratorInfo } from '../../typedef/parser/Decorator';
import { ApiStatisticsHelper } from '../statistics/Statistics';
import { FunctionUtils } from '../../utils/FunctionUtils';
import { CommonFunctions } from '../../utils/checkUtils';
import { NumberConstant } from '../../utils/Constant';

export namespace DiffProcessorHelper {
  /**
   * 权限编码进行逻辑运算的转义规则
   */
  export const permissionsCharMap: CharMapType = new Map([
    ['and', { splitchar: 'and', transferchar: '&' }],
    ['or', { splitchar: 'or', transferchar: '|' }],
  ]);

  /**
   * type进行逻辑运算的转义规则
   */
  export const typeCharMap: CharMapType = new Map([
    ['and', { splitchar: '&', transferchar: '&' }],
    ['or', { splitchar: '|', transferchar: '|' }],
  ]);

  /**
   * 处理api节点jsdoc中的diff信息工具
   *
   */
  export class JsDocDiffHelper {
    static diffJsDocInfo(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const oldJsDocInfo: Comment.JsDocInfo | undefined = oldApiInfo.getLastJsDocInfo();
      const newJsDocInfo: Comment.JsDocInfo | undefined = newApiInfo.getLastJsDocInfo();
      JsDocDiffHelper.diffSinceVersion(oldApiInfo, newApiInfo, diffInfos);
      for (let i = 0; i < jsDocDiffProcessors.length; i++) {
        const jsDocDiffProcessor: JsDocDiffProcessor | undefined = jsDocDiffProcessors[i];
        const diffType: DiffTypeInfo | undefined = jsDocDiffProcessor(oldJsDocInfo, newJsDocInfo);
        if (!diffType) {
          continue;
        }
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffType);
        diffInfos.push(diffInfo);
      }
    }

    static getFirstSinceVersion(jsDocInfos: Comment.JsDocInfo[]): string {
      let sinceVersion: string = '';
      for (let i = 0; i < jsDocInfos.length; i++) {
        const jsDocInfo: Comment.JsDocInfo = jsDocInfos[i];
        if (jsDocInfo.getSince() !== '-1') {
          sinceVersion = jsDocInfo.getSince();
          return sinceVersion;
        }      
      }
      return sinceVersion;
    }

    static diffSinceVersion(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const oldFirstJsDocInfo: Comment.JsDocInfo | undefined = oldApiInfo.getJsDocInfos()[0];
      const newFirstJsDocInfo: Comment.JsDocInfo | undefined = newApiInfo.getJsDocInfos()[0];
      const sinceVersionOfOld: string = oldFirstJsDocInfo ? oldFirstJsDocInfo.getSince() : '-1';
      const sinceVersionOfNew: string = newFirstJsDocInfo ? newFirstJsDocInfo.getSince() : '-1';
      diffTypeInfo
        .setStatusCode(ApiStatusCode.VERSION_CHNAGES)
        .setOldMessage(sinceVersionOfOld)
        .setNewMessage(sinceVersionOfNew);
      if (sinceVersionOfOld === sinceVersionOfNew) {
        return;
      }
      if (sinceVersionOfOld === '-1') {
        diffTypeInfo.setDiffType(ApiDiffType.SINCE_VERSION_NA_TO_HAVE);
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
        diffInfos.push(diffInfo);
        return;
      }
      if (sinceVersionOfNew === '-1') {
        diffTypeInfo.setDiffType(ApiDiffType.SINCE_VERSION_HAVE_TO_NA);
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
        diffInfos.push(diffInfo);
        return;
      }
      diffTypeInfo.setDiffType(ApiDiffType.SINCE_VERSION_A_TO_B);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }

    static diffIsSystemApi(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const isSystemApiOfOld: boolean = oldJsDocInfo ? oldJsDocInfo.getIsSystemApi() : false;
      const isSystemApiOfNew: boolean = newJsDocInfo ? newJsDocInfo.getIsSystemApi() : false;
      diffTypeInfo
        .setStatusCode(ApiStatusCode.SYSTEM_API_CHNAGES)
        .setOldMessage(StringUtils.transformBooleanToTag(isSystemApiOfOld, Comment.JsDocTag.SYSTEM_API))
        .setNewMessage(StringUtils.transformBooleanToTag(isSystemApiOfNew, Comment.JsDocTag.SYSTEM_API));
      if (isSystemApiOfNew === isSystemApiOfOld) {
        return undefined;
      }
      if (isSystemApiOfNew) {
        return diffTypeInfo.setDiffType(ApiDiffType.PUBLIC_TO_SYSTEM);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.SYSTEM_TO_PUBLIC);
    }

    static diffModelLimitation(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const modelLimitationDiffMap: Map<string, ApiDiffType> = new Map([
        ['_stagemodelonly', ApiDiffType.NA_TO_STAGE],
        ['stagemodelonly_', ApiDiffType.STAGE_TO_NA],
        ['_famodelonly', ApiDiffType.NA_TO_FA],
        ['famodelonly_', ApiDiffType.FA_TO_NA],
        ['famodelonly_stagemodelonly', ApiDiffType.FA_TO_STAGE],
        ['stagemodelonly_famodelonly', ApiDiffType.STAGE_TO_FA],
      ]);
      const modelLimitationOfOld: string = oldJsDocInfo ? oldJsDocInfo.getModelLimitation().toLowerCase() : '';
      const modelLimitationOfNew: string = newJsDocInfo ? newJsDocInfo.getModelLimitation().toLowerCase() : '';
      if (modelLimitationOfNew === modelLimitationOfOld) {
        return undefined;
      }
      const diffMsg: string = `${modelLimitationOfOld.toLowerCase()}_${modelLimitationOfNew.toLowerCase()}`;
      const diffType: ApiDiffType = modelLimitationDiffMap.get(diffMsg) as ApiDiffType;
      diffTypeInfo
        .setStatusCode(ApiStatusCode.MODEL_CHNAGES)
        .setDiffType(diffType)
        .setOldMessage(modelLimitationOfOld)
        .setNewMessage(modelLimitationOfNew);
      return diffTypeInfo;
    }

    static diffIsForm(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const isCardOfOld: boolean = oldJsDocInfo ? oldJsDocInfo.getIsForm() : false;
      const isCardOfNew: boolean = newJsDocInfo ? newJsDocInfo.getIsForm() : false;
      diffTypeInfo
        .setStatusCode(ApiStatusCode.FORM_CHANGED)
        .setOldMessage(StringUtils.transformBooleanToTag(isCardOfOld, Comment.JsDocTag.FORM))
        .setNewMessage(StringUtils.transformBooleanToTag(isCardOfNew, Comment.JsDocTag.FORM));
      if (isCardOfNew === isCardOfOld) {
        return undefined;
      }
      if (isCardOfNew) {
        return diffTypeInfo.setDiffType(ApiDiffType.NA_TO_CARD);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.CARD_TO_NA);
    }

    static diffIsCrossPlatForm(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const isCrossPlatFormOfOld: boolean = oldJsDocInfo ? oldJsDocInfo.getIsCrossPlatForm() : false;
      const isCrossPlatFormOfNew: boolean = newJsDocInfo ? newJsDocInfo.getIsCrossPlatForm() : false;
      diffTypeInfo
        .setStatusCode(ApiStatusCode.CROSSPLATFORM_CHANGED)
        .setOldMessage(StringUtils.transformBooleanToTag(isCrossPlatFormOfOld, Comment.JsDocTag.CROSS_PLAT_FORM))
        .setNewMessage(StringUtils.transformBooleanToTag(isCrossPlatFormOfNew, Comment.JsDocTag.CROSS_PLAT_FORM));
      if (isCrossPlatFormOfNew === isCrossPlatFormOfOld) {
        return undefined;
      }
      if (isCrossPlatFormOfNew) {
        return diffTypeInfo.setDiffType(ApiDiffType.NA_TO_CROSS_PLATFORM);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.CROSS_PLATFORM_TO_NA);
    }

    static diffPermissions(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const permissionsOfOld: string = oldJsDocInfo ? oldJsDocInfo.getPermission() : '';
      const permissionsOfNew: string = newJsDocInfo ? newJsDocInfo.getPermission() : '';
      diffTypeInfo
        .setStatusCode(ApiStatusCode.PERMISSION_CHANGES)
        .setOldMessage(permissionsOfOld)
        .setNewMessage(permissionsOfNew);
      if (permissionsOfOld === permissionsOfNew) {
        return undefined;
      }
      if (permissionsOfOld === '') {
        return diffTypeInfo.setStatusCode(ApiStatusCode.PERMISSION_NEW).setDiffType(ApiDiffType.PERMISSION_NA_TO_HAVE);
      }
      if (permissionsOfNew === '') {
        return diffTypeInfo
          .setStatusCode(ApiStatusCode.PERMISSION_DELETE)
          .setDiffType(ApiDiffType.PERMISSION_HAVE_TO_NA);
      }
      const permiss: PermissionsProcessorHelper = new PermissionsProcessorHelper(permissionsCharMap);
      const compareVal: CompareReturnObjType = permiss.comparePermissions(permissionsOfOld, permissionsOfNew);
      if (compareVal.range === RangeChange.DOWN) {
        return diffTypeInfo.setDiffType(ApiDiffType.PERMISSION_RANGE_SMALLER);
      }
      if (compareVal.range === RangeChange.UP) {
        return diffTypeInfo.setDiffType(ApiDiffType.PERMISSION_RANGE_BIGGER);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.PERMISSION_RANGE_CHANGE);
    }

    static diffErrorCodes(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const errorCodesOfOld: number[] = oldJsDocInfo ? oldJsDocInfo.getErrorCode().sort() : [];
      const errorCodesOfNew: number[] = newJsDocInfo ? newJsDocInfo.getErrorCode().sort() : [];
      const errorCodesStringOfOld: string = errorCodesOfOld.toString();
      const errorCodesStringOfNew: string = errorCodesOfNew.toString();
      diffTypeInfo
        .setStatusCode(ApiStatusCode.ERRORCODE_CHANGES)
        .setOldMessage(errorCodesStringOfOld)
        .setNewMessage(errorCodesStringOfNew);
      if (errorCodesStringOfNew === errorCodesStringOfOld) {
        return undefined;
      }
      if (StringUtils.hasSubstring(errorCodesStringOfNew, errorCodesStringOfOld)) {
        return diffTypeInfo.setStatusCode(ApiStatusCode.NEW_ERRORCODE).setDiffType(ApiDiffType.ERROR_CODE_ADD);
      }
      if (StringUtils.hasSubstring(errorCodesStringOfOld, errorCodesStringOfNew)) {
        return diffTypeInfo.setDiffType(ApiDiffType.ERROR_CODE_REDUCE);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.ERROR_CODE_CHANGE);
    }

    static diffSyscap(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const syscapOfOld: string = oldJsDocInfo ? oldJsDocInfo.getSyscap() : '';
      const syscapOfNew: string = newJsDocInfo ? newJsDocInfo.getSyscap() : '';
      diffTypeInfo.setStatusCode(ApiStatusCode.SYSCAP_CHANGES).setOldMessage(syscapOfOld).setNewMessage(syscapOfNew);
      if (syscapOfNew === syscapOfOld) {
        return undefined;
      }
      if (syscapOfOld === '') {
        return diffTypeInfo.setDiffType(ApiDiffType.SYSCAP_NA_TO_HAVE);
      }
      if (syscapOfNew === '') {
        return diffTypeInfo.setDiffType(ApiDiffType.SYSCAP_HAVE_TO_NA);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.SYSCAP_A_TO_B);
    }

    static diffDeprecated(
      oldJsDocInfo: Comment.JsDocInfo | undefined,
      newJsDocInfo: Comment.JsDocInfo | undefined
    ): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const deprecatedVersionOfOld: string = oldJsDocInfo ? oldJsDocInfo.getDeprecatedVersion() : '-1';
      const deprecatedVersionOfNew: string = newJsDocInfo ? newJsDocInfo.getDeprecatedVersion() : '-1';
      diffTypeInfo
        .setStatusCode(ApiStatusCode.DEPRECATED_CHNAGES)
        .setOldMessage(deprecatedVersionOfOld.toString())
        .setNewMessage(deprecatedVersionOfNew.toString());
      if (deprecatedVersionOfNew === deprecatedVersionOfOld) {
        return undefined;
      }
      if (deprecatedVersionOfOld === '-1') {
        return diffTypeInfo.setDiffType(ApiDiffType.DEPRECATED_NA_TO_HAVE);
      }
      if (deprecatedVersionOfNew === '-1') {
        return diffTypeInfo.setDiffType(ApiDiffType.DEPRECATED_HAVE_TO_NA);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.DEPRECATED_A_TO_B);
    }
  }

  /**
   * 比较API的装饰器信息
   */
  export class ApiDecoratorsDiffHelper {
    /**
     * 新旧版本API一致的情况下，比较装饰器
     *
     * @param {ApiInfo} oldApiInfo
     * @param {ApiInfo} newApiInfo
     * @param {BasicDiffInfo[]} diffInfos
     * @returns
     */
    static diffDecorator(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const oldDecoratorsMap: Map<string, string[] | undefined> = ApiDecoratorsDiffHelper.setDecoratorsMap(
        oldApiInfo.getDecorators()
      );
      const newDecoratorsMap: Map<string, string[] | undefined> = ApiDecoratorsDiffHelper.setDecoratorsMap(
        newApiInfo.getDecorators()
      );
      if (newDecoratorsMap.size === 0) {
        for (const key of oldDecoratorsMap.keys()) {
          ApiDecoratorsDiffHelper.addDeleteDecoratorsInfo(key, oldApiInfo, newApiInfo, diffInfos);
        }
        return;
      }

      if (oldDecoratorsMap.size === 0) {
        for (const key of newDecoratorsMap.keys()) {
          ApiDecoratorsDiffHelper.addNewDecoratorsInfo(key, oldApiInfo, newApiInfo, diffInfos);
          newDecoratorsMap.delete(key);
        }
        return;
      }
      ApiDecoratorsDiffHelper.diffDecoratorInfo(oldDecoratorsMap, newDecoratorsMap, oldApiInfo, newApiInfo, diffInfos);
    }

    static diffDecoratorInfo(
      oldDecoratorsMap: Map<string, string[] | undefined>,
      newDecoratorsMap: Map<string, string[] | undefined>,
      oldApiInfo: ApiInfo,
      newApiInfo: ApiInfo,
      diffInfos: BasicDiffInfo[]
    ): void {
      const sameDecoratorSet: Set<string> = new Set();
      for (const key of oldDecoratorsMap.keys()) {
        const newDecoratorArguments: string[] | undefined = newDecoratorsMap.get(key);
        const oldDecoratorArguments: string[] | undefined = oldDecoratorsMap.get(key);
        //新版本没有这个装饰器
        if (!newDecoratorArguments) {
          ApiDecoratorsDiffHelper.addDeleteDecoratorsInfo(key, oldApiInfo, newApiInfo, diffInfos);
          sameDecoratorSet.add(key);
          continue;
        }

        // 新旧版本装饰器参数一样
        if (oldDecoratorArguments && newDecoratorArguments.join() === oldDecoratorArguments.join()) {
          newDecoratorsMap.delete(key);
          sameDecoratorSet.add(key);
          continue;
        }
      }
      // 新版中剩下的装饰器为新增
      for (const key of newDecoratorsMap.keys()) {
        ApiDecoratorsDiffHelper.addNewDecoratorsInfo(key, oldApiInfo, newApiInfo, diffInfos);
      }

      for (const key of oldDecoratorsMap.keys()) {
        if (sameDecoratorSet.has(key)) {
          continue;
        }
        ApiDecoratorsDiffHelper.addDeleteDecoratorsInfo(key, oldApiInfo, newApiInfo, diffInfos);
      }
    }

    static setDecoratorsMap(decorators: DecoratorInfo[] | undefined): Map<string, string[] | undefined> {
      const decoratorsMap: Map<string, string[]> = new Map();
      if (!decorators) {
        return decoratorsMap;
      }

      decorators.forEach((decoratorInfo: DecoratorInfo) => {
        const expressionArguments: string[] | undefined = decoratorInfo.getExpressionArguments();
        decoratorsMap.set(decoratorInfo.getExpression(), expressionArguments === undefined ? [] : expressionArguments);
      });
      return decoratorsMap;
    }

    static addDeleteDecoratorsInfo(
      decoratorName: string,
      oldApiInfo: ApiInfo,
      newApiInfo: ApiInfo,
      diffInfos: BasicDiffInfo[]
    ): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      diffTypeInfo
        .setStatusCode(ApiStatusCode.DELETE_DECORATOR)
        .setDiffType(ApiDiffType.DELETE_DECORATOR)
        .setOldMessage(decoratorName)
        .setNewMessage('');
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }

    static addNewDecoratorsInfo(
      decoratorName: string,
      oldApiInfo: ApiInfo,
      newApiInfo: ApiInfo,
      diffInfos: BasicDiffInfo[]
    ): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      diffTypeInfo
        .setStatusCode(ApiStatusCode.NEW_DECORATOR)
        .setDiffType(ApiDiffType.NEW_DECORATOR)
        .setOldMessage('')
        .setNewMessage(decoratorName);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }
  }

  export class ApiCheckHelper {
    /**
     * 比较两个API的历史版本jsdoc
     *
     * @param {ApiInfo} oldApiInfo
     * @param {ApiInfo} newApiInfo
     * @param {BasicDiffInfo[]} diffInfos
     */
    static diffHistoricalJsDoc(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const currentVersion: string = CommonFunctions.getCheckApiVersion().toString();
      const oldJsDocTextArr: Array<string> = oldApiInfo.getJsDocText().split('*/');
      const newJsDocTextArr: Array<string> = newApiInfo.getJsDocText().split('*/');
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      if (oldApiInfo.getCurrentVersion() === currentVersion) {
        oldJsDocTextArr.splice(NumberConstant.DELETE_CURRENT_JS_DOC);
      } else {
        oldJsDocTextArr.splice(-1);
      }

      if (newApiInfo.getCurrentVersion() === currentVersion) {
        newJsDocTextArr.splice(NumberConstant.DELETE_CURRENT_JS_DOC);
      } else {
        newJsDocTextArr.splice(-1);
      }

      if (oldJsDocTextArr.length !== newJsDocTextArr.length) {
        diffTypeInfo.setDiffType(ApiDiffType.HISTORICAL_JSDOC_CHANGE);
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
        diffInfos.push(diffInfo);
        return;
      }
      for (let i = 0; i < oldJsDocTextArr.length; i++) {
        if (oldJsDocTextArr[i].replace(/\r\n/g, '') !== newJsDocTextArr[i].replace(/\r\n/g, '')) {
          diffTypeInfo.setDiffType(ApiDiffType.HISTORICAL_JSDOC_CHANGE);
          const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
          diffInfos.push(diffInfo);
        }
      }
    }

    static diffHistoricalAPI(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const currentVersion: string = CommonFunctions.getCheckApiVersion().toString();
      const oldApiDefinedText: string = oldApiInfo.getDefinedText();
      const newApiDefinedText: string = newApiInfo.getDefinedText();
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      if (oldApiDefinedText !== newApiDefinedText && newApiInfo.getCurrentVersion() !== currentVersion) {
        diffTypeInfo.setDiffType(ApiDiffType.HISTORICAL_API_CHANGE);
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
        diffInfos.push(diffInfo);
      }
    }
  }

  /**
   * 处理api节点的diff信息工具
   *
   */
  export class ApiNodeDiffHelper {
    /**
     * 根据节点类型处理节点的diff信息，处理的主流程
     *
     * @param {ApiInfo} oldApiInfo 旧版本的节点信息
     * @param {ApiInfo} newApiInfo 新版本的节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     * @return {void}
     */
    static diffNodeInfo(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[], isCheck?: boolean): void {
      if (isCheck) {
        ApiCheckHelper.diffHistoricalJsDoc(oldApiInfo, newApiInfo, diffInfos);
        ApiCheckHelper.diffHistoricalAPI(oldApiInfo, newApiInfo, diffInfos);
      }
      const apiType: string = newApiInfo.getApiType();
      if (oldApiInfo.getApiType() !== apiType) {
        return;
      }
      const apiNodeDiff: ApiNodeDiffProcessor | undefined = apiNodeDiffMethod.get(apiType);
      if (!apiNodeDiff) {
        return;
      }
      apiNodeDiff(oldApiInfo, newApiInfo, diffInfos);
    }

    /**
     * 处理type类型
     *
     * @static
     * @param {string} oldType 旧版本的type字符串
     * @param {string} newType 新版本的type字符串
     * @return { ApiDiffType | undefined}  type范围的变化情况
     * @memberof ApiNodeDiffHelper
     */
    static diffBaseType(oldType: string, newType: string): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      if (oldType === newType) {
        return undefined;
      }
      diffTypeInfo.setStatusCode(ApiStatusCode.TYPE_CHNAGES).setOldMessage(oldType).setNewMessage(newType);
      if (oldType === '') {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_RANGE_CHANGE);
      }
      if (newType === '') {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_RANGE_CHANGE);
      }
      const permiss: PermissionsProcessorHelper = new PermissionsProcessorHelper(typeCharMap);
      const compareVal: CompareReturnObjType = permiss.comparePermissions(oldType, newType);
      if (compareVal.range === RangeChange.DOWN) {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_RANGE_SMALLER);
      }
      if (compareVal.range === RangeChange.UP) {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_RANGE_BIGGER);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.TYPE_RANGE_CHANGE);
    }

    /**
     * 处理方法节点，获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的方法节点信息
     * @param {ApiInfo} newApiInfo 新版本的方法节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     */
    static diffMethod(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      methodDiffProcessors.forEach((methodDiffProcessor: ApiScenesDiffProcessor) => {
        const diffTypeInfo: DiffTypeInfo[] | DiffTypeInfo | undefined = methodDiffProcessor(
          oldApiInfo as MethodInfo,
          newApiInfo as MethodInfo
        );
        if (!diffTypeInfo) {
          return;
        }
        if (diffTypeInfo instanceof Array) {
          diffTypeInfo.forEach((info: DiffTypeInfo) => {
            const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
              oldApiInfo,
              newApiInfo,
              info.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
            );
            diffInfos.push(diffInfo);
          });
        } else {
          const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
            oldApiInfo,
            newApiInfo,
            diffTypeInfo.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
          );
          diffInfos.push(diffInfo);
        }
      });
    }

    /**
     * 处理方法节点的返回值
     *
     * @param {MethodInfo} oldApiInfo 旧版本的方法节点信息
     * @param {MethodInfo} newApiInfo 新版本的方法节点信息
     * @return {*}  {(ApiDiffType | undefined)} 方法节点的返回值的变化情况
     */
    static diffMethodReturnType(oldApiInfo: MethodInfo, newApiInfo: MethodInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaMethodType: string[] = oldApiInfo.getReturnValue();
      const newMethodType: string[] = newApiInfo.getReturnValue();
      const olaMethodTypeStr = olaMethodType.toString().replace(/\r|\n|\s+|'|"/g, '');
      const newMethodTypeStr = newMethodType.toString().replace(/\r|\n|\s+|'|"/g, '');
      if (olaMethodTypeStr === newMethodTypeStr) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaMethodTypeStr).setNewMessage(newMethodTypeStr);
      if (StringUtils.hasSubstring(newMethodTypeStr, olaMethodTypeStr)) {
        return diffTypeInfo.setDiffType(ApiDiffType.FUNCTION_RETURN_TYPE_ADD);
      }
      if (StringUtils.hasSubstring(olaMethodTypeStr, newMethodTypeStr)) {
        return diffTypeInfo.setDiffType(ApiDiffType.FUNCTION_RETURN_TYPE_REDUCE);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.FUNCTION_RETURN_TYPE_CHANGE);
    }

    /**
     * 处理方法节点的参数，获取对应diff信息
     *
     * @param {MethodInfo} oldApiInfo 旧版本的方法节点信息
     * @param {MethodInfo} newApiInfo 新版本的方法节点信息
     * @return {*}  {ApiDiffType[]}  返回各个参数的变化情况
     */
    static diffMethodParams(oldApiInfo: MethodInfo, newApiInfo: MethodInfo): DiffTypeInfo[] {
      const diffTypeInfos: DiffTypeInfo[] = [];
      const diffTypes: ApiDiffType[] = [];
      const oldMethodParams: ParamInfo[] = oldApiInfo.getParams();
      const newMethodParams: ParamInfo[] = newApiInfo.getParams();
      const diffProcessors: ((oldApiInfo: ParamInfo, newApiInfo: ParamInfo) => ApiDiffType | undefined)[] = [
        ApiNodeDiffHelper.diffMethodParamName,
        ApiNodeDiffHelper.diffMethodParamType,
        ApiNodeDiffHelper.diffMethodParamRequired,
      ];
      const maxLen: number = Math.max(oldMethodParams.length, newMethodParams.length);
      // 遍历方法参数列表
      for (let i = 0; i < maxLen; i++) {
        const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
        if (i >= oldMethodParams.length) {
          const newElement: ParamInfo = newMethodParams[i];
          const oldParamISRequired: boolean = newElement.getIsRequired();
          diffTypeInfo
            .setDiffType(
              oldParamISRequired ? ApiDiffType.FUNCTION_PARAM_REQUIRED_ADD : ApiDiffType.FUNCTION_PARAM_UNREQUIRED_ADD
            )
            .setNewMessage(newElement.getDefinedText());
          diffTypeInfos.push(diffTypeInfo);
          continue;
        }
        if (i >= newMethodParams.length) {
          const oldElement: ParamInfo = oldMethodParams[i];
          diffTypeInfo.setDiffType(ApiDiffType.FUNCTION_PARAM_REDUCE).setOldMessage(oldElement.getDefinedText());
          diffTypeInfos.push(diffTypeInfo);
          continue;
        }
        const oldElement: ParamInfo = oldMethodParams[i];
        const newElement: ParamInfo = newMethodParams[i];
        diffTypeInfo.setOldMessage(oldElement.getDefinedText()).setNewMessage(newElement.getDefinedText());
        for (let j = 0; j < diffProcessors.length; j++) {
          const apiSceneDiffProcessor = diffProcessors[j];
          const diffType: ApiDiffType | undefined = apiSceneDiffProcessor(oldElement, newElement);
          if (!diffType) {
            continue;
          }
          diffTypeInfos.push(diffTypeInfo.setDiffType(diffType));
        }
      }
      return diffTypeInfos;
    }

    /**
     * 处理方法节点的参数名称
     *
     * @param {ParamInfo} oldApiInfo 旧版本的参数节点信息
     * @param {ParamInfo} newApiInfo 新版本的参数节点信息
     * @return {*}  {(ApiDiffType | undefined)} 方法节点的参数名称的变化情况
     */
    static diffMethodParamName(oldApiInfo: ParamInfo, newApiInfo: ParamInfo): ApiDiffType | undefined {
      const oldParamName: string = oldApiInfo.getApiName();
      const newParamName: string = newApiInfo.getApiName();
      if (oldParamName === newParamName) {
        return undefined;
      }
      return ApiDiffType.FUNCTION_PARAM_NAME_CHANGE;
    }

    /**
     * 处理方法节点的参数类型
     *
     * @param {ParamInfo} oldApiInfo 旧版本的参数节点信息
     * @param {ParamInfo} newApiInfo 新版本的参数节点信息
     * @return {*}  {(ApiDiffType | undefined)} 方法节点的参数类型的变化情况
     */
    static diffMethodParamType(oldApiInfo: ParamInfo, newApiInfo: ParamInfo): ApiDiffType | undefined {
      const oldParamType: string[] = oldApiInfo.getType();
      const newParamType: string[] = newApiInfo.getType();
      const oldParamTypeStr: string = oldParamType.toString().replace(/\r|\n|\s+|'|"/g, '');
      const newParamTypeStr: string = newParamType.toString().replace(/\r|\n|\s+|'|"/g, '');
      if (oldParamTypeStr === newParamTypeStr) {
        return undefined;
      }
      if (StringUtils.hasSubstring(newParamTypeStr, oldParamTypeStr)) {
        return ApiDiffType.FUNCTION_PARAM_TYPE_ADD;
      }
      if (StringUtils.hasSubstring(oldParamTypeStr, newParamTypeStr)) {
        return ApiDiffType.FUNCTION_PARAM_TYPE_REDUCE;
      }
      return ApiDiffType.FUNCTION_PARAM_TYPE_CHANGE;
    }

    /**
     * 处理方法节点的参数必选
     *
     * @param {ParamInfo} oldApiInfo 旧版本的参数节点信息
     * @param {ParamInfo} newApiInfo 新版本的参数节点信息
     * @return {*}  {(ApiDiffType | undefined)} 方法节点的必选参数的变化情况
     */
    static diffMethodParamRequired(oldApiInfo: ParamInfo, newApiInfo: ParamInfo): ApiDiffType | undefined {
      const oldParamISRequired: boolean = oldApiInfo.getIsRequired();
      const newParamISRequired: boolean = newApiInfo.getIsRequired();
      if (oldParamISRequired === newParamISRequired) {
        return undefined;
      }
      return newParamISRequired ? ApiDiffType.FUNCTION_PARAM_TO_REQUIRED : ApiDiffType.FUNCTION_PARAM_TO_UNREQUIRED;
    }

    /**
     * 处理class节点，获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的class节点信息
     * @param {ApiInfo} newApiInfo 新版本的class节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     * @return {*}  {void}
     */
    static diffClass(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaClassName: string = oldApiInfo.getApiName();
      const newClassName: string = newApiInfo.getApiName();
      if (olaClassName === newClassName) {
        return;
      }
      diffTypeInfo
        .setStatusCode(ApiStatusCode.CLASS_CHANGES)
        .setDiffType(ApiDiffType.API_NAME_CHANGE)
        .setOldMessage(olaClassName)
        .setNewMessage(newClassName);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }

    /**
     * 处理interface节点，获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的interface节点信息
     * @param {ApiInfo} newApiInfo 新版本的interface节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     * @return {*}  {void}
     */
    static diffInterface(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaClassName: string = oldApiInfo.getApiName();
      const newClassName: string = newApiInfo.getApiName();
      if (olaClassName === newClassName) {
        return;
      }
      diffTypeInfo
        .setStatusCode(ApiStatusCode.CLASS_CHANGES)
        .setDiffType(ApiDiffType.API_NAME_CHANGE)
        .setOldMessage(olaClassName)
        .setNewMessage(newClassName);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }

    /**
     * 处理namespace节点,获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的namespace节点信息
     * @param {ApiInfo} newApiInfo 新版本的namespace节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     * @return {*}  {void}
     */
    static diffNamespace(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaClassName: string = oldApiInfo.getApiName();
      const newClassName: string = newApiInfo.getApiName();
      if (olaClassName === newClassName) {
        return;
      }
      diffTypeInfo
        .setStatusCode(ApiStatusCode.CLASS_CHANGES)
        .setDiffType(ApiDiffType.API_NAME_CHANGE)
        .setOldMessage(olaClassName)
        .setNewMessage(newClassName);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
      diffInfos.push(diffInfo);
    }

    /**
     * 处理属性节点,获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的属性节点信息
     * @param {ApiInfo} newApiInfo 新版本的属性节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     * @return {*}  {void}
     */
    static diffProperty(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      propertyDiffProcessors.forEach((propertyDiffProcessor: ApiSceneDiffProcessor) => {
        const diffType: DiffTypeInfo | undefined = propertyDiffProcessor(oldApiInfo, newApiInfo);
        if (!diffType) {
          return;
        }
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
          oldApiInfo,
          newApiInfo,
          diffType.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
        );
        diffInfos.push(diffInfo);
      });
    }

    /**
     * 处理属性节点的类型
     *
     * @param {ApiInfo} oldApiInfo 旧版本的属性节点信息
     * @param {ApiInfo} newApiInfo 新版本的属性节点信息
     * @return {*}  {(ApiDiffType | undefined)} 属性节点的类型的变化情况
     */
    static diffPropertyType(oldApiInfo: PropertyInfo, newApiInfo: PropertyInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaPropertyType: string[] = oldApiInfo.getType();
      const newPropertyType: string[] = newApiInfo.getType();
      const oldPropertyIsReadOnly: boolean = oldApiInfo.getIsReadOnly();
      const newPropertyIsReadOnly: boolean = newApiInfo.getIsReadOnly();
      const olaPropertyTypeStr = olaPropertyType.toString();
      const newPropertyTypeStr = newPropertyType.toString();
      if (olaPropertyTypeStr === newPropertyTypeStr) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaPropertyTypeStr).setNewMessage(newPropertyTypeStr);
      if (StringUtils.hasSubstring(newPropertyTypeStr, olaPropertyTypeStr)) {
        return diffTypeInfo.setDiffType(
          newPropertyIsReadOnly ? ApiDiffType.PROPERTY_READONLY_ADD : ApiDiffType.PROPERTY_WRITABLE_ADD
        );
      }
      if (StringUtils.hasSubstring(olaPropertyTypeStr, newPropertyTypeStr)) {
        return diffTypeInfo.setDiffType(
          oldPropertyIsReadOnly ? ApiDiffType.PROPERTY_READONLY_REDUCE : ApiDiffType.PROPERTY_WRITABLE_REDUCE
        );
      }
      return diffTypeInfo.setDiffType(ApiDiffType.PROPERTY_TYPE_CHANGE);
    }

    /**
     * 处理属性节点的必选属性
     *
     * @param {ApiInfo} oldApiInfo 旧版本的属性节点信息
     * @param {ApiInfo} newApiInfo 新版本的属性节点信息
     * @return {*}  {(ApiDiffType | undefined)} 属性节点的必选属性的变化情况
     */
    static diffPropertyRequired(oldApiInfo: PropertyInfo, newApiInfo: PropertyInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const oldPropertyName: string = oldApiInfo.getApiName();
      const newPropertyName: string = newApiInfo.getApiName();
      const oldPropertyIsReadOnly: boolean = oldApiInfo.getIsReadOnly();
      //？？？只读属性是否会变为可写属性
      const propertyRequiredDiffMap: Map<string, ApiDiffType> = new Map([
        //old是否必选_new是否必选_old是否只读
        ['_true_false_true', ApiDiffType.PROPERTY_READONLY_TO_UNREQUIRED],
        ['_false_true_true', ApiDiffType.PROPERTY_READONLY_TO_REQUIRED],
        ['_true_false_false', ApiDiffType.PROPERTY_WRITABLE_TO_UNREQUIRED],
        ['_false_true_false', ApiDiffType.PROPERTY_WRITABLE_TO_REQUIRED],
      ]);
      const oldPropertyISRequired: boolean = oldApiInfo.getIsRequired();
      const newPropertyISRequired: boolean = newApiInfo.getIsRequired();

      if (oldPropertyName === newPropertyName && oldPropertyISRequired === newPropertyISRequired) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(oldApiInfo.getDefinedText()).setNewMessage(newApiInfo.getDefinedText());
      const paramRequiredStr: string = `_${!!oldPropertyISRequired}_${!!newPropertyISRequired}_${!!oldPropertyIsReadOnly}`;
      const paramRequiredType: ApiDiffType = propertyRequiredDiffMap.get(paramRequiredStr) as ApiDiffType;
      return diffTypeInfo.setDiffType(paramRequiredType);
    }

    /**
     * 处理常量节点,获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的常量节点信息
     * @param {ApiInfo} newApiInfo 新版本的常量节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     */
    static diffConstant(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      constantDiffProcessors.forEach((constantDiffProcessor: ApiSceneDiffProcessor) => {
        const diffTypeInfo: DiffTypeInfo | undefined = constantDiffProcessor(oldApiInfo, newApiInfo);
        if (!diffTypeInfo) {
          return;
        }
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
          oldApiInfo,
          newApiInfo,
          diffTypeInfo.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
        );
        diffInfos.push(diffInfo);
      });
    }

    /**
     * 处理常量节点的值
     *
     * @param {ConstantInfo} oldApiInfo 旧版本的常量节点信息
     * @param {ConstantInfo} newApiInfo 新版本的常量节点信息
     * @return {*}  {(ApiDiffType | undefined)} 常量节点的值的变化情况
     */
    static diffConstantValue(oldApiInfo: ConstantInfo, newApiInfo: ConstantInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaConstantValue: string = oldApiInfo.getValue();
      const newConstantValue: string = newApiInfo.getValue();
      if (olaConstantValue === newConstantValue) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaConstantValue).setNewMessage(newConstantValue);
      return diffTypeInfo.setDiffType(ApiDiffType.CONSTANT_VALUE_CHANGE);
    }

    /**
     * 处理自定义类型节点,过去对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的自定义类型节点信息
     * @param {ApiInfo} newApiInfo 新版本的自定义类型节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     */
    static diffTypeAlias(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      typeAliasDiffProcessors.forEach((typeAliasDiffProcessor: ApiSceneDiffProcessor) => {
        const diffTypeInfo: DiffTypeInfo | undefined = typeAliasDiffProcessor(oldApiInfo, newApiInfo);
        if (!diffTypeInfo) {
          return;
        }
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(oldApiInfo, newApiInfo, diffTypeInfo);
        diffInfos.push(diffInfo);
      });
    }

    /**
     * 处理自定义类型节点的类型
     *
     * @param {TypeAliasInfo} oldApiInfo 旧版本的自定义类型节点信息
     * @param {TypeAliasInfo} newApiInfo 新版本的自定义类型节点信息
     * @return {*}  {(ApiDiffType | undefined)} 自定义类型节点的类型的变化情况
     */
    static diffTypeAliasType(oldApiInfo: TypeAliasInfo, newApiInfo: TypeAliasInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaTypeAliasType: string[] = oldApiInfo.getType();
      const newTypeAliasType: string[] = newApiInfo.getType();
      const olaTypeAliasTypeStr: string = olaTypeAliasType.toString();
      const newTypeAliasTypeStr: string = newTypeAliasType.toString();
      if (olaTypeAliasTypeStr === newTypeAliasTypeStr) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaTypeAliasTypeStr).setNewMessage(newTypeAliasTypeStr);
      if (StringUtils.hasSubstring(newTypeAliasTypeStr, olaTypeAliasTypeStr)) {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_ALIAS_ADD);
      }
      if (StringUtils.hasSubstring(olaTypeAliasTypeStr, newTypeAliasTypeStr)) {
        return diffTypeInfo.setDiffType(ApiDiffType.TYPE_ALIAS_REDUCE);
      }
      return diffTypeInfo.setDiffType(ApiDiffType.TYPE_ALIAS_CHANGE);
    }

    /**
     * 处理枚举值节点，获取对应diff信息
     *
     * @param {ApiInfo} oldApiInfo 旧版本的枚举值节点信息
     * @param {ApiInfo} newApiInfo 新版本的枚举值节点信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     */
    static diffEnum(oldApiInfo: ApiInfo, newApiInfo: ApiInfo, diffInfos: BasicDiffInfo[]): void {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const oldEnumName: string = oldApiInfo.getApiName();
      const newEnumName: string = newApiInfo.getApiName();
      if (oldEnumName === newEnumName) {
        return;
      }
      diffTypeInfo.setDiffType(ApiDiffType.API_NAME_CHANGE).setOldMessage(oldEnumName).setNewMessage(newEnumName);
      const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
        oldApiInfo,
        newApiInfo,
        diffTypeInfo.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
      );
      diffInfos.push(diffInfo);
    }

    /**
     * 处理枚举值节点的每个元素，获取对应diff信息
     *
     * @param {EnumValueInfo} oldApiInfo 旧版本的枚举值节点元素信息
     * @param {EnumValueInfo} newApiInfo 新版本的枚举值节点元素信息
     * @param {BasicDiffInfo[]} diffInfos 各个节点diff信息集合
     */
    static diffEnumMember(oldApiInfo: EnumValueInfo, newApiInfo: EnumValueInfo, diffInfos: BasicDiffInfo[]): void {
      enumDiffProcessors.forEach((enumDiffProcessor: ApiSceneDiffProcessor) => {
        const diffTypeInfo: DiffTypeInfo | undefined = enumDiffProcessor(oldApiInfo, newApiInfo);
        if (!diffTypeInfo) {
          return;
        }
        const diffInfo: BasicDiffInfo = DiffProcessorHelper.wrapDiffInfo(
          oldApiInfo,
          newApiInfo,
          diffTypeInfo.setStatusCode(ApiStatusCode.FUNCTION_CHANGES)
        );
        diffInfos.push(diffInfo);
      });
    }

    /**
     * 处理枚举值节点的每个元素的值
     *
     * @param {EnumValueInfo} oldApiInfo 旧版本的枚举值节点元素信息
     * @param {EnumValueInfo} newApiInfo 新版本的枚举值节点元素信息
     * @return {*}  {(ApiDiffType | undefined)} 枚举值节点的每个元素的值的变化情况
     */
    static diffEnumMemberValue(oldApiInfo: EnumValueInfo, newApiInfo: EnumValueInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaEnumMemberValue: string = oldApiInfo.getValue();
      const newEnumMemberValue: string = newApiInfo.getValue();
      if (olaEnumMemberValue === newEnumMemberValue) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaEnumMemberValue).setNewMessage(newEnumMemberValue);
      return diffTypeInfo.setDiffType(ApiDiffType.ENUM_MEMBER_VALUE_CHANGE);
    }

    /**
     * 处理通用类型节点的apiName
     *
     * @param {ApiInfo} oldApiInfo 旧版本的节点信息
     * @param {ApiInfo} newApiInfo 新版本的节点信息
     * @return {*}  {(ApiDiffType | undefined)} apiName的变化情况
     */
    static diffApiName(oldApiInfo: ApiInfo, newApiInfo: ApiInfo): DiffTypeInfo | undefined {
      const diffTypeInfo: DiffTypeInfo = new DiffTypeInfo();
      const olaConstantName: string = oldApiInfo.getApiName();
      const newConstantName: string = newApiInfo.getApiName();
      if (olaConstantName === newConstantName) {
        return undefined;
      }
      diffTypeInfo.setOldMessage(olaConstantName).setNewMessage(newConstantName);
      return diffTypeInfo.setDiffType(ApiDiffType.API_NAME_CHANGE);
    }
  }

  /**
   * 根据节点信息和type生成需要的diff对象
   *
   * @param {(BasicApiInfo | undefined)} [oldApiInfo=undefined] 旧版本节点信息，默认undefined
   * @param {(BasicApiInfo | undefined)} [newApiInfo=undefined] 新版本节点信息，默认undefined
   * @param {ApiDiffType} diffType diff的节点类型
   * @return {*}  {BasicDiffInfo} 生成的diff对象
   */
  export function wrapDiffInfo(
    oldApiInfo: BasicApiInfo | undefined = undefined,
    newApiInfo: BasicApiInfo | undefined = undefined,
    diffTypeInfo: DiffTypeInfo
  ): BasicDiffInfo {
    const diffInfo: BasicDiffInfo = new BasicDiffInfo();
    const diffType: ApiDiffType = diffTypeInfo.getDiffType();
    if (oldApiInfo) {
      processOldApiDiff(oldApiInfo, diffInfo);
    }
    if (newApiInfo) {
      processNewApiDiff(newApiInfo, diffInfo);
    }
    diffInfo
      .setDiffType(diffType)
      .setDiffMessage(diffMap.get(diffType) as string)
      .setIsCompatible(!incompatibleApiDiffTypes.has(diffType))
      .setStatusCode(diffTypeInfo.getStatusCode())
      .setOldDescription(diffTypeInfo.getOldMessage())
      .setNewDescription(diffTypeInfo.getNewMessage());
    return diffInfo;
  }

  /**
   * 添加旧版本的基础信息
   *
   * @param {BasicApiInfo} oldApiInfo 旧版本的节点信息
   * @param {BasicDiffInfo} diffInfo 需要填充的diff对象
   */
  function processOldApiDiff(oldApiInfo: BasicApiInfo, diffInfo: BasicDiffInfo): void {
    const clonedOldApiInfo: ApiInfo = oldApiInfo as ApiInfo;
    const kitInfo: string | undefined = clonedOldApiInfo.getLastJsDocInfo()?.getKit();
    if (kitInfo) {
      diffInfo.setOldKitInfo(kitInfo);
    }

    diffInfo
      .setOldApiDefinedText(oldApiInfo.getDefinedText())
      .setApiType(oldApiInfo.getApiType())
      .setOldApiName(oldApiInfo.getApiName())
      .setOldDtsName(oldApiInfo.getFilePath())
      .setOldHierarchicalRelations(oldApiInfo.getHierarchicalRelations())
      .setOldPos(oldApiInfo.getPos())
      .setOldSyscapField(oldApiInfo.getSyscap());
  }

  /**
   * 添加新版本的基础信息
   *
   * @param {BasicApiInfo} newApiInfo 新版本的节点信息
   * @param {BasicDiffInfo} diffInfo 需要填充的diff对象
   */
  function processNewApiDiff(newApiInfo: BasicApiInfo, diffInfo: BasicDiffInfo): void {
    const clonedOldApiInfo: ApiInfo = newApiInfo as ApiInfo;
    const kitInfo: string | undefined = clonedOldApiInfo.getLastJsDocInfo()?.getKit();
    if (kitInfo) {
      diffInfo.setNewKitInfo(kitInfo);
    }
    diffInfo
      .setNewApiDefinedText(newApiInfo.getDefinedText())
      .setApiType(newApiInfo.getApiType())
      .setNewApiName(newApiInfo.getApiName())
      .setNewDtsName(newApiInfo.getFilePath())
      .setNewHierarchicalRelations(newApiInfo.getHierarchicalRelations())
      .setNewPos(newApiInfo.getPos())
      .setNewSyscapField(newApiInfo.getSyscap());
  }
  /**
   * api节点类型对应的处理方法，获取diff信息
   */
  export const apiNodeDiffMethod: Map<string, ApiNodeDiffProcessor> = new Map([
    [ApiType.PROPERTY, ApiNodeDiffHelper.diffProperty],
    [ApiType.CLASS, ApiNodeDiffHelper.diffClass],
    [ApiType.INTERFACE, ApiNodeDiffHelper.diffInterface],
    [ApiType.NAMESPACE, ApiNodeDiffHelper.diffNamespace],
    [ApiType.METHOD, ApiNodeDiffHelper.diffMethod],
    [ApiType.CONSTANT, ApiNodeDiffHelper.diffConstant],
    [ApiType.ENUM, ApiNodeDiffHelper.diffEnum],
    [ApiType.ENUM_VALUE, ApiNodeDiffHelper.diffEnumMember],
    [ApiType.TYPE_ALIAS, DiffProcessorHelper.ApiNodeDiffHelper.diffTypeAlias],
  ]);

  /**
   * api节点jsdoc需要处理的数据，获取diff信息
   */
  export const jsDocDiffProcessors: JsDocDiffProcessor[] = [
    JsDocDiffHelper.diffSyscap,
    JsDocDiffHelper.diffDeprecated,
    JsDocDiffHelper.diffPermissions,
    JsDocDiffHelper.diffErrorCodes,
    JsDocDiffHelper.diffIsForm,
    JsDocDiffHelper.diffIsCrossPlatForm,
    JsDocDiffHelper.diffModelLimitation,
    JsDocDiffHelper.diffIsSystemApi,
  ];

  /**
   * 枚举值节点需要处理的数据
   */
  export const enumDiffProcessors: ApiSceneDiffProcessor[] = [
    ApiNodeDiffHelper.diffApiName,
    ApiNodeDiffHelper.diffEnumMemberValue,
  ];

  /**
   * 自定义类型节点需要处理的数据
   */
  export const typeAliasDiffProcessors: ApiSceneDiffProcessor[] = [
    ApiNodeDiffHelper.diffApiName,
    ApiNodeDiffHelper.diffTypeAliasType,
  ];

  /**
   * 常量节点需要处理的数据
   */
  export const constantDiffProcessors: ApiSceneDiffProcessor[] = [
    ApiNodeDiffHelper.diffApiName,
    ApiNodeDiffHelper.diffConstantValue,
  ];

  /**
   * 属性节点需要处理的数据
   */
  export const propertyDiffProcessors: ApiSceneDiffProcessor[] = [
    ApiNodeDiffHelper.diffApiName,
    ApiNodeDiffHelper.diffPropertyType,
    ApiNodeDiffHelper.diffPropertyRequired,
  ];

  /**
   * 属性节点需要处理的数据
   */
  export const methodDiffProcessors: ApiScenesDiffProcessor[] = [
    ApiNodeDiffHelper.diffApiName,
    ApiNodeDiffHelper.diffMethodReturnType,
    ApiNodeDiffHelper.diffMethodParams,
  ];
}
