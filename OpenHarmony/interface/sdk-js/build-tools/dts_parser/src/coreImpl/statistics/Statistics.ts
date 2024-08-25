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
  ContainerApiInfo,
  containerApiTypes,
  notJsDocApiTypes,
} from '../../typedef/parser/ApiInfoDefination';
import {
  ApiStatisticsInfo,
  apiNotStatisticsType,
  apiStatisticsType,
  mergeDefinedTextType,
  notMergeDefinedText,
  StatisticsInfoValueType,
} from '../../typedef/statistics/ApiStatistics';
import { Comment } from '../../typedef/parser/Comment';
import { StringConstant, NumberConstant } from '../../utils/Constant';
import { ApiInfosMap, FileInfoMap, FilesMap, BasicApiInfoMap } from '../parser/parser';
import { LogUtil } from '../../utils/logUtil';
import ts from 'typescript';

export class ApiStatisticsHelper {
  /**
   * 获取需要收集的api信息
   *
   * @param { FilesMap } apiMap 根据接口定义文件处理得到的map结果
   * @returns { ApiStatisticsInfo[] } 返回需要统计的api列表
   */
  static getApiStatisticsInfos(apiMap: FilesMap): StatisticsInfoValueType {
    const apiStatisticsInfos: ApiStatisticsInfo[] = [];
    const allApiStatisticsInfos: ApiStatisticsInfo[] = [];
    // map的第一层key均为文件路径名
    for (const filePath of apiMap.keys()) {
      const fileMap: FileInfoMap | undefined = apiMap.get(filePath);
      if (!fileMap) {
        continue;
      }
      ApiStatisticsHelper.processFileApiMap(fileMap, apiStatisticsInfos, allApiStatisticsInfos);
    }
    return { apiStatisticsInfos: apiStatisticsInfos, allApiStatisticsInfos: allApiStatisticsInfos };
  }

  /**
   * 得到SourceFile节点下的第一层节点解析后的对象，方便后续以此为基础，得到整个文件所有的节点信息
   *
   * @param { FileInfoMap } fileMap 获取到的一个文件解析到的map对象
   * @param { ApiStatisticsInfo[] } apiStatisticsInfos SourceFile节点下的第一层节点解析后的对象
   */
  static processFileApiMap(
    fileMap: FileInfoMap,
    apiStatisticsInfos: ApiStatisticsInfo[],
    allApiStatisticsInfos: ApiStatisticsInfo[]
  ): void {
    for (const apiKey of fileMap.keys()) {
      if (apiKey === StringConstant.SELF) {
        continue;
      }
      const apiInfoMap: ApiInfosMap | BasicApiInfo[] | undefined = fileMap.get(apiKey);
      if (!apiInfoMap || Array.isArray(apiInfoMap)) {
        continue;
      }
      const apiInfos: BasicApiInfo[] | BasicApiInfoMap | undefined = apiInfoMap.get(StringConstant.SELF);
      const sameNameRawTextMap: Map<string, string> = new Map();
      if (!apiInfos || !Array.isArray(apiInfos)) {
        continue;
      }
      ApiStatisticsHelper.connectDefinedText(apiInfos, sameNameRawTextMap);
      const apiRelations: Set<string> = new Set();
      apiInfos.forEach((apiInfo: BasicApiInfo) => {
        ApiStatisticsHelper.processApiInfo(
          apiInfo,
          apiStatisticsInfos,
          sameNameRawTextMap,
          allApiStatisticsInfos,
          apiRelations
        );
      });
    }
  }

  /**
   * 遍历一个文件内的所有API，将同名函数的API声明合并
   *
   * @param { BasicApiInfo[] } apiInfos 存放API信息的数组
   * @param { Map<string, string> } sameNameRawTextMap 存放处理后的同名函数声明
   */
  static connectDefinedText(apiInfos: BasicApiInfo[], sameNameRawTextMap: Map<string, string>): void {
    apiInfos.forEach((apiInfo: BasicApiInfo) => {
      if (apiInfo.getApiType() === ApiType.METHOD) {
        if (notMergeDefinedText.has(apiInfo.getApiName())) {
          return;
        }
        const currentApiText: string | undefined = sameNameRawTextMap.get(ApiStatisticsHelper.joinRelations(apiInfo));
        if (currentApiText) {
          const definedText: string = `${currentApiText}\n${apiInfo.getDefinedText()}`;
          sameNameRawTextMap.set(ApiStatisticsHelper.joinRelations(apiInfo), definedText);
          return;
        } else {
          sameNameRawTextMap.set(ApiStatisticsHelper.joinRelations(apiInfo), apiInfo.getDefinedText());
        }
      }

      if (containerApiTypes.has(apiInfo.getApiType())) {
        const containerApiInfo: ContainerApiInfo = apiInfo as ContainerApiInfo;
        ApiStatisticsHelper.connectDefinedText(containerApiInfo.getChildApis(), sameNameRawTextMap);
      }
    });
  }

  /**
   * 处理API层级关系
   *
   * @param { BasicApiInfo } childApiInfo API信息
   * @returns
   */
  static joinRelations(childApiInfo: BasicApiInfo): string {
    const relations = childApiInfo.getHierarchicalRelations().join();
    return relations;
  }

  /**
   * 根据传入的api信息，转化为需要统计的api信息对象并统计
   *
   * @param { BasicApiInfo } basicApiInfo 解析后的api对象
   * @param apiStatisticsInfos api统计列表对象
   */
  static processApiInfo(
    basicApiInfo: BasicApiInfo,
    apiStatisticsInfos: ApiStatisticsInfo[],
    sameNameRawTextMap: Map<string, string>,
    allApiStatisticsInfos: ApiStatisticsInfo[],
    apiRelations: Set<string>
  ): void {
    const apiInfo: ApiInfo = basicApiInfo as ApiInfo;
    allApiStatisticsInfos.push(ApiStatisticsHelper.initApiStatisticsInfo(apiInfo, sameNameRawTextMap, true));

    if (!apiStatisticsType.has(basicApiInfo.getApiType())) {
      return;
    }
    if (basicApiInfo.getApiName() === StringConstant.CONSTRUCTOR_API_NAME) {
      return;
    }
    const apiStatisticsInfo: ApiStatisticsInfo = ApiStatisticsHelper.initApiStatisticsInfo(apiInfo, sameNameRawTextMap);
    if (
      !apiNotStatisticsType.has(apiStatisticsInfo.getApiType()) &&
      !apiRelations.has(ApiStatisticsHelper.joinRelations(basicApiInfo))
    ) {
      apiStatisticsInfos.push(apiStatisticsInfo);
    }
    apiRelations.add(ApiStatisticsHelper.joinRelations(basicApiInfo));
    if (!containerApiTypes.has(apiInfo.getApiType())) {
      return;
    }
    const containerApiInfo: ContainerApiInfo = apiInfo as ContainerApiInfo;
    containerApiInfo.getChildApis().forEach((childApiInfo: BasicApiInfo) => {
      ApiStatisticsHelper.processApiInfo(
        childApiInfo,
        apiStatisticsInfos,
        sameNameRawTextMap,
        allApiStatisticsInfos,
        apiRelations
      );
    });
  }

  static initApiStatisticsInfo(
    apiInfo: ApiInfo,
    sameNameRawTextMap: Map<string, string>,
    isAll?: boolean
  ): ApiStatisticsInfo {
    const apiStatisticsInfo: ApiStatisticsInfo = new ApiStatisticsInfo();
    const relations = apiInfo.getHierarchicalRelations();
    if (relations.length > NumberConstant.RELATION_LENGTH) {
      apiStatisticsInfo.setParentModuleName(relations[relations.length - NumberConstant.RELATION_LENGTH]);
    }
    const apiRelations: string = ApiStatisticsHelper.joinRelations(apiInfo);
    const sameNameDefinedText: string | undefined = sameNameRawTextMap.get(apiRelations);

    if (isAll) {
      apiStatisticsInfo.setDefinedText(apiInfo.getDefinedText());
    } else {
      apiStatisticsInfo.setDefinedText(sameNameDefinedText ? sameNameDefinedText : apiInfo.getDefinedText());
    }
    apiStatisticsInfo
      .setFilePath(apiInfo.getFilePath())
      .setApiType(apiInfo.getApiType())
      .setApiName(apiInfo.getApiName())
      .setPos(apiInfo.getPos())
      .setHierarchicalRelations(relations.join('/'))
      .setDecorators(apiInfo.getDecorators());
    if (notJsDocApiTypes.has(apiInfo.getApiType())) {
      return apiStatisticsInfo;
    }
    const firstJsDocInfo: Comment.JsDocInfo | undefined = apiInfo.getJsDocInfos()[0];
    if (firstJsDocInfo) {
      apiStatisticsInfo.setSince(firstJsDocInfo.getSince());
    }
    const jsDocInfo: Comment.JsDocInfo | undefined = apiInfo.getLastJsDocInfo();
    if (jsDocInfo) {
      apiStatisticsInfo
        .setSyscap(jsDocInfo.getSyscap() ? jsDocInfo.getSyscap() : ApiStatisticsHelper.extendSyscap(apiInfo))
        .setPermission(jsDocInfo.getPermission())
        .setIsForm(jsDocInfo.getIsForm())
        .setIsCrossPlatForm(jsDocInfo.getIsCrossPlatForm())
        .setDeprecatedVersion(
          jsDocInfo.getDeprecatedVersion() === NumberConstant.DEFAULT_DEPRECATED_VERSION ?
            '' :
            jsDocInfo.getDeprecatedVersion()
        )
        .setUseInstead(jsDocInfo.getUseinstead())
        .setApiLevel(jsDocInfo.getIsSystemApi())
        .setModelLimitation(jsDocInfo.getModelLimitation())
        .setIsAutomicService(jsDocInfo.getIsAtomicService())
        .setErrorCodes(jsDocInfo.getErrorCode())
        .setKitInfo(jsDocInfo.getKit());
    } else {
      apiStatisticsInfo.setSyscap(ApiStatisticsHelper.extendSyscap(apiInfo));
    }
    return apiStatisticsInfo;
  }

  /**
   * 未标注@syscap的API，从父级API寻找syscap
   *
   * @param {ApiInfo} apiInfo API信息
   * @returns syscap
   */
  static extendSyscap(apiInfo: ApiInfo): string {
    let curApiInfo: ApiInfo = apiInfo;
    let syscap: string = '';
    const node: ts.Node | undefined = curApiInfo.getNode();
    try {
      while (node && curApiInfo && !ts.isSourceFile(node)) {
        const jsdoc: Comment.JsDocInfo | undefined = curApiInfo.getLastJsDocInfo();
        if (jsdoc) {
          syscap = jsdoc.getSyscap();
        }
        if (syscap) {
          return syscap;
        }
        curApiInfo = curApiInfo.getParentApi() as ApiInfo;
      }
    } catch (error) {
      LogUtil.e('SYSCAP ERROR', error);
    }
    return syscap;
  }

  /**
   * 获取api的总数
   *
   * @param { ApiStatisticsInfo[] } apiStatisticsInfos api统计列表对象
   * @returns { number } api的数量
   */
  static getApiNumber(apiStatisticsInfos: ApiStatisticsInfo[]): number {
    const apis: Set<string> = new Set();
    apiStatisticsInfos.forEach((apiStatisticsInfo: ApiStatisticsInfo) => {
      apis.add(apiStatisticsInfo.getHierarchicalRelations());
    });
    return apis.size;
  }
}
