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

import { Comment } from '../../typedef/parser/Comment';
import { StringConstant } from '../../utils/Constant';
import {
  ApiInfo,
  ApiType,
  BasicApiInfo,
  ContainerApiInfo,
  containerApiTypes,
  ClassInfo,
  ConstantInfo,
  EnumInfo,
  EnumValueInfo,
  ExportDeclareInfo,
  ExportDefaultInfo,
  ExportImportValue,
  ImportInfo,
  InterfaceInfo,
  MethodInfo,
  MethodType,
  ModifierProcessorInterface,
  ModuleInfo,
  NamespaceInfo,
  NodeProcessorInterface,
  ParamInfo,
  PropertyInfo,
  PropertyNode,
  TypeAliasInfo,
  TypeAliasType,
} from '../../typedef/parser/ApiInfoDefination';
import * as ResultsInfo from '../../typedef/parser/ResultsInfo';
import { ApiInfosMap, BasicApiInfoMap, FileInfoMap, FilesMap } from './parser';

/**
 * 处理解析完节点数据的方法
 */
export class ResultsProcessHelper {
  // 如果是字符串的话，会出现单双引号重复的情况
  static regQuotation: RegExp = /^[\'|\"](.*)[\'|\"]$/;
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
   * 获取SourceFile节点下的第一层节点解析后的对象
   *
   * @param { FileInfoMap } fileMap 获取到的一个文件解析到的map对象
   * @return {BasicApiInfo[]}  SourceFile节点下的第一层节点解析后的对象
   */
  static processFileApiMap(fileMap: FileInfoMap): BasicApiInfo[] {
    const apis: BasicApiInfo[] = [];
    for (const apiKey of fileMap.keys()) {
      const apiInfos: BasicApiInfo[] = ResultsProcessHelper.getApiInfosInFileMap(fileMap, apiKey);
      apiInfos.forEach((apiInfo: BasicApiInfo) => {
        ResultsProcessHelper.processApiInfo(apiInfo);
        apis.push(apiInfo);
      });
    }
    return apis;
  }

  /**
   * 将每一个节点解析后的对象的parentApi属性置为undefined，防止循环引用
   *
   * @param { BasicApiInfo } basicApiInfo 解析后的api对象
   */
  static processApiInfo(basicApiInfo: BasicApiInfo): void {
    basicApiInfo.setParentApi(undefined);
    basicApiInfo.removeNode();
    ResultsProcessHelper.processJsDocInfos(basicApiInfo as ApiInfo);
    if (!containerApiTypes.has(basicApiInfo.getApiType())) {
      return;
    }
    const containerApiInfo: ContainerApiInfo = basicApiInfo as ContainerApiInfo;
    containerApiInfo.getChildApis().forEach((childApiInfo: BasicApiInfo) => {
      ResultsProcessHelper.processApiInfo(childApiInfo);
    });
  }

  /**
   * 判断jsdoc节点，去除tag数组
   *
   * @param {ApiInfo} apiInfo
   * @return {void}
   */
  static processJsDocInfos(apiInfo: ApiInfo): void {
    if (!(apiInfo instanceof ApiInfo)) {
      return;
    }
    const jsDocInfos: Comment.JsDocInfo[] = apiInfo.getJsDocInfos();
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      jsDocInfo.removeTags();
    });
  }

  /**
   * 解析整个文件所有api
   *
   * @param {FileInfoMap} fileMap 文件对象
   * @return {BasicApiInfo[]} 整个文件的所有api
   */
  static processFileApiMapForGetBasicApi(fileMap: FileInfoMap): BasicApiInfo[] {
    let apis: BasicApiInfo[] = [];
    for (const apiKey of fileMap.keys()) {
      const apiInfos: BasicApiInfo[] = ResultsProcessHelper.getApiInfosInFileMap(fileMap, apiKey);
      apiInfos.forEach((apiInfo: BasicApiInfo) => {
        apis = apis.concat(ResultsProcessHelper.processApiInfoForGetBasicApi(apiInfo));
      });
    }
    return apis;
  }

  /**
   * 获取一个api的所有子节点，例如NamespaceInfo | ClassInfo | InterfaceInfo | EnumInfo | ModuleInfo | StructInfo
   *
   * @param { BasicApiInfo } basicApiInfo 解析后的api对象
   * @return { BasicApiInfo[] } 递归获取有子节点的api的所有api
   */
  static processApiInfoForGetBasicApi(basicApiInfo: BasicApiInfo): BasicApiInfo[] {
    let apis: BasicApiInfo[] = [];
    apis = apis.concat(basicApiInfo);
    if (!containerApiTypes.has(basicApiInfo.getApiType())) {
      return apis;
    }
    const containerApiInfo: ContainerApiInfo = basicApiInfo as ContainerApiInfo;
    containerApiInfo.getChildApis().forEach((childApiInfo: BasicApiInfo) => {
      apis = apis.concat(ResultsProcessHelper.processApiInfoForGetBasicApi(childApiInfo));
    });
    return apis;
  }
  /**
   * 获取SourceFile节点下的第一层节点解析后的对象，需要将JsDoc按照since的版本进行拆分
   * 1、子节点的since必须大于等于父节点的since，小于的进行剔除
   * 2、一个节点出现多段JsDoc时，将会拆分成多个节点，每个节点包含对应版本的子节点
   * 3、JsDoc中since默认为-1，可以存在一段没有since的JsDoc
   * 3、当节点没有JsDoc时设置since默认为-1，其他信息默认
   *
   * @param { FileInfoMap } fileMap
   * @return  { Array<Comment.jsDocEachSince> }
   */
  static processFileApiMapForEachSince(fileMap: FileInfoMap): Array<ResultsInfo.BasicApiInfo> {
    const apis: ResultsInfo.BasicApiInfo[] = [];
    for (const apiKey of fileMap.keys()) {
      const apiInfos: BasicApiInfo[] = ResultsProcessHelper.getApiInfosInFileMap(fileMap, apiKey);
      apiInfos.forEach((apiInfo: BasicApiInfo) => {
        const api: ResultsInfo.BasicApiInfo[] = ResultsProcessHelper.processApiInfoForEachSince(apiInfo);
        if (api.length === 0) {
          return;
        }
        apis.push(...api);
      });
    }
    return apis;
  }

  /**
   * 获取到文件下每个节点的数据，解析jsdoc中的since信息，根据规则提取出对应数组
   *
   * @param {BasicApiInfo} basicApiInfo 一级节点信息
   * @return {ResultsInfo.BasicApiInfo[]}
   */
  static processApiInfoForEachSince(basicApiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const resultApis: ResultsInfo.BasicApiInfo[] = ResultsProcessHelper.getNodeInfo(basicApiInfo);
    if (!containerApiTypes.has(basicApiInfo.getApiType())) {
      return resultApis;
    }
    const containerApiInfo: ContainerApiInfo = basicApiInfo as ContainerApiInfo;
    containerApiInfo.getChildApis().forEach((childApiInfo: BasicApiInfo) => {
      const childApis: ResultsInfo.BasicApiInfo[] = ResultsProcessHelper.processApiInfoForEachSince(childApiInfo);
      ResultsProcessHelper.mergeResultApis(resultApis, childApis);
    });
    return resultApis;
  }

  /**
   * 根据父节点和子节点，将子节点中满足父节点的版本要求的数据填充到父节点
   *
   * @param {ResultsInfo.BasicApiInfo[]} parentApis 父节点信息，根据jsdoc分段
   * @param {ResultsInfo.BasicApiInfo[]} childApis 子节点信息，根据jsdoc分段
   */
  static mergeResultApis(parentApis: ResultsInfo.BasicApiInfo[], childApis: ResultsInfo.BasicApiInfo[]): void {
    parentApis.forEach((parentApi: ResultsInfo.BasicApiInfo) => {
      const containerApiInfo: ResultsInfo.NamespaceEnumInfo = parentApi as ResultsInfo.NamespaceEnumInfo;
      const cApis: ResultsInfo.BasicApiInfo[] = ResultsProcessHelper.getResultApisVersion(
        childApis,
        Number(containerApiInfo.getSince())
      );
      containerApiInfo.addChildApi(cApis);
    });
  }

  /**
   * 在多段jsdoc数据中提取符合版本的数据
   *
   * @param {ResultsInfo.BasicApiInfo[]} resultApis
   * @param {number} version
   * @return {ResultsInfo.BasicApiInfo[]}
   */
  static getResultApisVersion(resultApis: ResultsInfo.BasicApiInfo[], version: number): ResultsInfo.BasicApiInfo[] {
    return resultApis.filter((resultApi: ResultsInfo.BasicApiInfo) => {
      const apiInfo: ResultsInfo.ApiInfo = resultApi as ResultsInfo.ApiInfo;
      const since: number = Number(apiInfo.getSince());
      return since === -1 || since >= version;
    });
  }

  /**
   * 按节点的类型分类处理，拆分多段jsdoc
   *
   * @param {BasicApiInfo} apiInfo 节点信息
   * @return {ResultsInfo.BasicApiInfo[]}
   */
  static getNodeInfo(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    let apiType: string = apiInfo.getApiType();
    const nodeProcessor: ResultsInfo.NodeProcessorInterface | undefined = resultsProcessMethod.get(apiType);
    if (!nodeProcessor) {
      return [];
    }
    const newApiInfos: ResultsInfo.BasicApiInfo[] = nodeProcessor(apiInfo);
    return newApiInfos;
  }

  static processProperty(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.PropertyInfo[] = [];
    const propertyInfo: PropertyInfo = apiInfo as PropertyInfo;
    const jsDocInfos: Comment.JsDocInfo[] = propertyInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.PropertyInfo = new ResultsInfo.PropertyInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setType(propertyInfo.getType().join(' | '));
      newInfo.setName(apiInfo.getApiName());
      newInfo.setIsRequired(propertyInfo.getIsRequired());
      newInfo.setIsReadOnly(propertyInfo.getIsReadOnly());
      newInfo.setIsStatic(propertyInfo.getIsStatic());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.PropertyInfo = new ResultsInfo.PropertyInfo(apiInfo.getApiType(), jsDocInfo);
      const typeInfo: string = jsDocInfo.getTypeInfo();
      const isRequired: boolean = !/\?/.test(typeInfo);
      newInfo.setType(typeInfo ? typeInfo.replace(/^[\?]*[\(](.*)[\)]$/, '$1') : propertyInfo.getType().join(' | '));
      newInfo.setName(apiInfo.getApiName());
      newInfo.setIsRequired(isRequired ? true : propertyInfo.getIsRequired());
      newInfo.setIsReadOnly(propertyInfo.getIsReadOnly());
      newInfo.setIsStatic(propertyInfo.getIsStatic());
      infos.push(newInfo);
    });
    return infos;
  }

  static processClass(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.ClassInterfaceInfo[] = [];
    const classInfo: ClassInfo = apiInfo as ClassInfo;
    const jsDocInfos: Comment.JsDocInfo[] = classInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.ClassInterfaceInfo = new ResultsInfo.ClassInterfaceInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setParentClasses(classInfo.getParentClasses());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.ClassInterfaceInfo = new ResultsInfo.ClassInterfaceInfo(
        apiInfo.getApiType(),
        jsDocInfo
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setParentClasses(classInfo.getParentClasses());
      infos.push(newInfo);
    });
    return infos;
  }

  static processInterface(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.ClassInterfaceInfo[] = [];
    const interfaceInfo: InterfaceInfo = apiInfo as InterfaceInfo;
    const jsDocInfos: Comment.JsDocInfo[] = interfaceInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.ClassInterfaceInfo = new ResultsInfo.ClassInterfaceInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setParentClasses(interfaceInfo.getParentClasses());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.ClassInterfaceInfo = new ResultsInfo.ClassInterfaceInfo(
        apiInfo.getApiType(),
        jsDocInfo
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setParentClasses(interfaceInfo.getParentClasses());
      infos.push(newInfo);
    });
    return infos;
  }

  static processNamespace(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.NamespaceEnumInfo[] = [];
    const interfaceInfo: NamespaceInfo = apiInfo as NamespaceInfo;
    const jsDocInfos: Comment.JsDocInfo[] = interfaceInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.NamespaceEnumInfo = new ResultsInfo.NamespaceEnumInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.NamespaceEnumInfo = new ResultsInfo.NamespaceEnumInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      infos.push(newInfo);
    });
    return infos;
  }

  static processMethod(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.MethodInfo[] = [];
    const methodInfo: MethodInfo = apiInfo as MethodInfo;
    const jsDocInfos: Comment.JsDocInfo[] = methodInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.MethodInfo = new ResultsInfo.MethodInfo(apiInfo.getApiType(), new Comment.JsDocInfo());
      newInfo.setName(apiInfo.getApiName());
      newInfo.setCallForm(methodInfo.getCallForm());
      newInfo.setReturnValue(methodInfo.getReturnValue().join(' | '));
      methodInfo.getParams().forEach((param: ParamInfo) => {
        const newParam: ResultsInfo.ParamInfo = new ResultsInfo.ParamInfo(param.getApiType(), new Comment.JsDocInfo());
        newParam.setName(param.getApiName());
        newParam.setType(param.getType().join(' | '));
        newParam.setIsRequired(param.getIsRequired());
        newInfo.addParam(newParam);
      });
      newInfo.setIsStatic(methodInfo.getIsStatic());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.MethodInfo = new ResultsInfo.MethodInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      newInfo.setCallForm(methodInfo.getCallForm());
      newInfo.setReturnValue(methodInfo.getReturnValue().join(' | '));
      methodInfo.getParams().forEach((param: ParamInfo) => {
        const newParam: ResultsInfo.ParamInfo = new ResultsInfo.ParamInfo(param.getApiType(), new Comment.JsDocInfo());
        newParam.setName(param.getApiName());
        newParam.setType(param.getType().join(' | '));
        newParam.setIsRequired(param.getIsRequired());
        newInfo.addParam(newParam);
      });
      newInfo.setIsStatic(methodInfo.getIsStatic());
      infos.push(newInfo);
    });
    return infos;
  }

  static processExportDefault(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.ExportDefaultInfo[] = [];
    const newInfo: ResultsInfo.ExportDefaultInfo = new ResultsInfo.ExportDefaultInfo(apiInfo.getApiType());
    newInfo.setName(apiInfo.getApiName());
    infos.push(newInfo);
    return infos;
  }

  static processImportInfo(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.ImportInfo[] = [];
    const importInfo: ImportInfo = apiInfo as ImportInfo;
    const newInfo: ResultsInfo.ImportInfo = new ResultsInfo.ImportInfo(apiInfo.getApiType());
    importInfo.getImportValues().forEach((importValue: ExportImportValue) => {
      newInfo.addImportValue(importValue.key, importValue.value);
    });
    infos.push(newInfo);
    return infos;
  }

  static processConstant(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.ConstantInfo[] = [];
    const constantInfo: ConstantInfo = apiInfo as ConstantInfo;
    const jsDocInfos: Comment.JsDocInfo[] = constantInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.ConstantInfo = new ResultsInfo.ConstantInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      const value: string = constantInfo.getValue();
      newInfo.setValue(value.replace(ResultsProcessHelper.regQuotation, '$1'));
      newInfo.setType(isNaN(Number(value)) ? 'string' : 'number');
      const declarationNode: ts.VariableDeclaration = constantInfo.getNode() as ts.VariableDeclaration;
      if (declarationNode.initializer) {
        const typeOfLiteral: string | undefined = typeMap.get(declarationNode.initializer.kind);
        newInfo.setType(typeOfLiteral ? typeOfLiteral : '');
      }
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.ConstantInfo = new ResultsInfo.ConstantInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      const value: string = constantInfo.getValue();
      newInfo.setValue(value.replace(ResultsProcessHelper.regQuotation, '$1'));
      newInfo.setType(isNaN(Number(value)) ? 'string' : 'number');
      const declarationNode: ts.VariableDeclaration = constantInfo.getNode() as ts.VariableDeclaration;
      if (declarationNode.initializer) {
        const typeOfLiteral: string | undefined = typeMap.get(declarationNode.initializer.kind);
        newInfo.setType(typeOfLiteral ? typeOfLiteral : '');
      }
      infos.push(newInfo);
    });
    return infos;
  }

  static processDeclareConstant(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.DeclareConstInfo[] = [];
    const constantInfo: ConstantInfo = apiInfo as ConstantInfo;
    const jsDocInfos: Comment.JsDocInfo[] = constantInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.DeclareConstInfo = new ResultsInfo.DeclareConstInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setType(constantInfo.getValue());
      const declarationNode: ts.VariableDeclaration = constantInfo.getNode() as ts.VariableDeclaration;
      if (declarationNode.initializer) {
        const typeOfLiteral: string | undefined = typeMap.get(declarationNode.initializer.kind);
        newInfo.setType(typeOfLiteral ? typeOfLiteral : '');
      }
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.DeclareConstInfo = new ResultsInfo.DeclareConstInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      newInfo.setType(constantInfo.getValue());
      const declarationNode: ts.VariableDeclaration = constantInfo.getNode() as ts.VariableDeclaration;
      if (declarationNode.initializer) {
        const typeOfLiteral: string | undefined = typeMap.get(declarationNode.initializer.kind);
        newInfo.setType(typeOfLiteral ? typeOfLiteral : '');
      }
      infos.push(newInfo);
    });
    return infos;
  }

  static processEnum(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.NamespaceEnumInfo[] = [];
    const enumInfo: EnumInfo = apiInfo as EnumInfo;
    const jsDocInfos: Comment.JsDocInfo[] = enumInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.NamespaceEnumInfo = new ResultsInfo.NamespaceEnumInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.NamespaceEnumInfo = new ResultsInfo.NamespaceEnumInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      infos.push(newInfo);
    });
    return infos;
  }

  static processEnumMember(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.EnumValueInfo[] = [];
    const enumValueInfo: EnumValueInfo = apiInfo as EnumValueInfo;
    const jsDocInfos: Comment.JsDocInfo[] = enumValueInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.EnumValueInfo = new ResultsInfo.EnumValueInfo(
        apiInfo.getApiType(),
        new Comment.JsDocInfo()
      );
      newInfo.setName(apiInfo.getApiName());
      newInfo.setValue(enumValueInfo.getValue());
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.EnumValueInfo = new ResultsInfo.EnumValueInfo(apiInfo.getApiType(), jsDocInfo);
      newInfo.setName(apiInfo.getApiName());
      newInfo.setValue(enumValueInfo.getValue());
      infos.push(newInfo);
    });
    return infos;
  }

  static processTypeAlias(apiInfo: BasicApiInfo): ResultsInfo.BasicApiInfo[] {
    const infos: ResultsInfo.BasicApiInfo[] = [];
    const typeAliasInfo: TypeAliasInfo = apiInfo as TypeAliasInfo;
    const jsDocInfos: Comment.JsDocInfo[] = typeAliasInfo.getJsDocInfos();
    if (jsDocInfos.length === 0) {
      const newInfo: ResultsInfo.BasicApiInfo = ResultsProcessHelper.processTypeAliasGetNewInfo(
        typeAliasInfo,
        new Comment.JsDocInfo()
      );
      infos.push(newInfo);
    }
    jsDocInfos.forEach((jsDocInfo: Comment.JsDocInfo) => {
      const newInfo: ResultsInfo.BasicApiInfo = ResultsProcessHelper.processTypeAliasGetNewInfo(
        typeAliasInfo,
        jsDocInfo
      );
      infos.push(newInfo);
    });
    return infos;
  }
  static processTypeAliasGetNewInfo(
    typeAliasInfo: TypeAliasInfo,
    jsDocInfo: Comment.JsDocInfo
  ): ResultsInfo.BasicApiInfo {
    if (typeAliasInfo.getTypeName() === TypeAliasType.UNION_TYPE) {
      const newInfo: ResultsInfo.UnionTypeInfo = new ResultsInfo.UnionTypeInfo(typeAliasInfo.getTypeName(), jsDocInfo);
      newInfo.setName(typeAliasInfo.getApiName());
      newInfo.addValueRanges(
        typeAliasInfo.getType().map((type: string) => {
          return type.replace(ResultsProcessHelper.regQuotation, '$1');
        })
      );
      return newInfo;
    }
    const newInfo: ResultsInfo.TypeAliasInfo = new ResultsInfo.TypeAliasInfo(typeAliasInfo.getApiType(), jsDocInfo);
    newInfo.setName(typeAliasInfo.getApiName());
    newInfo.setType(typeAliasInfo.getType().join(' | '));
    return newInfo;
  }
}

const typeMap: Map<ts.SyntaxKind, string> = new Map([
  [ts.SyntaxKind.StringLiteral, 'string'],
  [ts.SyntaxKind.NumericLiteral, 'number'],
]);

/**
 * api节点类型对应的处理方法，获取diff信息
 */
export const resultsProcessMethod: Map<string, ResultsInfo.NodeProcessorInterface> = new Map([
  [ApiType.PROPERTY, ResultsProcessHelper.processProperty],
  [ApiType.CLASS, ResultsProcessHelper.processClass],
  [ApiType.INTERFACE, ResultsProcessHelper.processInterface],
  [ApiType.NAMESPACE, ResultsProcessHelper.processNamespace],
  [ApiType.METHOD, ResultsProcessHelper.processMethod],
  // [ApiType.PARAM, ResultsProcessHelper.processParam],
  // [ApiType.MODULE, ResultsProcessHelper.processModule],
  // [ApiType.EXPORT, ResultsProcessHelper.processExport],
  [ApiType.EXPORT_DEFAULT, ResultsProcessHelper.processExportDefault],
  [ApiType.IMPORT, ResultsProcessHelper.processImportInfo],
  [ApiType.CONSTANT, ResultsProcessHelper.processConstant],
  [ApiType.DECLARE_CONST, ResultsProcessHelper.processDeclareConstant],
  [ApiType.ENUM, ResultsProcessHelper.processEnum],
  [ApiType.ENUM_VALUE, ResultsProcessHelper.processEnumMember],
  [ApiType.TYPE_ALIAS, ResultsProcessHelper.processTypeAlias],
]);
