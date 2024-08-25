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
import _ from 'lodash';
import path from 'path';

import {
  ApiInfo,
  ApiType,
  BasicApiInfo,
  ClassInfo,
  ConstantInfo,
  ContainerApiInfo,
  EnumInfo,
  EnumValueInfo,
  ExportDeclareInfo,
  ExportDefaultInfo,
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
  ReferenceInfo,
  StructInfo,
  TypeAliasType,
  TypeAliasInfo,
  containerApiTypes,
  GenericInfo,
  ParentClass,
  ParserParam,
  FileTag,
  TypeParamInfo,
  TypeLocationInfo,
} from '../../typedef/parser/ApiInfoDefination';
import { Comment } from '../../typedef/parser/Comment';
import { StringUtils } from '../../utils/StringUtils';
import { StringConstant, EventConstant } from '../../utils/Constant';
import { BasicApiInfoMap, ApiInfosMap, FileInfoMap } from './parser';
import { JsDocProcessorHelper } from './JsDocProcessor';

export const parserParam: ParserParam = new ParserParam();

export class NodeProcessorHelper {
  // 如果是字符串的话，会出现单双引号重复的情况
  static regQuotation: RegExp = /^[\'|\"](.*)[\'|\"]$/;

  /**
   * 解析文件typereference对应symbol集合
   * 
   * @type {Map<string, Map<string, ts.Symbol>>}
   */
  static symbolOfTypeReferenceMap: Map<string, Map<string, ts.Symbol>> = new Map<string, Map<string, ts.Symbol>>();

  static processReference(
    sourceFile: ts.SourceFile,
    parentMap: Map<string, object>,
    parentApiInfo: BasicApiInfo
  ): void {
    const references: ReferenceInfo[] = [];
    sourceFile.referencedFiles.forEach((referencedFile: ts.FileReference) => {
      const referenceInfo: ReferenceInfo = new ReferenceInfo(ApiType.REFERENCE_FILE, sourceFile, parentApiInfo);
      referenceInfo.setApiName(ApiType.REFERENCE_FILE);
      referenceInfo.setPathName(referencedFile.fileName);
      references.push(referenceInfo);
    });
    if (references.length === 0) {
      return;
    }
    const currentMap: Map<string, object> = new Map();
    currentMap.set(StringConstant.SELF, references);
    parentMap.set(StringConstant.REFERENCE, currentMap);
  }
  /**
   * 根据节点类型处理节点的方法，处理的主流程
   *
   * @param { ts.Node } node 当前处理的节点
   * @param { FileInfoMap } parentMap 父节点建立的map对象
   * @param { BasicApiInfo } parentApiInfo 父节点解析后的对象
   */
  static processNode(node: ts.Node, parentMap: FileInfoMap | ApiInfosMap, parentApiInfo: BasicApiInfo): void {
    const nodeProcessor: NodeProcessorInterface | undefined = nodeProcessorMap.get(node.kind);
    if (!nodeProcessor) {
      return;
    }
    const apiInfo: BasicApiInfo = nodeProcessor(node, parentApiInfo);
    const currentMap: BasicApiInfoMap = NodeProcessorHelper.setApiInfo(apiInfo, parentMap, node);
    const childNodes: ts.NodeArray<ts.Node> | undefined = NodeProcessorHelper.getChildNodes(node);
    if (!childNodes) {
      return;
    }
    childNodes.forEach((cNode: ts.Node) => {
      if (apiInfo.getApiType() === ApiType.STRUCT && cNode.getFullText() === '') { // 去除struct的默认构造方法
        return;
      }
      NodeProcessorHelper.processNode(cNode, currentMap as ApiInfosMap, apiInfo);
    });
  }

  /**
   * 将解析后的api添加到当前的map中，会对某些特殊情况进行调整
   *
   * @param { BasicApiInfo } apiInfo 当前api的解析对象
   * @param { Map<string, object> } parentMap 当前父节点所在的map
   * @param { ts.Node } node 当前apinode节点
   * @returns { Map<string, object> } 返回当前节点所属的map
   */
  static setApiInfo(apiInfo: BasicApiInfo, parentMap: FileInfoMap | ApiInfosMap, node: ts.Node): BasicApiInfoMap {
    if (apiInfo.getApiType() !== ApiType.METHOD) {
      return NodeProcessorHelper.setSingleApiInfo(apiInfo, parentMap);
    }
    let apiInfos: BasicApiInfo[] = [];
    apiInfos = NodeProcessorHelper.processEventMethod(apiInfo, node);
    // 处理promise/asynccallback
    NodeProcessorHelper.processAsyncMethod(apiInfos);
    let currentMap: BasicApiInfoMap = new Map();
    apiInfos.forEach((apiInfo: BasicApiInfo) => {
      currentMap = NodeProcessorHelper.setSingleApiInfo(apiInfo, parentMap);
    });
    return currentMap;
  }

  /**
   *  将解析后的单个api添加到当前的map中，不允许对apiInfo进行二次修改
   *
   * @param { BasicApiInfo } apiInfo 当前api的解析对象
   * @param { ApiInfosMap } parentMap  当前父节点所在的map
   * @return { BasicApiInfoMap } 返回当前节点所属的map
   */
  static setSingleApiInfo(apiInfo: BasicApiInfo, parentMap: FileInfoMap | ApiInfosMap): BasicApiInfoMap {
    const apiName: string = apiInfo.getApiName();
    const parentApiInfo: BasicApiInfo | undefined = apiInfo.getParentApi();
    if (parentApiInfo && containerApiTypes.has(parentApiInfo.apiType)) {
      const containerApiInfo: ContainerApiInfo = parentApiInfo as ContainerApiInfo;
      containerApiInfo.addChildApi(apiInfo);
    }
    if (parentMap.has(apiName)) {
      //同名方法处理
      const currentMap: BasicApiInfoMap = parentMap.get(apiName) as BasicApiInfoMap;
      const methodInfos: BasicApiInfo[] = currentMap.get(StringConstant.SELF) as BasicApiInfo[];
      methodInfos.push(apiInfo);
      return currentMap;
    }
    const apiInfos: BasicApiInfo[] = [];
    apiInfos.push(apiInfo);
    const currentMap: BasicApiInfoMap = new Map();
    currentMap.set(StringConstant.SELF, apiInfos);
    parentMap.set(apiName, currentMap);
    return currentMap;
  }

  /**
   * 处理方法节点中事件订阅相关方法
   *
   * 第一个参数只要是字符串的字面量就将apiName修改为on_string，联合类型进行分开解析
   * @param {BasicApiInfo} apiInfo 当前api的解析对象
   * @param {ts.Node} node 当前apinode节点
   * @return {BasicApiInfo[]} 解析完on/off的apiInfo数组
   */
  static processEventMethod(apiInfo: BasicApiInfo, node: ts.Node): BasicApiInfo[] {
    const apiInfos: BasicApiInfo[] = [];
    const type: ts.TypeNode | undefined = NodeProcessorHelper.getOnOrOffMethodFirstParamType(
      apiInfo,
      node as MethodType
    );
    if (type === undefined) {
      apiInfos.push(apiInfo);
      return apiInfos;
    }
    const literal = (type as ts.LiteralTypeNode).literal;
    if (type.kind === ts.SyntaxKind.LiteralType && ts.isStringLiteral(literal)) {
      const text: string = literal.getText();
      apiInfo.setApiName(`${apiInfo.getApiName()}_${text.substring(1, text.length - 1)}`);
      apiInfo.setIsJoinType(true);
    } else if (type.kind === ts.SyntaxKind.UnionType) {
      const types: ts.NodeArray<ts.TypeNode> = (type as ts.UnionTypeNode).types;
      types.forEach((item: ts.TypeNode) => {
        if (ts.isLiteralTypeNode(item) && ts.isStringLiteral(item.literal)) {
          const text: string = item.literal.getText();
          const cloneApiInfo: BasicApiInfo = _.cloneDeep(apiInfo);
          cloneApiInfo.setParentApi(apiInfo.getParentApi());
          cloneApiInfo.setApiName(`${apiInfo.getApiName()}_${text.substring(1, text.length - 1)}`);
          apiInfo.setIsJoinType(true);
          apiInfos.push(cloneApiInfo);
        }
      });
    } else if (type.kind === ts.SyntaxKind.StringKeyword) {
      apiInfo.setApiName(`${apiInfo.getApiName()}_string`);
      apiInfo.setIsJoinType(true);
    } else if (type.kind === ts.SyntaxKind.BooleanKeyword) {
      apiInfo.setApiName(`${apiInfo.getApiName()}_boolean`);
      apiInfo.setIsJoinType(true);
    } else {
      apiInfo.setApiName(`${apiInfo.getApiName()}_${type.getText()}`);
      apiInfo.setIsJoinType(true);
    }
    if (apiInfos.length === 0) {
      apiInfos.push(apiInfo);
    }
    return apiInfos;
  }

  /**
   * 获取on/off方法第一个参数的类型
   *
   * @param {BasicApiInfo} apiInfo 当前api的解析对象
   * @param {MethodType} methodNode 当前apinode节点
   * @return {(ts.TypeNode | undefined)} 满足条件的on/off第一个参数的类型
   */
  static getOnOrOffMethodFirstParamType(apiInfo: BasicApiInfo, methodNode: MethodType): ts.TypeNode | undefined {
    const subscriotionSet: Set<string> = new Set(EventConstant.eventNameList);
    if (!subscriotionSet.has(apiInfo.getApiName())) {
      return undefined;
    }
    if (methodNode.parameters.length === 0) {
      return undefined;
    }
    const firstParam: ts.ParameterDeclaration = methodNode.parameters[0];
    return firstParam.type;
  }

  /**
   * 处理AsyncCallback和Promise，将符合规则的apiName修改为apiName（AsyncCallback/Promise）
   *
   * 1、返回参数是Promise类型
   *
   * 2、参数中有类型为AsyncCallback的参数
   *
   * @param {BasicApiInfo[]} apiInfos 需要处理的apiInfo集合
   */
  static processAsyncMethod(apiInfos: BasicApiInfo[]): void {
    apiInfos.forEach((apiInfo: BasicApiInfo) => {
      const methodInfo: MethodInfo = apiInfo as MethodInfo;
      const returnValues: string[] = methodInfo.getReturnValue();
      if (returnValues.length === 1 && returnValues[0].startsWith(StringConstant.PROMISE_METHOD_KEY)) {
        methodInfo.setSync(StringConstant.PROMISE_METHOD_KEY_CHANGE);
        return;
      }
      const params: ParamInfo[] = methodInfo.getParams();
      for (let i = params.length - 1; i >= 0; i--) {
        const paramType: string[] = params[i].getType();
        if (paramType.length === 1 && paramType[0].startsWith(StringConstant.ASYNC_CALLBACK_METHOD_KEY)) {
          methodInfo.setSync(StringConstant.ASYNC_CALLBACK_METHOD_KEY_CHANGE);
          return;
        }
      }
    });
  }

  /**
   * 获取interface、class、namespace，struct以及type定义的对象的子节点
   *
   * @param { ts.Node } node 当前节点
   * @returns { ts.NodeArray<ts.Node> | undefined } 返回当前节点的子节点
   */
  static getChildNodes(node: ts.Node): ts.NodeArray<ts.Node> | undefined {
    if (
      ts.isInterfaceDeclaration(node) ||
      ts.isClassDeclaration(node) ||
      ts.isEnumDeclaration(node) ||
      ts.isStructDeclaration(node)
    ) {
      return node.members;
    }
    if (ts.isTypeAliasDeclaration(node) && ts.isTypeLiteralNode(node.type)) {
      return node.type.members;
    }
    if (ts.isModuleDeclaration(node) && node.body && ts.isModuleBlock(node.body)) {
      return node.body.statements;
    }
    return undefined;
  }

  /**
   * 处理export default xxx节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ExportDefaultInfo } 返回处理后得到的ExportDefaultInfo对象
   */
  static processExportAssignment(node: ts.Node, parentApi: BasicApiInfo): ExportDefaultInfo {
    const exportDefaultInfo: ExportDefaultInfo = new ExportDefaultInfo(ApiType.EXPORT_DEFAULT, node, parentApi);
    const exportDefaultNode: ts.ExportAssignment = node as ts.ExportAssignment;
    exportDefaultInfo.setApiName(StringConstant.EXPORT_DEFAULT + exportDefaultNode.expression.getText());
    exportDefaultInfo.setDefinedText(exportDefaultNode.getText());
    ModifierHelper.processModifiers(exportDefaultNode.modifiers, exportDefaultInfo);
    return exportDefaultInfo;
  }

  /**
   * 处理export { xxx }节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ExportDeclareInfo } 返回处理后得到的ExportDeclareInfoInfo对象
   */
  static processExportDeclaration(node: ts.Node, parentApi: BasicApiInfo): ExportDeclareInfo {
    const exportDeclareInfo: ExportDeclareInfo = new ExportDeclareInfo(ApiType.EXPORT, node, parentApi);
    const exportDeclarationNode: ts.ExportDeclaration = node as ts.ExportDeclaration;
    const exportClause: ts.NamedExportBindings | undefined = exportDeclarationNode.exportClause;
    if (!exportClause) {
      //export * from 'test';
      exportDeclareInfo.setApiName(
        StringConstant.EXPORT +
        (exportDeclarationNode.moduleSpecifier ? exportDeclarationNode.moduleSpecifier.getText() : '')
      );
    } else if (ts.isNamespaceExport(exportClause)) {
      //export * as myTest from 'test';
      exportDeclareInfo.setApiName(StringConstant.EXPORT + exportClause.name.getText());
    } else if (ts.isNamedExports(exportClause)) {
      // export { xxx , yyy  }
      // export { xxx as x, yyy as y }
      const exportValueNames: string[] = [];
      exportClause.elements.forEach((element: ts.ExportSpecifier) => {
        const exportValueType: string = element.propertyName ? element.propertyName.getText() : '';
        const exportValueName: string = element.name.getText();
        exportValueNames.push(exportValueName);
        exportDeclareInfo.addExportValues(exportValueName, exportValueType);
      });
      exportDeclareInfo.setApiName(StringConstant.EXPORT + exportValueNames.join('_'));
    }
    exportDeclareInfo.setDefinedText(exportDeclarationNode.getText());
    ModifierHelper.processModifiers(exportDeclarationNode.modifiers, exportDeclareInfo);
    return exportDeclareInfo;
  }

  /**
   * 处理 export import NetAddress = connection.NetAddress;
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { importInfo } 返回处理后得到的importInfo对象
   */
  static processImportEqualsDeclaration(node: ts.Node, parentApi: BasicApiInfo): ImportInfo {
    const importInfo: ImportInfo = new ImportInfo(ApiType.EXPORT, node, parentApi);
    return importInfo;
  }

  /**
   * 处理import xxx from xxx 节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ImportInfo } 返回处理后得到的ImportInfo对象
   */
  static processImportInfo(node: ts.Node, parentApi: BasicApiInfo): ImportInfo {
    const importInfo: ImportInfo = new ImportInfo(ApiType.IMPORT, node, parentApi);
    const importNode: ts.ImportDeclaration = node as ts.ImportDeclaration;
    importInfo.setApiName(importNode.moduleSpecifier.getText());
    importInfo.setImportPath(importNode.moduleSpecifier.getText());
    importInfo.setDefinedText(importNode.getText());
    ModifierHelper.processModifiers(importNode.modifiers, importInfo);
    if (importNode.importClause === undefined) {
      return importInfo;
    }
    const importClause: ts.ImportClause = importNode.importClause;
    if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
      importClause.namedBindings.elements.forEach((element: ts.ImportSpecifier) => {
        const importValueType: string = element.propertyName ? element.propertyName.getText() : '';
        const importValueName: string = element.name.getText();
        importInfo.addImportValue(importValueName, importValueType);
      });
    } else {
      const importValueName: string = importClause.name ? importClause.name.escapedText.toString() : '';
      importInfo.addImportValue(importValueName, importValueName);
    }
    return importInfo;
  }

  /**
   * 处理interface节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { InterfaceInfo } 返回处理后得到的InterfaceInfo对象
   */
  static processInterface(node: ts.Node, parentApi: BasicApiInfo): InterfaceInfo {
    const interfaceDeclaration: ts.InterfaceDeclaration = node as ts.InterfaceDeclaration;
    const interfaceInfo: InterfaceInfo = new InterfaceInfo(ApiType.INTERFACE, node, parentApi);
    interfaceInfo.setApiName(interfaceDeclaration.name.getText());
    interfaceDeclaration.typeParameters?.forEach((typeParameter: ts.TypeParameterDeclaration) => {
      interfaceInfo.setGenericInfo(NodeProcessorHelper.processGenericity(typeParameter));
    });
    ModifierHelper.processModifiers(interfaceDeclaration.modifiers, interfaceInfo);
    if (interfaceDeclaration.heritageClauses === undefined) {
      return interfaceInfo;
    }
    interfaceDeclaration.heritageClauses.forEach((value: ts.HeritageClause) => {
      if (value.token === ts.SyntaxKind.ExtendsKeyword) {
        value.types.forEach((value: ts.ExpressionWithTypeArguments) => {
          const parentClass: ParentClass = new ParentClass();
          parentClass.setImplementClass('');
          parentClass.setExtendClass(value.getText());
          interfaceInfo.setParentClasses(parentClass);
        });
      } else if (value.token === ts.SyntaxKind.ImplementsKeyword) {
        value.types.forEach((value: ts.ExpressionWithTypeArguments) => {
          const parentClass: ParentClass = new ParentClass();
          parentClass.setImplementClass(value.getText());
          parentClass.setExtendClass('');
          interfaceInfo.setParentClasses(parentClass);
        });
      }
    });
    return interfaceInfo;
  }

  static processGenericity(typeParameter: ts.TypeParameterDeclaration): GenericInfo {
    const genericInfo: GenericInfo = new GenericInfo();
    genericInfo.setIsGenericity(true);
    genericInfo.setGenericContent(typeParameter.getText());
    return genericInfo;
  }
  /**
   * 处理class节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ClassInfo } 返回处理后得到的ClassInfo对象
   */
  static processClass(node: ts.Node, parentApi: BasicApiInfo): ClassInfo {
    const classDeclaration: ts.ClassDeclaration = node as ts.ClassDeclaration;
    const classInfo: ClassInfo = new ClassInfo(ApiType.CLASS, node, parentApi);
    const className: string = classDeclaration.name ? classDeclaration.name.getText() : '';
    classInfo.setApiName(className);
    classDeclaration.typeParameters?.forEach((typeParameter: ts.TypeParameterDeclaration) => {
      classInfo.setGenericInfo(NodeProcessorHelper.processGenericity(typeParameter));
    });
    ModifierHelper.processModifiers(classDeclaration.modifiers, classInfo);
    if (classDeclaration.heritageClauses === undefined) {
      return classInfo;
    }
    classDeclaration.heritageClauses.forEach((value: ts.HeritageClause) => {
      if (value.token === ts.SyntaxKind.ExtendsKeyword) {
        value.types.forEach((value: ts.ExpressionWithTypeArguments) => {
          const parentClass: ParentClass = new ParentClass();
          parentClass.setExtendClass(value.getText());
          parentClass.setImplementClass('');
          classInfo.setParentClasses(parentClass);
        });
      } else if (value.token === ts.SyntaxKind.ImplementsKeyword) {
        value.types.forEach((value: ts.ExpressionWithTypeArguments) => {
          const parentClass: ParentClass = new ParentClass();
          parentClass.setImplementClass(value.getText());
          parentClass.setExtendClass('');
          classInfo.setParentClasses(parentClass);
        });
      }
    });
    return classInfo;
  }

  /**
   * 处理module节点,分为外部模块（module）和内部模块（namespace）
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { NamespaceInfo } 返回处理后得到的NamespaceInfo对象
   */
  static processBaseModule(node: ts.Node, parentApi: BasicApiInfo): NamespaceInfo {
    const moduleDeclaration: ts.ModuleDeclaration = node as ts.ModuleDeclaration;
    if (!ts.isIdentifier(moduleDeclaration.name)) {
      return NodeProcessorHelper.processModule(node, parentApi);
    }
    return NodeProcessorHelper.processNamespace(node, parentApi);
  }

  /**
   * 处理module节点-外部模块
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ModuleInfo } 返回处理后得到的ModuleInfo对象
   */
  static processModule(node: ts.Node, parentApi: BasicApiInfo): ModuleInfo {
    const moduleDeclaration: ts.ModuleDeclaration = node as ts.ModuleDeclaration;
    const moduleInfo: ModuleInfo = new ModuleInfo(ApiType.MODULE, node, parentApi);
    moduleInfo.setApiName(moduleDeclaration.name.getText());
    ModifierHelper.processModifiers(moduleDeclaration.modifiers, moduleInfo);
    return moduleInfo;
  }

  /**
   * 处理namespace节点-内部模块
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { NamespaceInfo } 返回处理后得到的NamespaceInfo对象
   */
  static processNamespace(node: ts.Node, parentApi: BasicApiInfo): NamespaceInfo {
    const moduleDeclaration: ts.ModuleDeclaration = node as ts.ModuleDeclaration;
    const namespaceInfo: NamespaceInfo = new NamespaceInfo(ApiType.NAMESPACE, node, parentApi);
    namespaceInfo.setApiName(moduleDeclaration.name.getText());
    ModifierHelper.processModifiers(moduleDeclaration.modifiers, namespaceInfo);
    return namespaceInfo;
  }

  /**
   * 处理enum节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { EnumInfo } 返回处理后得到的EnumInfo对象
   */
  static processEnum(node: ts.Node, parentApi: BasicApiInfo): EnumInfo {
    const enumDeclaration: ts.EnumDeclaration = node as ts.EnumDeclaration;
    const enumInfo: EnumInfo = new EnumInfo(ApiType.ENUM, node, parentApi);
    enumInfo.setApiName(enumDeclaration.name.getText());
    ModifierHelper.processModifiers(enumDeclaration.modifiers, enumInfo);
    return enumInfo;
  }

  /**
   * 处理枚举值节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { EnumValueInfo } 返回处理后得到的EnumValueInfo对象
   */
  static processEnumValue(node: ts.Node, parentApi: BasicApiInfo): EnumValueInfo {
    const enumValueNode: ts.EnumMember = node as ts.EnumMember;
    const enumValueInfo: EnumValueInfo = new EnumValueInfo(ApiType.ENUM_VALUE, node, parentApi);
    enumValueInfo.setApiName(enumValueNode.name.getText());
    enumValueInfo.setDefinedText(enumValueNode.getText());
    const enumInfo: EnumInfo = parentApi as EnumInfo;
    enumValueInfo.setValue(NodeProcessorHelper.getCurrentEnumValue(enumInfo));
    if (enumValueNode.initializer) {
      const value: string = enumValueNode.initializer.getText().replace(NodeProcessorHelper.regQuotation, '$1');
      enumValueInfo.setValue(value);
    }
    return enumValueInfo;
  }

  /**
   *
   * @param  { EnumInfo } enumInfo Enum枚举类节点的信息
   * @returns { string } 返回当前遍历到的枚举成员的可能的枚举值
   */
  static getCurrentEnumValue(enumInfo: EnumInfo): string {
    const length: number = enumInfo.getChildApis().length;
    if (length === 0) {
      return String(0);
    }
    const preEnumValueInfo: EnumValueInfo = enumInfo.getChildApis()[length - 1] as EnumValueInfo;
    const preEnumValue: string = preEnumValueInfo.getValue();
    return isNaN(Number(preEnumValue)) ? '' : `${Number(preEnumValue) + 1}`;
  }

  /**
   * 处理interface或class下面的属性节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { PropertyInfo } 返回处理后得到的PropertyInfo对象
   */
  static processPropertySigAndDec(node: ts.Node, parentApi: BasicApiInfo): PropertyInfo {
    const propertyNode: PropertyNode = node as PropertyNode;
    const propertyInfo: PropertyInfo = new PropertyInfo(ApiType.PROPERTY, node, parentApi);
    propertyInfo.setApiName(propertyNode.name.getText());
    propertyInfo.setDefinedText(propertyNode.getText());
    ModifierHelper.processModifiers(propertyNode.modifiers, propertyInfo);
    propertyInfo.setIsRequired(!propertyNode.questionToken ? true : false);
    propertyInfo.addType(NodeProcessorHelper.processDataType(propertyNode.type));
    if (Boolean(process.env.NEED_DETECTION) && propertyNode.type) {
      NodeProcessorHelper.processFunctionTypeNode(
        propertyNode.type,
        propertyInfo,
        new ParamInfo(ApiType.PARAM),
        false
      );
    }
    propertyInfo.setTypeKind(propertyNode.type ? propertyNode.type.kind : -1);
    return propertyInfo;
  }

  /**
   * 处理.d.ets文件中的Struct节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { StructInfo } 返回处理后得到的StructInfo对象
   */
  static processStruct(node: ts.Node, parentApi: BasicApiInfo): StructInfo {
    const structNode: ts.StructDeclaration = node as ts.StructDeclaration;
    const structInfo: StructInfo = new StructInfo(ApiType.STRUCT, node, parentApi);
    const structName: string = structNode.name ? structNode.name.getText() : '';
    structInfo.setApiName(structName);
    structInfo.setDefinedText(structInfo.getApiName());
    ModifierHelper.processModifiers(structNode.modifiers, structInfo);
    return structInfo;
  }

  /**
   * 处理方法节点
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { MethodInfo } 返回处理后得到的MethodInfo对象
   */
  static processMethod(node: ts.Node, parentApi: BasicApiInfo): MethodInfo {
    const methodNode: MethodType = node as MethodType;
    const methodInfo: MethodInfo = new MethodInfo(ApiType.METHOD, node, parentApi);
    methodInfo.setDefinedText(methodNode.getText());
    let methodName: string = methodNode.name ? methodNode.name.getText() : '';
    if (
      ts.isConstructorDeclaration(methodNode) ||
      ts.isConstructSignatureDeclaration(methodNode) ||
      ts.isCallSignatureDeclaration(methodNode)
    ) {
      methodName = StringConstant.CONSTRUCTOR_API_NAME;
    }
    methodInfo.setApiName(methodName);
    methodNode.typeParameters?.forEach((typeParameter: ts.TypeParameterDeclaration) => {
      methodInfo.setGenericInfo(NodeProcessorHelper.processGenericity(typeParameter));
    });
    const callForm: string = methodNode.getText().replace(/export\s+|declare\s+|function\s+|\r\n|\;/g, '');
    methodInfo.setCallForm(callForm);
    if (methodNode.type && ts.SyntaxKind.VoidKeyword !== methodNode.type.kind) {
      const returnValues: string[] = NodeProcessorHelper.processDataType(methodNode.type);
      methodInfo.setReturnValue(returnValues);
      methodInfo.setReturnValueType(methodNode.type.kind);
      if (Boolean(process.env.NEED_DETECTION)) {
        NodeProcessorHelper.processFunctionTypeNode(
          methodNode.type,
          methodInfo,
          new ParamInfo(ApiType.PARAM),
          false
        );
      }
    }
    for (let i = 0; i < methodNode.parameters.length; i++) {
      const param: ts.ParameterDeclaration = methodNode.parameters[i];
      const paramInfo: ParamInfo = NodeProcessorHelper.processParam(param, methodInfo);
      methodInfo.addParam(paramInfo);
    }
    if (!ts.isCallSignatureDeclaration(methodNode) && !ts.isConstructSignatureDeclaration(methodNode)) {
      ModifierHelper.processModifiers(methodNode.modifiers, methodInfo);
    }
    return methodInfo;
  }

  /**
   * 处理方法入参
   *
   * @param { ts.ParameterDeclaration } param 参数节点
   * @param { MethodInfo } methodInfo MethodInfo对象
   * @returns { ParamInfo } 返回处理后的ParamInfo对象
   */
  static processParam(param: ts.ParameterDeclaration, methodInfo: MethodInfo): ParamInfo {
    const paramInfo: ParamInfo = new ParamInfo(ApiType.PARAM);
    paramInfo.setApiName(param.name.getText());
    paramInfo.setIsRequired(!param.questionToken ? true : false);
    paramInfo.setDefinedText(param.getText());
    paramInfo.setParamType(param.type ? param.type.kind : -1);
    if (param.type === undefined) {
      return paramInfo;
    }
    let typeMapValue: string | undefined = undefined;
    if (Boolean(process.env.NEED_DETECTION)) {
      NodeProcessorHelper.processFunctionTypeNode(param.type, methodInfo, paramInfo, true);
    }
    if (ts.isLiteralTypeNode(param.type)) {
      typeMapValue = typeMap.get(param.type.literal.kind);
    }
    paramInfo.setType(NodeProcessorHelper.processDataType(param.type));
    return paramInfo;
  }

  /**
   * 根据node节点获取当前文件名称
   *
   * @param {ts.Node} node
   * @return {string} 文件名称
   */
  static getFilePathFromNode(node: ts.Node): string {
    if (ts.isSourceFile(node)) {
      return node.fileName;
    } else {
      return NodeProcessorHelper.getFilePathFromNode(node.parent);
    }
  }

  /**
   * 设置SymbolOfTypeReferenceMap对象
   *
   * @param {string} filePath 文件路径 
   * @param {ts.TypeReferenceNode} tsNode 文件中的typeReference
   * @param {ts.Symbol} symbol typereference对应symbol
   */
  static setSymbolOfTypeReferenceMap(filePath: string, tsNode: ts.TypeReferenceNode, symbol: ts.Symbol): void {
    if (!NodeProcessorHelper.symbolOfTypeReferenceMap.has(filePath)) {
      NodeProcessorHelper.symbolOfTypeReferenceMap.set(filePath, new Map<string, ts.Symbol>());
    }
    const typeSymbolMap: Map<string, ts.Symbol> | undefined =
      NodeProcessorHelper.symbolOfTypeReferenceMap.get(filePath);
    if (!typeSymbolMap) {
      return;
    }
    if (!typeSymbolMap.has(tsNode.getFullText().trim())) {
      typeSymbolMap.set(tsNode.getFullText().trim(), symbol);
    }
  }

  /**
   * 从symbolOfTypeReferenceMap获取值
   *
   * @param {string} filePath 文件路径 
   * @param {ts.TypeReferenceNode} tsNode 文件中的typeReference
   * @return {(ts.Symbol | undefined)} symbol值
   */
  static getSymbolOfTypeReferenceMap(filePath: string, tsNode: ts.TypeReferenceNode): ts.Symbol | undefined {
    const fileSymbolMap: Map<string, ts.Symbol> | undefined =
      NodeProcessorHelper.symbolOfTypeReferenceMap.get(filePath);
    if (!fileSymbolMap) {
      return;
    }
    const typeSymbol: ts.Symbol | undefined = fileSymbolMap.get(tsNode.getFullText().trim())
    if (!typeSymbol) {
      return;
    }
    return typeSymbol;
  }

  /**
   * 处理方法入参的类型、联合类型时会将多个类型遍历传入
   * 引用类型获取对应文件中的jsdoc
   * 匿名类型获取属性的doc信息
   *
   * @param { ts.TypeNode } typeNode 参数类型
   * @param { MethodInfo } methodInfo MethodInfo对象
   * @param { ParamInfo } paramInfo ParamInfo对象
   * @param { boolean } [isParam = true] 是否是参数的type，
   * true：类型为参数（入参）的数据
   * false：类型为返回值（出参）的数据
   */
  static processFunctionTypeNode(
    typeNode: ts.TypeNode,
    methodInfo: MethodInfo | PropertyInfo,
    paramInfo: ParamInfo,
    isParam: boolean = true
  ): void {
    if (ts.isTypeLiteralNode(typeNode)) {
      NodeProcessorHelper.processFunctionTypeObject(typeNode, methodInfo, paramInfo, isParam);
    } else if (ts.isUnionTypeNode(typeNode)) {
      typeNode.types.forEach((type: ts.TypeNode) => {
        NodeProcessorHelper.processFunctionTypeNode(type, methodInfo, paramInfo, isParam);
      });
    } else if (ts.isFunctionTypeNode(typeNode)) {
      typeNode.parameters.forEach((parameter: ts.ParameterDeclaration) => {
        if (parameter.type) {
          NodeProcessorHelper.processFunctionTypeNode(parameter.type, methodInfo, paramInfo, isParam);
        }
      })
      NodeProcessorHelper.processFunctionTypeNode(typeNode.type, methodInfo, paramInfo, isParam);
    }
    if (!ts.isTypeReferenceNode(typeNode)) {
      return;
    }
    NodeProcessorHelper.processFunctionTypeReference(typeNode, methodInfo, paramInfo, isParam);
  }

  /**
   * 处理方法引用类型
   *
   * @param { ts.TypeNode } typeNode 参数类型
   * @param { MethodInfo } methodInfo MethodInfo对象
   * @param { ParamInfo } paramInfo ParamInfo对象
   * @param { boolean } [isParam = true] 是否是参数的type，
   * true：类型为参数（入参）的数据
   * false：类型为返回值（出参）的数据
   */
  static processFunctionTypeReference(
    typeNode: ts.TypeReferenceNode,
    methodInfo: MethodInfo | PropertyInfo,
    paramInfo: ParamInfo,
    isParam: boolean = true
  ): void {
    const typeArguments: ts.NodeArray<ts.TypeNode> | undefined = typeNode.typeArguments;
    typeArguments?.forEach((typeArgument: ts.TypeNode) => {
      NodeProcessorHelper.processFunctionTypeNode(typeArgument, methodInfo, paramInfo, isParam);
    })
    try {
      const tsProgram: ts.Program = parserParam.getTsProgram();
      const filePath: string = parserParam.getFilePath();
      Object.assign(tsProgram, {
        getSymbolOfTypeReference: (tsNode: ts.TypeReferenceNode, symbol: ts.Symbol) => {
          const currentFilePath: string = NodeProcessorHelper.getFilePathFromNode(tsNode);
          if (path.resolve(currentFilePath) !== path.resolve(filePath)) {
            return;
          }
          NodeProcessorHelper.setSymbolOfTypeReferenceMap(filePath, tsNode, symbol);
        }
      })
      tsProgram.emit();
      const currentTypeSymbol: ts.Symbol | undefined =
        NodeProcessorHelper.getSymbolOfTypeReferenceMap(filePath, typeNode);
      if (!currentTypeSymbol) {
        return;
      }
      const declarations: ts.Declaration[] | undefined = currentTypeSymbol.declarations;
      if (!declarations) {
        return;
      }
      const declaration: ts.Declaration = declarations[0];
      const fileTags: FileTag = methodInfo.getKitInfoFromParent(methodInfo);
      const jsDocInfos: Comment.JsDocInfo[] = JsDocProcessorHelper.processJsDocInfos(
        declaration,
        ApiType.TYPE_ALIAS,
        fileTags.kitInfo,
        fileTags.isFile
      );
      if (jsDocInfos.length === 0) {
        return;
      }
      const typeLocationInfo: TypeLocationInfo = jsDocInfos[jsDocInfos.length - 1] as TypeLocationInfo;
      typeLocationInfo.removeTags();
      new TypeLocationInfo().setTypeName.apply(typeLocationInfo, [typeNode.getFullText().trim()]);
      if (isParam) {
        paramInfo.addTypeLocations(typeLocationInfo);
      } else {
        methodInfo.addTypeLocations(typeLocationInfo);
      }
    } catch (error) {
    } finally {
    }
  }

  /**
   * 处理方法入参的匿名类型
   * 将匿名类型的每个属性的doc存储
   *
   * @param {ts.TypeLiteralNode} typeObject 匿名对象
   * @param {MethodInfo} methodInfo MethodInfo对象
   * @param {ParamInfo} paramInfo ParamInfo对象
   * @param { boolean } [isParam = true] 是否是参数的type，
   * true：类型为参数（入参）的数据
   * false：类型为返回值（出参）的数据
   */
  static processFunctionTypeObject(
    typeObject: ts.TypeLiteralNode,
    methodInfo: MethodInfo | PropertyInfo,
    paramInfo: ParamInfo,
    isParam: boolean = true
  ): void {
    const fileTags: FileTag = methodInfo.getKitInfoFromParent(methodInfo);
    typeObject.members.forEach((member: ts.TypeElement) => {
      const jsDocInfos: Comment.JsDocInfo[] = JsDocProcessorHelper.processJsDocInfos(
        member,
        ApiType.TYPE_ALIAS,
        fileTags.kitInfo,
        fileTags.isFile
      );
      if (jsDocInfos.length === 0) {
        return;
      }
      const typeLocationInfo: TypeLocationInfo = jsDocInfos[jsDocInfos.length - 1] as TypeLocationInfo;
      if (isParam) {
        paramInfo.addObjLocations(typeLocationInfo);
      } else {
        methodInfo.addObjLocations(typeLocationInfo);
      }
      if (ts.isPropertySignature(member) && member.type) {
        NodeProcessorHelper.processFunctionTypeNode(member.type, methodInfo, paramInfo, isParam);
      }
    });
  }

  /**
   * 处理数据类型，因为会存在联合类型的情况
   *
   * @param { string } dataType 类型信息的字符串
   * @returns { string[] } 返回处理后的数组
   */
  static processDataType(dataType: ts.TypeNode | undefined): string[] {
    const typeArr: string[] = [];
    if (!dataType || dataType.kind === ts.SyntaxKind.VoidKeyword) {
      return typeArr;
    }
    if (ts.isUnionTypeNode(dataType)) {
      dataType.types.forEach((type: ts.TypeNode) => {
        typeArr.push(type.getText());
      });
      return typeArr;
    }
    typeArr.push(dataType.getText());
    return typeArr;
  }

  /**
   * 处理type关键字定义的节点TypeAliasDeclaration，包含定义别名(包含联合类型)以及自定义对象（归为interface）
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { ApiInfo } 返回处理后的ApiInfo对象
   */
  static TypeAliasDeclaration(node: ts.Node, parentApi: BasicApiInfo): ApiInfo {
    const typeAliasNode: ts.TypeAliasDeclaration = node as ts.TypeAliasDeclaration;
    if (typeAliasNode.type.kind === ts.SyntaxKind.TypeLiteral) {
      return NodeProcessorHelper.processTypeInterface(typeAliasNode, parentApi);
    } else {
      return NodeProcessorHelper.processTypeAlias(typeAliasNode, parentApi);
    }
  }

  /**
   * 处理type关键字定义的对象，如type sample = { count: number }
   *
   * @param { ts.TypeAliasDeclaration } node 当前节点
   * @returns { InterfaceInfo } 返回处理后的InterfaceInfo对象
   */
  static processTypeInterface(node: ts.TypeAliasDeclaration, parentApi: BasicApiInfo): InterfaceInfo {
    const interfaceInfo: InterfaceInfo = new InterfaceInfo(ApiType.INTERFACE, node, parentApi);
    interfaceInfo.setApiName(node.name.getText());
    interfaceInfo.setDefinedText(interfaceInfo.getApiName());
    ModifierHelper.processModifiers(node.modifiers, interfaceInfo);
    return interfaceInfo;
  }

  /**
   * 处理type关键字定义的类型别名，包含联合类型
   *
   * @param { ts.Node } node 当前节点
   * @returns { TypeAliasInfo } 返回处理后的TypeAliasInfo对象
   */
  static processTypeAlias(node: ts.TypeAliasDeclaration, parentApi: BasicApiInfo): TypeAliasInfo {
    const typeNameMap: Map<number, string> = new Map([
      [ts.SyntaxKind.UnionType, TypeAliasType.UNION_TYPE],
      [ts.SyntaxKind.TypeLiteral, TypeAliasType.OBJECT_TYPE],
      [ts.SyntaxKind.TupleType, TypeAliasType.TUPLE_TYPE],
      [ts.SyntaxKind.TypeReference, TypeAliasType.REFERENCE_TYPE],
    ]);
    const typeAliasInfo: TypeAliasInfo = new TypeAliasInfo(ApiType.TYPE_ALIAS, node, parentApi);
    typeAliasInfo.setApiName(node.name.getText());
    const typeName: string | undefined = typeNameMap.get(node.type.kind);
    if (typeName) {
      typeAliasInfo.setTypeName(typeName);
    }
    let nodeType: ts.TypeNode = node.type;
    if (ts.isFunctionTypeNode(nodeType)) {
      const typeParameters = nodeType.parameters;
      typeParameters.forEach((typeParameter: ts.ParameterDeclaration) => {
        const typeParamInfo: TypeParamInfo = new TypeParamInfo();
        typeParamInfo.setParamName(typeParameter.name.getText());
        typeParamInfo.setParamType(typeParameter.type?.getText());
        typeAliasInfo.setParamInfos(typeParamInfo);
      });
      typeAliasInfo.setReturnType(nodeType.type.getText());
      typeAliasInfo.setTypeIsFunction(true);
    }

    typeAliasInfo.setDefinedText(node.getText());
    ModifierHelper.processModifiers(node.modifiers, typeAliasInfo);
    typeAliasInfo.addType(NodeProcessorHelper.processDataType(node.type));
    return typeAliasInfo;
  }

  /**
   * 处理VariableStatement节点，根据节点定义的情况会将其处理为常量或属性
   *
   * @param { ts.Node } node 当前节点
   * @param { BasicApiInfo } parentApi 存储父节点信息的对象
   * @returns { BasicApiInfo } 返回处理后的节点对象
   */
  static processVariableStat(node: ts.Node, parentApi: BasicApiInfo): BasicApiInfo {
    const variableNode: ts.VariableStatement = node as ts.VariableStatement;
    const definedText: string = variableNode.getText();
    const declarationNode: ts.VariableDeclaration = variableNode.declarationList.declarations[0];
    const REG_DECLARE_CONSTANT: RegExp = /declare\s+const/;
    const REG_COMPONENT: RegExp = /[a-zA-Z]+(Attribute|Interface)/;
    // declare const
    let variableType: string = '';
    let value: string = '';
    if (declarationNode.type) {
      if (ts.isLiteralTypeNode(declarationNode.type)) {
        const typeOfLiteral: string | undefined = typeMap.get(declarationNode.type.literal.kind);
        variableType = typeOfLiteral ? typeOfLiteral : '';
        value = declarationNode.type.literal.getText().replace(NodeProcessorHelper.regQuotation, '$1');
      } else {
        variableType = declarationNode.type.getText();
      }
    }
    if (REG_DECLARE_CONSTANT.test(variableNode.getText()) && REG_COMPONENT.test(variableType)) {
      return NodeProcessorHelper.processDeclareConstant(variableNode, definedText, variableType, parentApi);
    }
    // 节点有初始化值，如const a = 1，归为常量
    if (declarationNode.initializer) {
      const constantValue: string = declarationNode.initializer.getText();
      return NodeProcessorHelper.processConstant(variableNode, definedText, constantValue, parentApi);
    }
    // 节点的类型为字面量值，如const a: 111，归为常量
    const typeNode: ts.TypeNode | undefined = declarationNode.type;
    if (typeNode && ts.isLiteralTypeNode(typeNode)) {
      const constantValue: string = typeNode.getText();
      return NodeProcessorHelper.processConstant(variableNode, definedText, constantValue, parentApi);
    }
    // 除了上述两种常量的情况，其他归为属性
    return NodeProcessorHelper.processVaribleProperty(variableNode, definedText, parentApi);
  }

  /**
   * 处理常量节点
   *
   * @param { ts.VariableDeclaration } node 当前节点
   * @param { string } definedText 节点定义的字符串
   * @param { string } value 常量的取值
   * @param { BasicApiInfo } parentApi 父节点解析后的对象
   * @returns { ConstantInfo } 返回解析后的常量对象
   */
  static processConstant(
    node: ts.VariableStatement,
    definedText: string,
    value: string,
    parentApi: BasicApiInfo
  ): ConstantInfo {
    const declarationNode: ts.VariableDeclaration = node.declarationList.declarations[0] as ts.VariableDeclaration;
    const constantInfo: ConstantInfo = new ConstantInfo(ApiType.CONSTANT, node, parentApi);
    constantInfo.setDefinedText(definedText);
    constantInfo.setApiName(declarationNode.name.getText());
    constantInfo.setValue(value);
    return constantInfo;
  }

  /**
   * 处理declare常量节点
   *
   * @param { ts.VariableDeclaration } node 当前节点
   * @param { string } definedText 节点定义的字符串
   * @param { string } value 常量的取值
   * @param { BasicApiInfo } parentApi 父节点解析后的对象
   * @returns { ConstantInfo } 返回解析后的常量对象
   */
  static processDeclareConstant(
    node: ts.VariableStatement,
    definedText: string,
    value: string,
    parentApi: BasicApiInfo
  ): ConstantInfo {
    const declarationNode: ts.VariableDeclaration = node.declarationList.declarations[0] as ts.VariableDeclaration;
    const constantInfo: ConstantInfo = new ConstantInfo(ApiType.DECLARE_CONST, node, parentApi);
    constantInfo.setDefinedText(definedText);
    constantInfo.setApiName(declarationNode.name.getText());
    constantInfo.setValue(value);
    return constantInfo;
  }

  /**
   * 处理VariableDeclaration节点类型的属性节点
   *
   * @param { ts.VariableDeclaration } node 当前节点
   * @param { string } definedText 节点定义的字符串
   * @param { BasicApiInfo } parentApi 父节点解析后的对象
   * @returns { ConstantInfo } 返回解析后的属性对象
   */
  static processVaribleProperty(
    node: ts.VariableStatement,
    definedText: string,
    parentApi: BasicApiInfo
  ): PropertyInfo {
    const declarationNode: ts.VariableDeclaration = node.declarationList.declarations[0] as ts.VariableDeclaration;
    const propertyInfo: PropertyInfo = new PropertyInfo(ApiType.PROPERTY, node, parentApi);
    propertyInfo.setDefinedText(definedText);
    propertyInfo.setApiName(declarationNode.name.getText());
    propertyInfo.addType(NodeProcessorHelper.processDataType(declarationNode.type));
    propertyInfo.setIsRequired(true);
    if (StringUtils.hasSubstring(definedText, StringConstant.CONST_KEY_WORD)) {
      propertyInfo.setIsReadOnly(true);
    }
    return propertyInfo;
  }
}

/**
 * 处理export readonly、static等修饰关键字
 */
export class ModifierHelper {
  static setIsStatic(apiInfo: BasicApiInfo): void {
    const propertyOrMethodInfo: PropertyInfo | MethodInfo = apiInfo as PropertyInfo | MethodInfo;
    propertyOrMethodInfo.setIsStatic(true);
  }

  static setIsReadonly(apiInfo: BasicApiInfo): void {
    const propertyInfo: PropertyInfo = apiInfo as PropertyInfo;
    if (propertyInfo.setIsReadOnly) {
      propertyInfo.setIsReadOnly(true);
    }
  }

  static setIsExport(apiInfo: BasicApiInfo): void {
    apiInfo.setIsExport(true);
  }

  static processModifiers(modifiers: ts.NodeArray<ts.Modifier> | undefined, apiInfo: BasicApiInfo): void {
    let definedText: string = '';
    if (modifiers) {
      modifiers.forEach((modifier: ts.Modifier) => {
        if (containerApiTypes.has(apiInfo.apiType) && !ts.isDecorator(modifier)) {
          definedText += ` ${modifier.getText()}`;
        }

        const setModifier: ModifierProcessorInterface | undefined = modifierProcessorMap.get(modifier.kind);
        setModifier ? setModifier(apiInfo) : undefined;
      });
    }
    if (containerApiTypes.has(apiInfo.apiType)) {
      definedText += ` ${apiInfo.getApiType().toLowerCase()} ${apiInfo.getApiName()}`;
      apiInfo.setDefinedText(definedText);
    }
  }
}

export const nodeProcessorMap: Map<ts.SyntaxKind, NodeProcessorInterface> = new Map([
  [ts.SyntaxKind.ExportAssignment, NodeProcessorHelper.processExportAssignment],
  [ts.SyntaxKind.ExportDeclaration, NodeProcessorHelper.processExportDeclaration],
  // [ts.SyntaxKind.ImportEqualsDeclaration, NodeProcessorHelper.processImportEqualsDeclaration],
  [ts.SyntaxKind.ImportDeclaration, NodeProcessorHelper.processImportInfo],
  [ts.SyntaxKind.VariableStatement, NodeProcessorHelper.processVariableStat],
  [ts.SyntaxKind.MethodDeclaration, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.MethodSignature, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.FunctionDeclaration, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.Constructor, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.ConstructSignature, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.CallSignature, NodeProcessorHelper.processMethod],
  [ts.SyntaxKind.PropertyDeclaration, NodeProcessorHelper.processPropertySigAndDec],
  [ts.SyntaxKind.PropertySignature, NodeProcessorHelper.processPropertySigAndDec],
  [ts.SyntaxKind.EnumMember, NodeProcessorHelper.processEnumValue],
  [ts.SyntaxKind.EnumDeclaration, NodeProcessorHelper.processEnum],
  [ts.SyntaxKind.TypeAliasDeclaration, NodeProcessorHelper.processTypeAlias],
  [ts.SyntaxKind.ClassDeclaration, NodeProcessorHelper.processClass],
  [ts.SyntaxKind.InterfaceDeclaration, NodeProcessorHelper.processInterface],
  [ts.SyntaxKind.ModuleDeclaration, NodeProcessorHelper.processBaseModule],
  [ts.SyntaxKind.StructDeclaration, NodeProcessorHelper.processStruct],
]);

export const modifierProcessorMap: Map<ts.SyntaxKind, ModifierProcessorInterface> = new Map([
  [ts.SyntaxKind.ConstKeyword, ModifierHelper.setIsReadonly],
  [ts.SyntaxKind.ReadonlyKeyword, ModifierHelper.setIsReadonly],
  [ts.SyntaxKind.StaticKeyword, ModifierHelper.setIsStatic],
  [ts.SyntaxKind.ExportKeyword, ModifierHelper.setIsExport],
]);

export const typeMap: Map<ts.SyntaxKind, string> = new Map([
  [ts.SyntaxKind.StringLiteral, 'string'],
  [ts.SyntaxKind.NumericLiteral, 'number'],
]);
