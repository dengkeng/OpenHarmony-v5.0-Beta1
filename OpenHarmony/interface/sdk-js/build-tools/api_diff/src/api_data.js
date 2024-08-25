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

const ts = require('typescript');

/**
 * 添加API信息到 apiMap
 * 
 * @param {Map} apiMap 
 * @param {ApiDigestInfo} apiDigestInfo 
 */
function addApiDigestInfo(apiMap, apiDigestInfo) {
  addApiInfo(apiMap, apiDigestInfo.getPackageName(),
    apiDigestInfo.getClassName(), apiDigestInfo.getApiName(),
    apiDigestInfo.getApiSignature(), apiDigestInfo);
}

/**
 * 将API摘要信息如以下数据格式保存 
 * @example
 * { packageName : Map }
 *                  |
 *      { className : { type: ApiDigestInfo, children: Map } }
 *                                                      |
 *                                             { apiName : Map }
 *                                                          |
 *                                                { signature : ApiDigestInfo[] }
 * 
 * @param {Map} apiMap API 摘要集合
 * @param {string} packageName 包名
 * @param {string} className 类型名
 * @param {string} apiSignature api节点签名
 * @param {ApiDigestInfo} api api摘要信息
 */
function addApiInfo(apiMap, packageName, className, apiName, apiSignature, api) {
  let dtsMap = apiMap.get(packageName);
  // 集合中没有该文件数据
  if (!dtsMap) {
    dtsMap = new Map();
    apiMap.set(packageName, dtsMap);
  }
  // 类数据
  let classApi = dtsMap.get(className);
  if (!classApi) {
    classApi = {
      children: new Map(),
    };
    dtsMap.set(className, classApi);
  }

  if (isTypeDeclaration(api) && !classApi.type) {
    classApi.type = api;
    return;
  }

  // api 映射表
  let apiNameMap = classApi.children.get(apiName);
  if (!apiNameMap) {
    apiNameMap = new Map();
    classApi.children.set(apiName, apiNameMap);
  }

  let apiArray = apiNameMap.get(apiSignature);
  if (!apiArray) {
    apiArray = [];
    apiNameMap.set(apiSignature, apiArray);
  }
  apiArray.push(api);
}

function isTypeDeclaration(api) {
  const types = [ApiType.ClassType.code, ApiType.InterfaceType.code, ApiType.EnumType.code, ApiType.NamespaceType.code, ApiType.SourceFile.code];
  return types.includes(api.getApiType().code);
}

/**
 * 获取AST节点的签名信息, 它由所有子节点非空字符串拼接而成，具有唯一性。
 * 类型的签名由 包名+类型名来确认唯一性。
 * 
 * @param {ts.Node} astNode 
 * @param {string} packageName 
 * @param {string} className 
 * @returns {string}
 */
function getNodeSignature(astNode, packageName, className) {
  if (ts.isInterfaceDeclaration(astNode) || ts.isClassDeclaration(astNode) ||
    ts.isModuleDeclaration(astNode) || ts.isEnumDeclaration(astNode) || ts.isSourceFile(astNode)) {
    return `${packageName}#${className}`;
  }
  let signature = '';
  if (astNode.getChildCount() > 0) {
    astNode.forEachChild((childNode) => {
      signature += `#${getNodeSignature(childNode)}`;
    });
  } else {
    signature = ts.isIdentifier(astNode) ? astNode.text.replace(/\'|\"/g, '') : astNode.getText().replace(/\'|\"/g, '');
  }
  return signature;
}

class ApiDigestInfo {
  constructor() {
  }

  /**
   * 设置包名,包名为d.ts文件与SDK根目录的相对路径
   * 
   * @param {string} packageName 
   * @returns {Object}
   */
  setPackageName(packageName) {
    this.packageName = packageName;
    return this;
  }

  getPackageName() {
    return this.packageName;
  }

  /**
   * 类型名称，如 class, enum, interface, namespace 名字
   * 
   * @param {string} className 
   * @returns {Object}
   */
  setClassName(className) {
    this.className = className;
    return this;
  }

  getClassName() {
    if (this.className) {
      return this.className;
    }
    let parentInfo = this.parent;
    while (parentInfo) {
      if (!parentInfo.className) {
        parentInfo = parentInfo.parent;
      } else {
        return parentInfo.className;
      }
    }
    return '';
  }

  /**
   * API的类型，如方法，属性，枚举等
   * 
   * @param {ApiType} apiType 
   * @returns {Object}
   */
  setApiType(apiType) {
    this.apiType = apiType;
    return this;
  }

  getApiType() {
    return this.apiType;
  }

  /**
   * API原始的文本
   * 
   * @param {string} rawText 
   * @returns {Object}
   */
  setRawText(rawText) {
    this.rawText = rawText;
    return this;
  }

  getRawText() {
    return this.rawText;
  }

  /**
   * API所属的d.ts文件路径
   * 
   * @param {string} path 
   * @returns {Object}
   */
  setPath(path) {
    this.path = path;
    return this;
  }

  getPath() {
    return this.path;
  }



  /**
   * API AST节点对象
   * 
   * @param {ts.Node} node 
   * @returns {Object}
   */
  setAstNode(node) {
    this.node = node;
    return this;
  }

  getAstNode() {
    return this.node;
  }

  /**
   * API的JSDoc信息
   * 
   * @param {Object} jsdoc 
   * @returns {Object}
   */
  setJSdoc(jsdoc) {
    this.jsdoc = jsdoc;
    return this;
  }

  setJSDocTagItem(jsdocTagItem) {
    this.jsdocTagItem = jsdocTagItem;
  }

  getJSDocTagItem() {
    return this.jsdocTagItem;
  }

  /**
   * AST节点的签名信息，可以确保在一个模块中的唯一性
   * 
   * @param {ts.Node} astNode 
   * @param {string} packageName 
   * @param {string} className 
   * @returns {Object}
   */
  setApiSignature(astNode, packageName, className) {
    this.signature = getNodeSignature(astNode, packageName, className);
    return this;
  }

  getApiSignature() {
    return this.signature;
  }

  setApiName(apiName) {
    this.apiName = apiName;
    return this;
  }

  getApiName() {
    return this.apiName;
  }

  /**
   * API 父节点摘要信息，可以确认某个节点的空间位置。
   * 
   * @param {Object} digestInfo 
   * @returns {Object}
   */
  setParent(digestInfo) {
    this.parent = digestInfo;
    return this;
  }

  getParent() {
    return this.parent;
  }

  setSyscap(syscap) {
    this.syscap = syscap;
    return this;
  }
}

const ApiType = {
  EnumType: { name: '枚举', code: 0 },
  EnumMember: { name: '枚举成员', code: 1 },
  ClassType: { name: '类', code: 2 },
  ClassProperty: { name: '类属性', code: 3 },
  ClassMethod: { name: '类方法', code: 4 },
  InterfaceType: { name: '接口', code: 5 },
  InterfaceMethod: { name: '接口方法', code: 6 },
  InterfaceProperty: { name: '接口属性', code: 7 },
  ExportType: { name: '类型导出', code: 8 },
  FunctionType: { name: '方法', code: 9 },
  NamespaceType: { name: '命名空间', code: 10 },
  TypeAliasDeclaration: { name: '类型成员', code: 11 },
  Constructor: { name: '构造器', code: 12 },
  CallSignature: { name: '类方法', code: 13 },
  SourceFile: { name: 'sourfile', code: 14 }
};

exports.ApiDigestInfo = ApiDigestInfo;
exports.ApiType = ApiType;
exports.apiDataHelper = {
  addApiInfo: addApiInfo,
  addApiDigestInfo: addApiDigestInfo,
  getNodeSignature: getNodeSignature,
};