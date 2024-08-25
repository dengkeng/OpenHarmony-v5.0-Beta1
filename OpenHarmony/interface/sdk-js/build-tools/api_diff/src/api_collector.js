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

const path = require('path');
const fs = require('fs');
const ts = require('typescript');
const { parse } = require('comment-parser');
const { ApiDigestInfo, ApiType, apiDataHelper } = require('./api_data');
const { isInDirectory } = require('./util');

/**
 * api 接口摘要信息包装方法
 * 
 * @param {ts.Node} astNode node节点对象
 * @param {string} className 类名
 * @param {ApiType} apiType 方法名
 * @param {string} rawText 原始文本
 * @param {VisitExt} ext 扩展参数
 * @returns {Object}
 */
function wrapApiDigestInfo(astNode, className, apiName, apiType, rawText, ext) {
  const digestInfo = new ApiDigestInfo();
  const jsdoc = getNodeLeadingJSDoc(astNode);
  digestInfo.setAstNode(astNode)
    .setApiType(apiType)
    .setClassName(className)
    .setPackageName(ext.packageName)
    .setRawText(rawText.trim())
    .setPath(ext.dtsPath)
    .setApiSignature(astNode, ext.packageName, className)
    .setApiName(apiName)
    .setJSdoc(jsdoc ? parseJSDocs(jsdoc) : undefined);
  return digestInfo;
}

/**
 * 接口属性签名信息
 * 
 * @param {ts.PropertySignature} propertySignature 
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getPropertySignatureInfo(propertySignature, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const rawText = propertySignature.getText();
  const apiName = propertySignature.name.getText();
  return wrapApiDigestInfo(propertySignature, className, apiName, ApiType.InterfaceProperty, rawText, ext);
}

/**
 * 
 * 
 * @param {ts.MethodDeclaration} methodDeclaration 
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getMethodDeclarationInfo(methodDeclaration, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const rawText = methodDeclaration.getText();
  const apiName = methodDeclaration.name.getText();
  return wrapApiDigestInfo(methodDeclaration, className, apiName, ApiType.ClassMethod, rawText, ext);
}

function getTypeAliasDeclarationInfo(typeAliasDeclaration, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const rawText = typeAliasDeclaration.getText();
  const apiName = typeAliasDeclaration.name.getText();
  return wrapApiDigestInfo(typeAliasDeclaration, className, apiName, ApiType.TypeAliasDeclaration, rawText, ext);
}

function getCallSignature(callSignature, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const rawText = callSignature.getText();
  const apiName = callSignature.name ? callSignature.name.getText() : className;
  return wrapApiDigestInfo(callSignature, className, apiName, ApiType.CallSignature, rawText, ext);
}

/**
 * 获取方法签名信息
 * 
 * @param {ts.MethodSignature} methodSignature 方法签名节点
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getMethodSignatureInfo(methodSignature, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const rawText = methodSignature.getText();
  const apiName = methodSignature.name.getText();
  return wrapApiDigestInfo(methodSignature, className, apiName, ApiType.InterfaceMethod, rawText, ext);
}

/**
 * 获取接口定义信息
 * 
 * @param {ts.InterfaceDeclaration} interfaceDec 
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getInterfaceDeclarationInfo(interfaceDec, parentApiDigest, ext) {
  const className = interfaceDec.name.getText();
  let rawText = '';
  if (interfaceDec.modifiers) {
    interfaceDec.modifiers.forEach((modifier) => {
      rawText += ` ${modifier.getText()}`;
    });
  }
  rawText += ` interface ${className}`;
  return wrapApiDigestInfo(interfaceDec, className, className, ApiType.InterfaceType, rawText, ext);
}

/**
 * 获取类属性定义
 * 
 * @param {ts.PropertyDeclaration} property 
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getPropertyDeclarationInfo(property, parentApiDigest, ext) {
  const className = parentApiDigest.getClassName();
  const apiName = property.name.getText();
  return wrapApiDigestInfo(property, className, apiName, ApiType.ClassProperty, property.getText(), ext);
}

/**
 * 收集构造方法信息
 * 
 * @param {ts.ConstructorDeclaration} constructorDec 构造方法定义节点 
 * @param {ApiDigestInfo} parentApiDigest 父类信息
 * @param {Object} ext 扩展参数
 * @returns {Object}
 */
function getConstructorInfo(constructorDec, parentApiDigest, ext) {
  const className = parentApiDigest ? parentApiDigest.getClassName() : '';
  const apiName = 'constructor';
  return wrapApiDigestInfo(constructorDec, className, apiName, ApiType.Constructor, constructorDec.getText(), ext);
}

/**
 * 搜集 Class 定义的信息
 * 
 * @param {ts.ClassDeclaration} classDec Class定义节点
 * @param {ApiDigestInfo} parentApiDigest 父类摘要信息
 * @param {VisitExt} ext 扩展参数
 * @returns {Object}
 */
function getClassDigestInfo(classDec, parentApiDigest, ext) {
  const className = classDec.name ? classDec.name.text : '';
  let rawText = '';
  if (classDec.modifiers) {
    classDec.modifiers.forEach((modifier) => {
      rawText += ` ${modifier.getText()}`;
    });
  }
  rawText += ` class ${className}`;
  return wrapApiDigestInfo(classDec, className, className, ApiType.ClassType, rawText, ext);
}

/**
 * 获取 Enum 成员的摘要信息
 * 
 * @param {ts.EnumMember} enumMember 
 * @param {ApiDigestInfo} parentApiDigest 
 * @param {VisitExt} ext 
 * @returns {Object}
 */
function getEnumMemberInfo(enumMember, parentApiDigest, ext) {
  const className = parentApiDigest ? parentApiDigest.getClassName() : '';
  const apiName = enumMember.name.getText();
  return wrapApiDigestInfo(enumMember, className, apiName, ApiType.EnumMember, enumMember.getText(), ext);
}

/**
 * 获取 enum 定义的信息
 * 
 * @param {ts.EnumDeclaration} enumNode Enum节点
 * @param {ApiDigestInfo} parentApiDigest 父类摘要信息
 * @param {VisitExt} ext 扩展参数
 * @returns {Object}
 */
function getEnumDigestInfo(enumNode, parentApiDigest, ext) {
  const className = enumNode.name.getText();
  let rawText = '';
  if (enumNode.modifiers) {
    enumNode.modifiers.forEach((modifier) => {
      rawText += ` ${modifier.getText()}`;
    });
  }
  rawText += ` enum ${className}`;
  return wrapApiDigestInfo(enumNode, className, className, ApiType.EnumType, rawText, ext);
}

/**
 * 获取 function 定义的API信息
 * 
 * @param {ts.FunctionDeclaration} fun 方法定义节点
 * @param {ApiDigestInfo} parentApiDigest 父类的摘要信息
 * @param {VisitExt} ext 扩展参数
 * @returns {Object}
 */
function getFunctionDigestInfo(fun, parentApiDigest, ext) {
  const className = parentApiDigest ? parentApiDigest.getClassName() : '';
  const apiName = fun.name ? fun.name.getText() : '';
  return wrapApiDigestInfo(fun, className, apiName, ApiType.FunctionType, fun.getText(), ext);
}

/**
 * 解析模块定义(namespace)类型。
 * 
 * @param {ts.ModuleDeclaration} module 模块定义类型对象
 * @param {VisitExt} ext 扩展参数
 * @returns {Object}
 */
function getModuleDigestInfo(module, parentApiDigest, ext) {
  const className = module.name.getText();
  let rawText = '';
  module.forEachChild((child) => {
    if (!ts.isModuleBlock(child)) {
      rawText += ` ${child.getText()}`;
    }
  });
  return wrapApiDigestInfo(module, className, className, ApiType.NamespaceType, rawText, ext);
}

function getSourceFile(sourceFile, parentApiDigest, ext) {
  const className = 'sourcefile';
  const rawText = 'sourcefile';
  return wrapApiDigestInfo(sourceFile, className, className, ApiType.SourceFile, rawText, ext);
}
/**
 * 所有特定类型API的处理方法集合。
 */
const apiDigestMethodMap = new Map([
  [ts.SyntaxKind.ModuleDeclaration, getModuleDigestInfo],
  [ts.SyntaxKind.FunctionDeclaration, getFunctionDigestInfo],
  [ts.SyntaxKind.EnumDeclaration, getEnumDigestInfo],
  [ts.SyntaxKind.EnumMember, getEnumMemberInfo],
  [ts.SyntaxKind.ClassDeclaration, getClassDigestInfo],
  [ts.SyntaxKind.Constructor, getConstructorInfo],
  [ts.SyntaxKind.PropertyDeclaration, getPropertyDeclarationInfo],
  [ts.SyntaxKind.InterfaceDeclaration, getInterfaceDeclarationInfo],
  [ts.SyntaxKind.MethodSignature, getMethodSignatureInfo],
  [ts.SyntaxKind.PropertySignature, getPropertySignatureInfo],
  [ts.SyntaxKind.MethodDeclaration, getMethodDeclarationInfo],
  [ts.SyntaxKind.TypeAliasDeclaration, getTypeAliasDeclarationInfo],
  [ts.SyntaxKind.CallSignature, getCallSignature],
  [ts.SyntaxKind.SourceFile, getSourceFile],
]);

/**
 * 解析节点的JSDoc信息，可能包含多段。
 * 
 * @param {string[]} jsdocText 
 * @returns {Array}
 */
function parseJSDocs(jsdocText) {
  return parse(jsdocText);
}

/**
 * 获取节点JSDoc的文本
 * 
 * @param {ts.Node} astNode 
 * @returns {string}
 */
function getNodeLeadingJSDoc(astNode) {
  if (astNode.kind === ts.SyntaxKind.SourceFile) {
    return '';
  }
  const sourceFile = astNode.getSourceFile();
  const leadingCommentRange = ts.getLeadingCommentRanges(sourceFile.getFullText(), astNode.getFullStart());
  if (!leadingCommentRange) {
    return undefined;
  }
  let commentText = '';
  leadingCommentRange.map((range) => {
    commentText += sourceFile.getFullText().slice(range.pos, range.end);
    commentText += '\n';
  });
  return commentText;
}

/**
 * 获取API的摘要信息
 * 
 * @param {ts.Node} astNode ast 节点对象
 * @param {VisitExt} ext 可扩展参数对象
 * @returns {@link ApiDigestInfo}
 */
function getApiDigestInfo(astNode, parentApiDigest, ext) {
  const digestMethod = apiDigestMethodMap.get(astNode.kind);
  if (digestMethod) {
    return digestMethod(astNode, parentApiDigest, ext);
  }
  return undefined;
}

/**
 * 非 API 节点的摘要信息，用于向上追溯父类API信息。
 * 
 * @param {ts.Node} astNode 
 * @returns {ApiDigestInfo} ApiDigestInfo
 */
function getDummyApiDigestInfo(astNode) {
  const dummyDigestInfo = new ApiDigestInfo();
  dummyDigestInfo.setAstNode(astNode);
  return dummyDigestInfo;
}

/**
 * 是否需要遍历特定节点类型的子节点。
 * 
 * @param {ts.Node} astNode 
 * @returns {Boolean} true or false
 */
function shouldVisitChildren(astNode) {
  return ts.isModuleDeclaration(astNode) || ts.isEnumDeclaration(astNode) || ts.isInterfaceDeclaration(astNode) ||
    ts.isClassDeclaration(astNode) || ts.isModuleBlock(astNode) || ts.isSourceFile(astNode);
}

/**
 * 递归遍历AST树的回调方法。
 * 
 * @param {ts.Node} astNode ast节点对象
 * @param {Map} apiMap api摘要信息的集合
 * @param {ApiDigestInfo} parentApiDigest 父节点摘要信息
 * @param {VisitExt} ext 扩展参数
 */
function visitAstNode(astNode, apiMap, parentApiDigest, ext) {
  let apiDigestInfo = getApiDigestInfo(astNode, parentApiDigest, ext);
  if (apiDigestInfo) {
    apiDataHelper.addApiDigestInfo(apiMap, apiDigestInfo);
  } else {
    apiDigestInfo = getDummyApiDigestInfo(astNode);
  }
  apiDigestInfo.setParent(parentApiDigest);
  if (shouldVisitChildren(astNode)) {
    astNode.forEachChild((child) => {
      visitAstNode(child, apiMap, apiDigestInfo, ext);
    });
  }
}

class VisitExt {
  constructor(packageName, filePath) {
    this.packageName = packageName;
    this.dtsPath = filePath;
  }
}

/**
 * 搜集API的主入口
 * 
 * @param {string} filePath d.ts路径
 * @param {string} rootDir sdk根目录
 * @returns {Map} api集合
 */
function collectApi(filePath, rootDir, resultMap) {
  const apiMap = resultMap ? resultMap : new Map();
  const apiFileName = path.basename(filePath, '.d.ts');
  const fileContent = fs.readFileSync(filePath, 'utf-8');
  const sourceFile = ts.createSourceFile(apiFileName, fileContent, ts.ScriptTarget.ES2017, true);
  const isArkUI = isInDirectory(path.resolve(rootDir, 'component'), filePath);
  const packageName = isArkUI ? 'ArkUI' : path.relative(rootDir, filePath);
  const dtsPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
  visitAstNode(sourceFile, apiMap, undefined, new VisitExt(packageName, dtsPath));
  return apiMap;
}

exports.ApiCollector = {
  collectApi: collectApi,
};