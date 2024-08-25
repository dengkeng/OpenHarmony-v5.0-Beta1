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

const { FileSystem, Logger } = require('./utils');
const path = require('path');
const ts = require('typescript');
const fs = require('fs');

class SystemApiRecognizer {
  constructor(systemRoot) {
    this.systemRoot = systemRoot;
    this.arkUIDecorator = new Set(['@Builder', '@Styles', '@Extend']);
    this.arkUIRender = new Set(['build']);
    this.componentAttributeMap = new Map();
    this.componentAttributeTypeSymbolMap = new Map();
    this.forEachComponents = new Set(['LazyForEach', 'ForEach']);
    this.apiInfoSet = new Set([]);
  }

  /**
   * 遍历AST, 识别系统API调用。
   * 
   * @param {ts.Node} node 
   * @param {string} fileName
   */
  visitNode(node, fileName) {
    this.recognizeDecorators(node, fileName, undefined);
    if (this.isArkUIRenderMethod(node)) {
      this.visitUIRenderNode(node.body, fileName);
    } else {
      this.visitNormalNode(node, fileName);
    }
  }

  recognizeDecorators(node, fileName, position) {
    let decoratorArray = [];
    if (node.decorators) {
      decoratorArray = node.decorators;
    } else if (node.modifiers) {
      decoratorArray = node.modifiers;
    }

    decoratorArray.forEach(decorator => {
      const symbol = this.typeChecker.getSymbolAtLocation(decorator.expression);
      if (!symbol) {
        return;
      }
      const apiDecInfo = this.getSdkApiFromValueDeclaration(symbol.valueDeclaration.parent.parent);
      if (apiDecInfo) {
        apiDecInfo.setPosition(position ?
          position :
          ts.getLineAndCharacterOfPosition(decorator.getSourceFile(), decorator.getStart()));
        apiDecInfo.setSourceFileName(fileName);
        apiDecInfo.setQualifiedTypeName('global');
        apiDecInfo.setPropertyName(this.getDecortorName(symbol.valueDeclaration));
        this.addApiInformation(apiDecInfo);
      }
    });
  }

  getDecortorName(node) {
    return node.name ? node.name.getText() : undefined;
  }

  /**
   * 遍历访问TypeScript 节点
   * 
   * @param {ts.Node} node 
   * @param {string} fileName 
   */
  visitNormalNode(node, fileName) {
    if (node) {
      if (ts.isCallExpression(node)) {
        this.recognizeNormalCallExpression(node, fileName);
      } else {
        this.recognizeNormal(node, fileName);
        ts.forEachChild(node, (child) => {
          this.visitNode(child, fileName);
        });
      }
    }
  }

  /**
   * 遍历访问 UI 渲染节点
   * 
   * @param {ts.Block} node 
   * @param {string} fileName 
   */
  visitUIRenderNode(node, fileName) {
    if (!node.statements) {
      return;
    }
    node.statements.forEach((statement) => {
      this.recognizeUIComponents(statement, fileName);
    });
  }

  setTypeChecker(typeChecker) {
    this.typeChecker = typeChecker;
  }

  /**
   * 保存系统API
   * 
   * @param {ApiDeclarationInformation} apiInfo 
   */
  addApiInformation(apiInfo) {
    if (!this.apiInfos) {
      this.apiInfos = [];
    }
    if (this.apiInfoSet.has(this.formatApiInfo(apiInfo))) {
      return;
    }
    this.apiInfos.push(apiInfo);
    this.apiInfoSet.add(this.formatApiInfo(apiInfo));
  }

  formatApiInfo(apiInfo) {
    return `${apiInfo.dtsName}#${apiInfo.typeName}#${apiInfo.apiRawText}#${apiInfo.sourceFileName}#${apiInfo.pos}`;
  }

  getApiInformations() {
    const apiDecInfos = this.apiInfos ? this.apiInfos : [];
    apiDecInfos.forEach((apiInfo) => {
      apiInfo.setApiNode(undefined);
    });
    return apiDecInfos;
  }

  isSdkApi(apiFilePath) {
    return FileSystem.isInDirectory(this.systemRoot, apiFilePath);
  }

  /**
   * 判断是否为创建ArkUI组件的方法
   * 
   * @param {ts.Node} node 
   */
  isArkUIRenderMethod(node) {
    if (ts.isMethodDeclaration(node) || ts.isFunctionDeclaration(node)) {
      return this.isBuildMethodInStruct(node) || this.hasArkUIDecortor(node);
    }
    return false;
  }

  /**
   * 是否为struct 中的 build 方法。
   * 
   * @param {ts.Node} node 
   * @returns ture or false
   */
  isBuildMethodInStruct(node) {
    return node.name && this.arkUIRender.has(node.name.getText()) && ts.isStructDeclaration(node.parent);
  }

  /**
   * 判断是否有ArkUI注解
   * 
   * @param {ts.Node} node 
   * @returns true or false
   */
  hasArkUIDecortor(node) {
    if (node.decorators) {
      for (const decorator of node.decorators) {
        const decoratorName = this.getDecortorIdefiner(decorator);
        if (!decoratorName) {
          continue;
        }
        const decoratorStr = `@${decoratorName.getText()}`;
        if (!this.arkUIDecorator.has(decoratorStr)) {
          continue;
        }
        const decoratroSymbol = this.typeChecker.getSymbolAtLocation(decoratorName);
        if (this.isSdkApi(decoratroSymbol.valueDeclaration.getSourceFile().fileName)) {
          return true;
        }
      }
    }
    return false;
  }

  getDecortorIdefiner(decoratorExp) {
    if (ts.isDecorator(decoratorExp) || ts.isCallExpression(decoratorExp)) {
      return this.getDecortorIdefiner(decoratorExp.expression);
    }
    return ts.isIdentifier(decoratorExp) ? decoratorExp : undefined;
  }

  /**
   * 获取AST节点的API信息。
   * 
   * @param {ts.Node} node 
   * @param {string} fileName 
   * @param {Function} positionCallback 
   * @returns {ApiDeclarationInformation | undefined} apiDecInfo
   */
  recognizeApiWithNode(node, fileName, positionCallback, useDeclarations) {
    let finallySymbol = undefined;
    if (!node) {
      return finallySymbol;
    }

    try {
      let symbol = this.typeChecker.getSymbolAtLocation(node);
      if (symbol && symbol.flags === ts.SymbolFlags.Alias) {
        symbol = this.typeChecker.getAliasedSymbol(symbol);
      }
      finallySymbol = this.recognizeApiWithNodeAndSymbol(node, symbol, fileName, positionCallback, useDeclarations);
    } catch (error) {
      Logger.error('UNKNOW NODE', error);
    }
    return finallySymbol;
  }

  recognizeApiWithNodeAndSymbol(node, symbol, fileName, positionCallback, useDeclarations) {
    if (symbol) {
      const apiDecInfo = this.getSdkApiDeclarationWithSymbol(symbol, node, useDeclarations);
      const position = ts.getLineAndCharacterOfPosition(node.getSourceFile(), positionCallback(node));
      if (symbol.valueDeclaration && this.isSdkApi(symbol.valueDeclaration.getSourceFile().fileName)) {
        this.recognizeDecorators(symbol.valueDeclaration, fileName, position);
      }
      if (apiDecInfo) {
        apiDecInfo.setPosition(position);
        apiDecInfo.setSourceFileName(fileName);
        this.addApiInformation(apiDecInfo);
        return apiDecInfo;
      }
    }
    return undefined;
  }

  /**
   * 识别TS代码节点中的系统API
   * 
   * @param {ts.Node} node 
   * @param {string} fileName
   */
  recognizeNormal(node, fileName) {
    if (ts.isPropertyAccessExpression(node)) {
      this.recognizePropertyAccessExpression(node, fileName);
    } else if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)) {
      this.recognizeHeritageClauses(node, fileName);
    } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      this.recognizeApiWithNode(node.expression, fileName, (node) => node.getStart());
    } else if (ts.isStructDeclaration(node)) {
      this.recognizeHeritageClauses(node, fileName);
    } else if (ts.isTypeReferenceNode(node)) {
      this.recognizeTypeReferenceNode(node, fileName);
    } else if (ts.isObjectLiteralExpression(node)) {
      this.recognizeObjectLiteralExpression(node, fileName);
    } else if (ts.isCallExpression(node)) {
      this.recognizeEtsComponentAndAttributeApi(node.expression, fileName);
    }
  }

  recognizeTypeReferenceNode(node, fileName) {
    if (ts.isTypeReferenceNode(node)) {
      this.recognizeTypeReferenceNode(node.typeName, fileName);
    } else if (ts.isQualifiedName(node)) {
      this.recognizeApiWithNode(node.typeName?.right, fileName, (node) => node.getStart(), true);
    } else if (ts.isIdentifier(node)) {
      this.recognizeApiWithNode(node, fileName, (node) => node.getStart(), true);
    }
  }

  recognizeNormalCallExpression(node, fileName) {
    if (!node) {
      return undefined;
    }
    if (ts.isCallExpression(node)) {
      const apiDecInfo = this.recognizeNormalCallExpression(node.expression, fileName);
      this.recognizeNormalCallExpressionArguments(apiDecInfo, node.arguments, fileName);
      return apiDecInfo;
    } else if (ts.isPropertyAccessExpression(node)) {
      this.recognizeNormalCallExpression(node.expression, fileName);
      return this.recognizePropertyAccessExpression(node, fileName);
    } else if (ts.isIdentifier(node)) {
      return this.recognizeApiWithNode(node, fileName, (node) => node.getStart());
    } else {
      return undefined;
    }
  }

  recognizeNormalCallExpressionArguments(apiDecInfo, args, fileName) {
    if (args.length === 0) {
      return;
    }
    const parameters = apiDecInfo ? apiDecInfo.apiNode.parameters : undefined;
    args.forEach((arg, index) => {
      // interface 定义作为函数入参时, 统计为API
      this.recognizeArgument(arg, fileName);
      if (!(parameters && parameters[index] && parameters[index].type)) {
        return;
      }
      const paramType = parameters[index].type;
      if (ts.isTypeReferenceNode(paramType)) {
        const paramTypeApiDecInfo = this.recognizeApiWithNode(paramType.typeName, fileName, (node) => node.getStart(), true);
        if (paramTypeApiDecInfo) {
          this.modifyTypeReferenceSourceFileName(paramType.typeName, paramTypeApiDecInfo);
          paramTypeApiDecInfo.setApiType('interface');
          paramTypeApiDecInfo.setPosition(ts.getLineAndCharacterOfPosition(arg.getSourceFile(), arg.getStart()));
        }
      }
    });
  }

  modifyTypeReferenceSourceFileName(typeNameNode, apiDecInfo) {
    const symbol = this.typeChecker.getSymbolAtLocation(typeNameNode);
    if (symbol) {
      const typeDec = symbol.declarations[0];
      let importDec = typeDec;
      while (importDec && !ts.isImportDeclaration(importDec)) {
        importDec = importDec.parent;
      }
      if (!importDec) {
        return;
      }
      const moduleSpecifier = importDec.moduleSpecifier;
      this.saveApiDecInfo(moduleSpecifier, apiDecInfo, typeNameNode);
    }
  }

  saveApiDecInfo(moduleSpecifier, apiDecInfo, typeNameNode) {
    const specialInterfaceSet = new Set(['Callback', 'AsyncCallback']);
    if (ts.isStringLiteral(moduleSpecifier, apiDecInfo)) {
      const useTypeFileName = apiDecInfo.apiNode.getSourceFile().fileName;
      const moduleRelativePaths = moduleSpecifier.getText().match(/^['"](.*)['"]$/);
      const MODULE_PATH_LENGTH = 2;
      if (moduleRelativePaths.length < MODULE_PATH_LENGTH) {
        return;
      }
      const modulePath = path.resolve(path.dirname(useTypeFileName), `${moduleRelativePaths[1]}.d.ts`);
      if (fs.existsSync(modulePath)) {
        if (specialInterfaceSet.has(typeNameNode.getText())) {
          apiDecInfo.apiText = this.getSpecialInterfaceText(modulePath, typeNameNode.getText());
        }
        const dtsPath = path.relative(this.systemRoot, modulePath).replace(/\\/g, '/');
        apiDecInfo.dtsName = path.basename(modulePath);
        apiDecInfo.packageName = path.relative(this.systemRoot, modulePath);
        apiDecInfo.dtsPath = this.formatDtsPath(dtsPath);
        apiDecInfo.typeName = apiDecInfo.propertyName;
      }
    }
  }

  getSpecialInterfaceText(modulePath, interfaceName) {
    const fileContent = fs.readFileSync(modulePath, 'utf-8');
    const apiFileName = path.basename(modulePath).replace('d.ts', '.ts');
    const sourceFile = ts.createSourceFile(apiFileName, fileContent, ts.ScriptTarget.ES2017, true);
    let interfaceText = '';
    sourceFile.statements.forEach(stat => {
      if (ts.isInterfaceDeclaration(stat) && stat.name.escapedText === interfaceName) {
        interfaceText = stat.getText().split('{')[0];
      }
    });
    return interfaceText;
  }

  formatDtsPath(dtsPath) {
    if (dtsPath.indexOf('api/@internal/full/canvaspattern.d.ts') > -1) {
      return dtsPath.replace('api/@internal/full/', 'interface/sdk-js/api/common/full/');
    } else if (dtsPath.indexOf('api/@internal/full/featureability.d.ts') > -1) {
      return dtsPath.replace('api/@internal/full/', '/interface/sdk-js/api/common/full/');
    } else if (dtsPath.indexOf('api/internal/full') > -1) {
      return dtsPath.replace('api/@internal/full/', '/interface/sdk-js/api/@internal/ets/');
    } else if (dtsPath.indexOf('component/') > -1) {
      return dtsPath.replace('component/', 'interface/sdk-js/api/@internal/component/ets/');
    } else {
      return path.join('/interface/sdk-js', dtsPath).replace(/\\/g, '/');
    }
  }

  /**
   * 识别UI组件及其属性
   * 
   * @param {ts.Node} node 
   * @param {string} fileName
   */
  recognizeUIComponents(node, fileName, parentName) {
    if (ts.isEtsComponentExpression(node)) {
      // ETS组件的声明, EtsComponentExpression 表示有子组件的组件.
      this.recognizeEtsComponentExpression(node, fileName);
    } else if (ts.isCallExpression(node)) {
      // 组件链式调用
      this.recognizeComponentAttributeChain(node, fileName, []);
    } else if (ts.isIfStatement(node)) {
      this.recognizeIfStatement(node, fileName);
    } else {
      ts.forEachChild(node, (child) => {
        this.recognizeUIComponents(child, fileName);
      });
    }
  }

  /**
   * 识别在对象内，作为入参的API
   * 
   * @param {ts.Node} node 
   * @param {string} fileName 
   * @returns 
   */
  recognizeObjectLiteralExpression(node, fileName) {
    let parentName = '';
    if (node.parent && node.parent.expression && ts.isIdentifier(node.parent.expression)) {
      parentName = node.parent.expression.escapedName ?
        node.parent.expression.escapedName : node.parent.expression.escapedText;
    }
    const parentType = this.typeChecker.getContextualType(node);
    if (!parentType || !parentType.properties) {
      return;
    }
    if (parentType.properties.length === 0) {
      return;
    }
    if (!parentType.properties[0].valueDeclaration) {
      return;
    }
    const sourceFile = parentType.properties[0].valueDeclaration.getSourceFile();

    //判断是否为系统API
    if (!this.isSdkApi(sourceFile.fileName)) {
      return;
    }
    let parentSymbol = sourceFile.locals.get(parentName);
    const apiMapInParent = this.getApiMapInParent(parentSymbol, parentType);

    node.properties.forEach(property => {
      const apiNode = apiMapInParent.get(property.name.escapedText);
      if (!apiNode) {
        return;
      }
      if (ts.isTypeLiteralNode(apiNode.parent)) {
        return;
      }
      const apiDecInfo = this.getSdkApiFromValueDeclaration(apiNode, property, fileName);
      if (apiDecInfo) {
        const position = ts.getLineAndCharacterOfPosition(property.getSourceFile(), property.name.getStart());
        this.recognizeDecorators(apiNode, fileName, position);
        apiDecInfo.setPosition(position);
        apiDecInfo.setSourceFileName(fileName);
        this.addApiInformation(apiDecInfo);
      }
    });
  }

  getApiMapInParent(parentSymbol, parentType) {
    const apiMapInParent = new Map();
    if (!parentSymbol) {
      parentType.members.forEach((memberValue, member) => {
        apiMapInParent.set(member, memberValue.valueDeclaration);
      });
    } else {
      parentSymbol.declarations[0]?.members?.forEach(member => {
        if (!member.name) {
          return;
        }
        apiMapInParent.set(member.name.escapedText, member);
      });
    }
    return apiMapInParent;
  }

  /**
   * 识别条件渲染
   * @param {ts.Node} node 
   * @param {string} fileName 
   */
  recognizeIfStatement(node, fileName) {
    this.recognizeArgument(node.expression, fileName);
    const thenStatements = ts.isBlock(node) ? node.statements :
      (ts.isBlock(node.thenStatement) ? node.thenStatement.statements : undefined);
    if (thenStatements) {
      thenStatements.forEach((child) => {
        this.recognizeUIComponents(child, fileName);
      });
    }
    if (node.elseStatement) {
      this.recognizeIfStatement(node.elseStatement, fileName);
    }
  }

  /**
   * 识别组件链式调用中的API
   * @param {ts.Node} node 
   * @param {string} fileName 
   */
  recognizeComponentAttributeChain(node, fileName) {
    if (ts.isCallExpression(node)) {
      const chainResult = this.recognizeComponentAttributeChain(node.expression, fileName);
      this.recognizeArguments(node.arguments, fileName);
      return new ComponentAttrResult(chainResult.componentInfo, undefined);
    } else if (ts.isPropertyAccessExpression(node)) {
      const chainResult = this.recognizeComponentAttributeChain(node.expression, fileName);
      const attrInfo = this.recognizeEtsComponentAndAttributeApi(node, fileName);
      if (chainResult.componentInfo && attrInfo) {
        attrInfo.setComponentName(chainResult.componentInfo.propertyName);
      }
      return new ComponentAttrResult(chainResult.componentInfo, attrInfo);
    } else if (ts.isEtsComponentExpression(node)) {
      return new ComponentAttrResult(this.recognizeEtsComponentExpression(node, fileName), undefined);
    } else if (ts.isIdentifier(node)) {
      return new ComponentAttrResult(this.recognizeEtsComponentAndAttributeApi(node, fileName), undefined);
    } else {
      return new ComponentAttrResult(undefined, undefined);
    }
  }

  /**
   * 识别ArkUI组件表达式
   * @param {ts.EtsComponentExpression} node 
   * @param {string} fileName 
   * @returns 
   */
  recognizeEtsComponentExpression(node, fileName) {
    // node.expression is component name Identifier
    const apiDecInfo = this.recognizeEtsComponentAndAttributeApi(node.expression, fileName);

    if (node.arguments) {
      this.recognizeComponentArguments(apiDecInfo, node.arguments, fileName);
    }

    if (node.body) {
      node.body.statements.forEach((statement) => {
        this.recognizeUIComponents(statement, fileName);
      });
    }

    return apiDecInfo;
  }

  /**
   * 识别组件入参
   * @param {ApiDeclarationInformation} apiDecInfo
   * @param {ts.Node[]} args 
   * @param {string} fileName 
   */
  recognizeComponentArguments(apiDecInfo, args, fileName) {
    // ForEach, LazyForEach
    if (apiDecInfo && this.forEachComponents.has(apiDecInfo.propertyName)) {
      args.forEach((arg, index) => {
        // itemGenerator
        if (index === 1) {
          this.visitUIRenderNode(arg.body ? arg.body : arg, fileName);
        } else {
          this.recognizeArgument(arg, fileName);
        }
      });
    } else {
      this.recognizeArguments(args, fileName);
    }
  }

  /**
   * 识别参数中的API
   * @param {ts.Node[]} args 
   * @param {string} fileName
   */
  recognizeArguments(args, fileName) {
    args.forEach((arg) => {
      this.recognizeArgument(arg, fileName);
    });
  }

  recognizeArgument(node, fileName) {
    if (!node) {
      return;
    }
    this.recognizeNormal(node, fileName);
    ts.forEachChild(node, (child) => {
      this.recognizeArgument(child, fileName);
    });
  }


  /**
   * 获取组件或属性的API详情
   * 
   * @param {ts.Identifier} node 
   * @param {string} fileName
   * @returns {ApiDeclarationInformation | undefined} apiDecInfo
   */
  recognizeEtsComponentAndAttributeApi(node, fileName) {
    // recognize component
    const apiDecInfo = this.recognizeApiWithNode(node, fileName,
      (node) => ts.isPropertyAccessExpression(node) ? node.name.getStart() : node.getStart());
    return apiDecInfo;
  }

  /**
   * 通过语义分析，识别继承关系中的系统API
   * 
   * @param {ts.ClassDeclaration | ts.InterfaceDeclaration} node
   * @param {ts.ClassDeclaration|ts.InterfaceDeclaration} node 
   */
  recognizeHeritageClauses(node, fileName) {
    if (!node.heritageClauses) {
      return;
    }
    const nodeType = this.typeChecker.getTypeAtLocation(node);
    const nodeSymbol = nodeType.getSymbol();
    if (!nodeSymbol.members) {
      return;
    }
    const heritagePropertyMap = this.collectAllHeritageMethods(node);
    if (!nodeSymbol.valueDeclaration) {
      return;
    }
    if (!nodeSymbol.valueDeclaration.heritageClauses) {
      return;
    }
    if (heritagePropertyMap.size === 0) {
      const extendNodes = nodeSymbol.valueDeclaration.heritageClauses[0].types;
      this.getExtendClassPropertyMap(extendNodes, heritagePropertyMap);
    }
    if (heritagePropertyMap === 0) {
      return;
    }
    nodeSymbol.members.forEach((memberSymbol, memberName) => {
      if (heritagePropertyMap.has(memberName)) {
        const apiDecInfo = this.getSdkApiDeclarationWithSymbol(heritagePropertyMap.get(memberName), undefined);
        if (apiDecInfo) {
          apiDecInfo.setPosition(ts.getLineAndCharacterOfPosition(node.getSourceFile(), memberSymbol.valueDeclaration.getStart()));
          apiDecInfo.setSourceFileName(fileName);
          this.addApiInformation(apiDecInfo);
        }
      }
    });
  }

  /**
   * 通过向上查找继承的节点，收集多次继承情况下的API
   * @param {ts.Node} extendNodes 
   * @param {Map} extendClassPropertyMap 
   */
  getExtendClassPropertyMap(extendNodes, extendClassPropertyMap) {
    extendNodes.forEach(extendNode => {
      const extendNodeType = this.typeChecker.getTypeAtLocation(extendNode);
      if (!extendNodeType) {
        return;
      }
      const extendNodeSymbol = extendNodeType.getSymbol();
      if (!extendNodeSymbol) {
        return;
      }
      const valueDeclaration = extendNodeSymbol.declarations[0];
      if (valueDeclaration && !this.isSdkApi(valueDeclaration.getSourceFile().fileName) && extendNodeSymbol.valueDeclaration &&
        extendNodeSymbol.valueDeclaration.heritageClauses) {
        const parentNodes = extendNodeSymbol.valueDeclaration.heritageClauses[0].types;
        this.getExtendClassPropertyMap(parentNodes, extendClassPropertyMap);
      } else {
        extendNodeSymbol.members.forEach((memberSymbol, memberName) => {
          extendClassPropertyMap.set(memberName, memberSymbol);
        });
      }
    });
  }

  /**
   * 搜集所有父类(属于SDK中的API)的方法和属性。
   * 
   * @param {ts.Node} node 
   * @returns Map
   */
  collectAllHeritageMethods(node) {
    const heritageMembers = new Map();
    if (!node.heritageClauses) {
      return heritageMembers;
    }
    node.heritageClauses.forEach((heritage) => {
      heritage.types.forEach((child) => {
        const childSymbol = this.typeChecker.getSymbolAtLocation(child.expression);
        if (!childSymbol) {
          return;
        }
        const type = this.typeChecker.getTypeOfSymbolAtLocation(childSymbol, child);
        const typeSymbol = type.getSymbol();
        if (!typeSymbol) {
          return;
        }
        if (!typeSymbol && childSymbol.members) {
          this.setHeritageMembersFroMmembers(heritageMembers, childSymbol.members);
          return;
        }
        const valueDeclaration = typeSymbol.valueDeclaration;
        if (!valueDeclaration || !this.isSdkApi(valueDeclaration.getSourceFile().fileName)) {
          return;
        }
        this.setHeritageMembersFroMmembers(heritageMembers, typeSymbol.members);
      });
    });
    return heritageMembers;
  }

  /**
   * 搜集所有父类(属于SDK中的API)的方法和属性。
   * 
   * @param {Map} heritageMembers 
   * @param {ts.NodeArray} members 
   */
  setHeritageMembersFroMmembers(heritageMembers, members) {
    members.forEach((memberSymbol, memberName) => {
      heritageMembers.set(memberName, memberSymbol);
    });
  }

  /**
   * 解析属性访问
   * 
   * @param {ts.PropertyAccessExpression} node 
   */
  recognizePropertyAccessExpression(node, fileName) {
    return this.recognizeApiWithNode(node, fileName, (node) => node.name.getStart());
  }

  /**
   * 获取 export {xx} 中xx的定义
   * @param {ts.Symbol} symbol
   */
  getAliasExcludesRealValueDeclarations(symbol) {
    const symbolName = symbol.escapedName;
    const sourceFile = symbol.declarations[0].getSourceFile();
    const realSymbol = sourceFile.locals ? sourceFile.locals.get(symbolName) : undefined;
    return realSymbol ? realSymbol.valueDeclaration : undefined;
  }

  getApiRawText(node) {
    switch (node.kind) {
      case ts.SyntaxKind.ClassDeclaration:
        return `class ${node.name ? node.name.getText() : ''}`;
      case ts.SyntaxKind.InterfaceDeclaration:
        return `interface ${node.name ? node.name.getText() : ''}`;
      case ts.SyntaxKind.EnumDeclaration:
        return `enum ${node.name ? node.name.getText() : ''}`;
      case ts.SyntaxKind.ModuleDeclaration:
        return `namespace ${node.name ? node.name.getText() : ''}`;
      case ts.SyntaxKind.StructDeclaration:
        return `struct ${node.name ? node.name.getText() : ''}`;
      case node.getText() === 'AsyncCallback' || node.getText() === 'Callback':
        return '';
      default:
        return node.getText();
    }
  }

  getApiTypeName(node) {
    if (ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) || ts.isEnumDeclaration(node) ||
      ts.isModuleDeclaration(node)) {
      return node.name ? node.name.getText() : '';
    }
    return undefined;
  }

  /**
   * 获取节点定义在哪个文件哪个类型下。
   * 
   * @param {ts.Symbol} type 
   */
  getSdkApiDeclarationWithSymbol(symbol, node, useDeclarations) {
    const sourceSymbol = symbol;
    let valudeDec = sourceSymbol && sourceSymbol.valueDeclaration ? sourceSymbol.valueDeclaration :
      (sourceSymbol.flags & ts.SymbolFlags.AliasExcludes ? this.getAliasExcludesRealValueDeclarations(symbol) : undefined);
    valudeDec = !valudeDec && useDeclarations ? symbol.declarations[0] : valudeDec;
    if (!valudeDec) {
      return undefined;
    }
    if (valudeDec.kind === ts.SyntaxKind.TypeParameter) {
      return undefined;
    }
    const sourceFile = valudeDec.getSourceFile();
    if (!this.isSdkApi(sourceFile.fileName)) {
      return undefined;
    }
    let apiDecInfo = undefined;
    if (symbol.declarations.length > 1) {
      apiDecInfo = this.getSdkApiFromMultiDeclarations(symbol, node);
    }
    return apiDecInfo ? apiDecInfo : this.getSdkApiFromValueDeclaration(valudeDec);
  }

  getSdkApiFromMultiDeclarations(symbol, node) {
    if (!node) {
      return undefined;
    }
    let callExpressionNode = node;
    while (callExpressionNode && !ts.isCallExpression(callExpressionNode)) {
      callExpressionNode = callExpressionNode.parent;
    }
    if (!callExpressionNode) {
      return undefined;
    }
    const matchedDec = this.findBestMatchedDeclaration(callExpressionNode, symbol);
    if (!matchedDec) {
      return undefined;
    }
    return this.getSdkApiFromValueDeclaration(matchedDec);
  }

  /**
   * 查找参数个数匹配，参数类型匹配的API
   * @param {number} argumentLength
   * @param {ts.Symbol} symbol
   * @returns api declaration node.
   */
  findBestMatchedDeclaration(callExpressionNode, symbol) {
    const callExpArgLen = callExpressionNode.arguments.length;
    if (callExpArgLen === 0) {
      return undefined;
    }
    let matchedDecs = [];
    for (let dec of symbol.declarations) {
      if (dec.parameters && dec.parameters.length === callExpArgLen) {
        matchedDecs.push(dec);
      }
    }
    if (matchedDecs.length === 1) {
      return matchedDecs[0];
    }
    if ('on' === callExpressionNode.expression.name.getText()) {
      return this.findBestMatchedApi(callExpressionNode, matchedDecs);
    }
    const lastArgument = callExpressionNode.arguments[callExpArgLen - 1];
    if (this.isAsyncCallbackCallExp(lastArgument)) {
      matchedDecs = matchedDecs.filter((value) => {
        return this.isAsyncCallbackApi(value);
      });
    } else {
      matchedDecs = matchedDecs.filter((value) => {
        return !this.isAsyncCallbackApi(value);
      });
    }
    return matchedDecs.length > 0 ? matchedDecs[0] : undefined;
  }

  /**
   * 通过匹配type字符串找到正确的API
   * 
   * @param { ts.Node } callExpressionNode 
   * @param { Array } matchedDecs 
   * @returns 
   */
  findBestMatchedApi(callExpressionNode, matchedDecs) {
    let apiNode = undefined;
    if (ts.isStringLiteral(callExpressionNode.arguments[0])) {
      const useType = callExpressionNode.arguments[0].text;
      for (let i = 0; i < matchedDecs.length; i++) {
        const matchDec = matchedDecs[i];
        const apiSubscribeTypes = this.getSubscribeApiType(matchDec.parameters[0].type);
        if (apiSubscribeTypes.has(useType)) {
          apiNode = matchDec;
        }
      }
    }

    if (!apiNode) {
      apiNode = matchedDecs[0];
    }
    return apiNode;
  }

  getSubscribeApiType(typeNode) {
    const literalTypeSet = new Set();
    if (ts.isLiteralTypeNode(typeNode)) {
      literalTypeSet.add(typeNode.literal.text);
    } else if (ts.isUnionTypeNode(typeNode)) {
      typeNode.types.forEach(type => {
        literalTypeSet.add(type.literal.text);
      });
    }
    return literalTypeSet;
  }

  isAsyncCallbackCallExp(node) {
    const type = this.typeChecker.getTypeAtLocation(node);
    if (!type || !type.symbol || !type.symbol.valueDeclaration) {
      return false;
    }
    const typeValueDec = type.symbol.valueDeclaration;
    return ts.isArrowFunction(typeValueDec) || ts.isMethodDeclaration(typeValueDec) ||
      ts.isFunctionDeclaration(typeValueDec) || ts.isMethodSignature(typeValueDec) ||
      ts.isFunctionExpression(typeValueDec);
  }

  isAsyncCallbackApi(declaration) {
    if (!declaration.parameters) {
      return false;
    }
    const lastArgument = declaration.parameters[declaration.parameters.length - 1];
    const argumentType = this.typeChecker.getTypeAtLocation(lastArgument);
    if (argumentType && argumentType.symbol) {
      return argumentType.symbol.escapedName === 'AsyncCallback';
    } else {
      if (!lastArgument.type || !lastArgument.type.typeName) {
        return false;
      }
      return 'AsyncCallback' === lastArgument.type.typeName.getText();
    }
  }

  getSdkApiFromValueDeclaration(valudeDec) {
    const sourceFile = valudeDec.getSourceFile();
    const apiInfo = new ApiDeclarationInformation();
    const dtsPath = sourceFile.fileName.replace(this.systemRoot.replace(/\\/g, '/'), '');
    apiInfo.setPropertyName(this.getMethodOrTypeName(valudeDec));
    apiInfo.setApiRawText(this.getApiRawText(valudeDec));
    apiInfo.setPackageName(this.getPackageName(sourceFile.fileName));
    apiInfo.setSdkFileName(path.basename(sourceFile.fileName));
    apiInfo.setTypeName(this.getApiTypeName(valudeDec));
    apiInfo.setApiNode(valudeDec);
    apiInfo.setApiType(this.getApiType(valudeDec));
    apiInfo.setDtsPath(this.formatDtsPath(dtsPath));
    apiInfo.setCompletedText(this.getApiText(valudeDec));

    if (ts.isSourceFile(valudeDec.parent) && ts.isFunctionDeclaration(valudeDec)) {
      apiInfo.setQualifiedTypeName('global');
    }

    let curDeclaration = valudeDec.parent;
    while (!ts.isSourceFile(curDeclaration)) {
      const nodeName = this.getMethodOrTypeName(curDeclaration);
      if (nodeName) {
        apiInfo.setTypeName(nodeName);
        apiInfo.setQualifiedTypeName(nodeName);
      }
      curDeclaration = curDeclaration.parent;
    }

    const qualifiedName = apiInfo.qualifiedTypeName ?
      `${apiInfo.qualifiedTypeName}.${apiInfo.propertyName}` : `${apiInfo.propertyName}`;
    apiInfo.setQualifiedName(qualifiedName);
    return this.fillJSDocInformation(apiInfo, valudeDec);
  }

  getApiType(valudeDec) {
    let type = apiType.get(valudeDec.kind);
    if (ts.isPropertySignature(valudeDec) && valudeDec.type && ts.isFunctionTypeNode(valudeDec.type)) {
      type = 'method';
    }
    return type;
  }

  getApiText(node) {
    switch (node.kind) {
      case ts.SyntaxKind.ClassDeclaration:
        return node.getText().split('{')[0];
      case ts.SyntaxKind.InterfaceDeclaration:
        return node.getText().split('{')[0];
      case ts.SyntaxKind.EnumDeclaration:
        return node.getText().split('{')[0];
      case ts.SyntaxKind.ModuleDeclaration:
        return node.getText().split('{')[0];
      case ts.SyntaxKind.StructDeclaration:
        return node.getText().split('{')[0];
      default:
        return node.getText();
    }
  }

  /**
   * 补充JsDoc中的信息。
   * 
   * @param {ApiDeclarationInformation} apiInfo 
   * @param {ts.Node} node 
   * @returns 
   */
  fillJSDocInformation(apiInfo, node) {
    this.forEachJsDocTags(node, (tag) => {
      (this.fillDeprecatedInfo(tag, apiInfo) || this.fillUseInsteadInfo(tag, apiInfo));
    });
    if (!apiInfo.deprecated) {
      const thiz = this;
      function reachJsDocTag(tag) {
        thiz.fillDeprecatedInfo(tag, apiInfo);
        return apiInfo.deprecated;
      }

      function reachParent(parent) {
        thiz.forEachJsDocTags(parent, reachJsDocTag);
        return apiInfo.deprecated;
      }
      this.forEachNodeParent(node, reachParent);
    }
    return apiInfo;
  }

  fillUseInsteadInfo(tag, apiInfo) {
    if (tag.kind === ts.SyntaxKind.JSDocTag &&
      tag.tagName.getText() === 'useinstead') {
      apiInfo.setUseInstead(tag.comment);
      return true;
    }
    return false;
  }

  fillDeprecatedInfo(tag, apiInfo) {
    if (tag.kind === ts.SyntaxKind.JSDocDeprecatedTag) {
      apiInfo.setDeprecated(tag.comment);
      return true;
    }
    return false;
  }

  forEachJsDocTags(node, callback) {
    if (!node.jsDoc || !callback) {
      return;
    }
    const latestJsDoc = node.jsDoc[node.jsDoc.length - 1];
    if (!latestJsDoc.tags) {
      return;
    }
    for (const tag of latestJsDoc.tags) {
      if (callback(tag)) {
        break;
      };
    };
  }

  forEachNodeParent(node, callback) {
    if (!node || !callback) {
      return;
    }
    let curNode = node.parent;
    while (curNode) {
      if (callback(curNode)) {
        break;
      }
      curNode = curNode.parent;
    }
  }

  getMethodOrTypeName(node) {
    return node.name ? node.name.getText() : undefined;
  }

  getPackageName(filePath) {
    const isArkUI = FileSystem.isInDirectory(path.resolve(this.systemRoot, 'component'), filePath);
    return isArkUI ? 'ArkUI' : path.relative(this.systemRoot, filePath);
  }
}

const apiType = new Map([
  [ts.SyntaxKind.FunctionDeclaration, 'method'],
  [ts.SyntaxKind.MethodSignature, 'method'],
  [ts.SyntaxKind.MethodDeclaration, 'method'],
  [ts.SyntaxKind.EnumMember, 'enum_instance'],
  [ts.SyntaxKind.PropertySignature, 'field'],
  [ts.SyntaxKind.VariableStatement, 'constant'],
  [ts.SyntaxKind.VariableDeclaration, 'constant'],
  [ts.SyntaxKind.VariableDeclarationList, 'constant'],
  [ts.SyntaxKind.TypeAliasDeclaration, 'type'],
  [ts.SyntaxKind.ClassDeclaration, 'class'],
  [ts.SyntaxKind.InterfaceDeclaration, 'interface'],
  [ts.SyntaxKind.EnumDeclaration, 'enum_class'],
  [ts.SyntaxKind.PropertyDeclaration, 'field']
]);

class ComponentAttrResult {
  constructor(componentInfo, attrInfo) {
    this.componentInfo = componentInfo;
    this.attrInfo = attrInfo;
  }
}

class ApiDeclarationInformation {
  constructor() {
    this.dtsName = '';
    this.packageName = '';
    this.propertyName = '';
    this.qualifiedTypeName = '';
    this.pos = '';
    this.sourceFileName = '';
    this.deprecated = '';
    this.apiRawText = '';
    this.qualifiedName = '';
    this.useInstead = '';
    this.typeName = '';
  }

  setSdkFileName(fileName) {
    this.dtsName = fileName;
  }

  setPackageName(packageName) {
    this.packageName = packageName;
  }

  setPropertyName(propertyName) {
    this.propertyName = propertyName;
  }

  setQualifiedTypeName(typeName) {
    if (!this.qualifiedTypeName) {
      this.qualifiedTypeName = typeName;
    } else {
      this.qualifiedTypeName = `${typeName}.${this.qualifiedTypeName}`;
    }
  }

  setTypeName(typeName) {
    if (typeName && (!this.typeName || this.typeName === '')) {
      this.typeName = typeName;
    }
  }

  setPosition(pos) {
    const { line, character } = pos;
    this.pos = `${line + 1},${character + 1}`;
  }

  setSourceFileName(sourceFileName) {
    this.sourceFileName = sourceFileName;
  }

  /**
   * 设置废弃版本号
   * 
   * @param {string} deprecated 
   */
  setDeprecated(deprecated) {
    const regExpResult = deprecated.match(/\s*since\s*(\d)+.*/);
    const RESULT_LENGTH = 2;
    if (regExpResult !== null && regExpResult.length === RESULT_LENGTH) {
      this.deprecated = regExpResult[1];
    }
  }

  setApiRawText(apiRawText) {
    this.apiRawText = apiRawText.replace(/\;/g, '');
  }

  setQualifiedName(qualifiedName) {
    this.qualifiedName = qualifiedName;
  }

  setUseInstead(useInstead) {
    this.useInstead = useInstead;
  }

  setComponentName(componentName) {
    this.componentName = componentName;
  }

  setApiNode(node) {
    this.apiNode = node;
  }

  setApiType(apiType) {
    this.apiType = apiType;
  }

  setDtsPath(dtsPath) {
    this.dtsPath = dtsPath;
  }

  setCompletedText(completedText) {
    this.apiText = completedText;
  }
}

exports.SystemApiRecognizer = SystemApiRecognizer;