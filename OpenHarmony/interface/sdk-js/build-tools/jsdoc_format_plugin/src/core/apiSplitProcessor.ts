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
import { Code } from '../utils/constant';
import type {
  comment, Context, ISourceCodeProcessor, ModifyLogResult, ProcessResult, sourceParser,
  MethodNodeType, ApiSplitProcessorInterface
} from './typedef';
import { ErrorInfo, JSDocModifyType } from './typedef';
import { CommentHelper, LogResult } from './coreImpls';
import { LogReportStringUtils } from '../utils/stringUtils';

export class ApiSplitProcessor implements ISourceCodeProcessor, sourceParser.ITransformCallback {

  context?: Context;

  async process(context: Context, content: string): Promise<ProcessResult> {
    if (!context.getOptions().splitUnionTypeApi) {
      return { code: Code.OK, content: content };
    }
    this.context = context;
    const sourceParser = context.getSourceParser(content);
    const sourceFile = sourceParser.transform(this);
    return {
      code: Code.OK,
      content: sourceFile ? sourceParser.printSourceFile(sourceFile) : content
    };
  }

  onTransformNode(node: comment.CommentNode): ts.Node | undefined {
    if (node.astNode === undefined) {
      return undefined;
    }
    const nodeProcessor = nodeProcessorMap.get(node.astNode.kind);
    return nodeProcessor ? nodeProcessor(node.astNode, this.context) : undefined;
  }
}

/**
 * 订阅事件api拆分工具类
 */
class ApiSplitProcessorHelper {

  static splitEventValues(node: ts.Node): string[] {
    let eventValues: Array<string> = [];
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isMethodSignature(node)) {
      let functionName: string = '';
      if (node.name && ts.isIdentifier(node.name)) {
        functionName = node.name.getText();
      }
      if ((functionName !== 'on') && (functionName !== 'off')) {
        return eventValues;
      }
      if ((node.parameters[0].type) && (node.parameters[0].type.kind === ts.SyntaxKind.UnionType)) {
        const types: ts.NodeArray<ts.TypeNode> = (node.parameters[0].type as ts.UnionTypeNode).types;
        for (let i = 0; i < types.length; i++) {
          const eventValueNode: ts.TypeNode = types[i];
          if (eventValueNode.kind === ts.SyntaxKind.LiteralType &&
            (eventValueNode as ts.LiteralTypeNode).literal.kind === ts.SyntaxKind.StringLiteral) {
            const eventValue = (eventValueNode as ts.LiteralTypeNode).literal.getText();
            // 这里获取的eventValue包含了单引号或双引号，因此需要进行截取
            eventValues.push(eventValue.slice(1, eventValue.length - 1));
          } else {
            eventValues = [];
            break;
          }
        }
      }
    }
    return eventValues;
  }

  static logReportProcess(node: MethodNodeType, context?: Context): void {
    const apiName: string = `${node.name?.getText()}(${node.parameters[0].type?.getFullText()})`;
    const description: string = LogReportStringUtils.createErrorInfo(ErrorInfo.EVENT_SUBSCRIPTION_SPLITTION, [`${apiName}`]);
    const comments: Array<comment.CommentInfo> = CommentHelper.getNodeLeadingComments(node, node.getSourceFile());
    const modifyLogResult: ModifyLogResult = LogResult.createModifyResult(node, comments, description, context,
      apiName, JSDocModifyType.EVENT_SUBSCRIPTION_SPLITTION);
    context?.getLogReporter().addModifyResult(modifyLogResult);
  }

  static createNewParams(node: MethodNodeType, eventValue: string, typeParam: ts.ParameterDeclaration): ts.ParameterDeclaration[] {
    const literalTypeNode = ts.factory.createLiteralTypeNode(ts.factory.createStringLiteral(eventValue));
    const newTypeParam: ts.ParameterDeclaration = ts.factory.createParameterDeclaration(typeParam.modifiers,
      typeParam.dotDotDotToken, typeParam.name, typeParam.questionToken, literalTypeNode, typeParam.initializer);
    const newParams: Array<ts.ParameterDeclaration> = [];
    newParams.push(newTypeParam);
    for (let i = 1; i < node.parameters.length; i++) {
      const param: ts.ParameterDeclaration = node.parameters[i];
      const paramNode: ts.ParameterDeclaration = ts.factory.createParameterDeclaration(param.modifiers,
        param.dotDotDotToken, param.name, param.questionToken, param.type, param.initializer);
      newParams.push(paramNode);
    }
    return newParams;
  }

  /**
   * 创建新的FunctionDeclaration类型节点数组
   * @param node 当前节点
   * @param eventValues 事件名称数组
   * @returns 新创建的节点数组
   */
  static createFunctionDecNodes(node: ts.FunctionDeclaration, eventValues: Array<string>): Array<ts.FunctionDeclaration> {
    const newFunctionNodes: Array<ts.FunctionDeclaration> = [];
    const typeParam: ts.ParameterDeclaration = node.parameters[0];
    const modifiers: Array<ts.Modifier> = [];
    node.modifiers?.forEach((modifier: ts.Modifier) => {
      ts.setEmitFlags(modifier, ts.EmitFlags.NoLeadingComments);
      const newModifier = ts.factory.createModifier(modifier.kind);
      modifiers.push(newModifier);
    });
    const newModifiers: ts.NodeArray<ts.Modifier> = ts.factory.createNodeArray(modifiers);
    eventValues.forEach((eventValue: string) => {
      const newParams: Array<ts.ParameterDeclaration> = ApiSplitProcessorHelper.createNewParams(node, eventValue, typeParam);
      const newFunctionNode: ts.FunctionDeclaration = ts.factory.createFunctionDeclaration(newModifiers,
        node.asteriskToken, node.name, node.typeParameters, newParams, node.type, node.body);
      const comments: Array<comment.CommentInfo> = CommentHelper.getNodeLeadingComments(node, node.getSourceFile());
      CommentHelper.setComment(newFunctionNode, [CommentHelper.getEmptyLineComment(), ...comments]);
      newFunctionNodes.push(newFunctionNode);
    });
    return newFunctionNodes;
  }

  /**
   * 创建新的MethodDeclaration类型节点数组
   * @param node 当前节点
   * @param eventValues 事件名称数组
   * @returns 新创建的节点数组
   */
  static createMethodDecNodes(node: ts.MethodDeclaration, eventValues: Array<string>): Array<ts.MethodDeclaration> {
    const newFunctionNodes: Array<ts.MethodDeclaration> = [];
    const typeParam: ts.ParameterDeclaration = node.parameters[0];
    eventValues.forEach((eventValue: string) => {
      const newParams: Array<ts.ParameterDeclaration> = ApiSplitProcessorHelper.createNewParams(node, eventValue, typeParam);
      ts.setEmitFlags(node.name, ts.EmitFlags.NoLeadingComments);
      const newFunctionNode: ts.MethodDeclaration = ts.factory.createMethodDeclaration(node.modifiers, node.asteriskToken,
        node.name, node.questionToken, node.typeParameters, newParams, node.type, node.body);
      const comments: Array<comment.CommentInfo> = CommentHelper.getNodeLeadingComments(node, node.getSourceFile());
      CommentHelper.setComment(newFunctionNode, [CommentHelper.getEmptyLineComment(), ...comments]);
      newFunctionNodes.push(newFunctionNode);
    });
    return newFunctionNodes;
  }

  /**
   * 创建新的MethodSignature类型节点数组
   * @param node 当前节点
   * @param eventValues 事件名称数组
   * @returns 新创建的节点数组
   */
  static createMethodSigNodes(node: ts.MethodSignature, eventValues: Array<string>): Array<ts.MethodSignature> {
    const newFunctionNodes: Array<ts.MethodSignature> = [];
    const typeParam: ts.ParameterDeclaration = node.parameters[0];
    eventValues.forEach((eventValue: string) => {
      const newParams: Array<ts.ParameterDeclaration> = ApiSplitProcessorHelper.createNewParams(node, eventValue, typeParam);
      ts.setEmitFlags(node.name, ts.EmitFlags.NoLeadingComments);
      const newFunctionNode: ts.MethodSignature = ts.factory.createMethodSignature(node.modifiers, node.name,
        node.questionToken, node.typeParameters, newParams, node.type);
      const comments: Array<comment.CommentInfo> = CommentHelper.getNodeLeadingComments(node, node.getSourceFile());
      CommentHelper.setComment(newFunctionNode, [CommentHelper.getEmptyLineComment(), ...comments]);
      newFunctionNodes.push(newFunctionNode);
    });

    return newFunctionNodes;
  }

  static processSourceFile(node: ts.Node, context: Context | undefined): ts.Node | undefined {
    const sourceFile: ts.SourceFile = node as ts.SourceFile;
    const newStatements: Array<ts.Statement> = [];
    const statements: ts.NodeArray<ts.Statement> = sourceFile.statements;
    statements.forEach((statement: ts.Statement) => {
      const eventValues: Array<string> = ApiSplitProcessorHelper.splitEventValues(statement);
      if (eventValues.length === 0) {
        newStatements.push(statement);
      } else {
        const funcDecNode: ts.FunctionDeclaration = statement as ts.FunctionDeclaration;
        const newFunctionNodes: Array<ts.FunctionDeclaration> = ApiSplitProcessorHelper.createFunctionDecNodes(funcDecNode, eventValues);
        newStatements.push(...newFunctionNodes);
        // 添加报告输出处理逻辑
        ApiSplitProcessorHelper.logReportProcess(funcDecNode, context);
      }
    });
    if (statements.length === newStatements.length) {
      return undefined;
    }
    return ts.factory.updateSourceFile(sourceFile, newStatements, sourceFile.isDeclarationFile,
      sourceFile.referencedFiles, sourceFile.typeReferenceDirectives, sourceFile.hasNoDefaultLib,
      sourceFile.libReferenceDirectives);
  }

  static processModuleDeclaration(node: ts.Node, context: Context | undefined): ts.Node | undefined {
    const moduleDeclaration: ts.ModuleDeclaration = node as ts.ModuleDeclaration;
    if (moduleDeclaration.body && moduleDeclaration.body.kind === ts.SyntaxKind.ModuleBlock) {
      const statements: ts.NodeArray<ts.Statement> = moduleDeclaration.body.statements;
      const newStatements: Array<ts.Statement> = [];
      statements.forEach((statement: ts.Statement) => {
        const eventValues: Array<string> = ApiSplitProcessorHelper.splitEventValues(statement);
        if (eventValues.length === 0) {
          newStatements.push(statement);
        } else {
          const funcDecNode: ts.FunctionDeclaration = statement as ts.FunctionDeclaration;
          const newFunctionNodes: Array<ts.FunctionDeclaration> = ApiSplitProcessorHelper.createFunctionDecNodes(funcDecNode, eventValues);
          newStatements.push(...newFunctionNodes);
          // 添加报告输出处理逻辑
          ApiSplitProcessorHelper.logReportProcess(funcDecNode, context);
        }
      });
      if (statements.length === newStatements.length) {
        return undefined;
      }
      const newModuleBlock: ts.ModuleBlock = ts.factory.updateModuleBlock(moduleDeclaration.body, newStatements);
      return ts.factory.updateModuleDeclaration(moduleDeclaration, moduleDeclaration.modifiers,
        moduleDeclaration.name, newModuleBlock);
    }
    return undefined;
  }

  static processClassDeclaration(node: ts.Node, context: Context | undefined): ts.Node | undefined {
    const classDeclaration: ts.ClassDeclaration = node as ts.ClassDeclaration;
    const members: ts.NodeArray<ts.ClassElement> = classDeclaration.members;
    const newMembers: Array<ts.ClassElement> = [];
    members.forEach((member: ts.ClassElement) => {
      const eventValues: Array<string> = ApiSplitProcessorHelper.splitEventValues(member);
      if (eventValues.length === 0) {
        newMembers.push(member);
      } else {
        const funcDecNode: ts.MethodDeclaration = member as ts.MethodDeclaration;
        const newFunctionNodes: Array<ts.MethodDeclaration> = ApiSplitProcessorHelper.createMethodDecNodes(funcDecNode, eventValues);
        newMembers.push(...newFunctionNodes);
        // 添加报告输出处理逻辑
        ApiSplitProcessorHelper.logReportProcess(funcDecNode, context);
      }
    });
    if (members.length === newMembers.length) {
      return undefined;
    }
    return ts.factory.updateClassDeclaration(classDeclaration, classDeclaration.modifiers, classDeclaration.name,
      classDeclaration.typeParameters, classDeclaration.heritageClauses, newMembers);
  }

  static processInterfaceDeclaration(node: ts.Node, context: Context | undefined): ts.Node | undefined {
    const interfaceDeclaration: ts.InterfaceDeclaration = node as ts.InterfaceDeclaration;
    const members: ts.NodeArray<ts.TypeElement> = interfaceDeclaration.members;
    const newMembers: Array<ts.TypeElement> = [];
    members.forEach((member: ts.TypeElement) => {
      const eventValues: Array<string> = ApiSplitProcessorHelper.splitEventValues(member);
      if (eventValues.length === 0) {
        newMembers.push(member);
      } else {
        const funcDecNode: ts.MethodSignature = member as ts.MethodSignature;
        const newFunctionNodes: Array<ts.MethodSignature> = ApiSplitProcessorHelper.createMethodSigNodes(funcDecNode, eventValues);
        newMembers.push(...newFunctionNodes);
        // 添加报告输出处理逻辑
        ApiSplitProcessorHelper.logReportProcess(funcDecNode, context);
      }
    });
    if (members.length === newMembers.length) {
      return undefined;
    }
    return ts.factory.updateInterfaceDeclaration(interfaceDeclaration, interfaceDeclaration.modifiers, interfaceDeclaration.name,
      interfaceDeclaration.typeParameters, interfaceDeclaration.heritageClauses, newMembers);
  }
}

const nodeProcessorMap: Map<ts.SyntaxKind, ApiSplitProcessorInterface> = new Map([
  [ts.SyntaxKind.SourceFile, ApiSplitProcessorHelper.processSourceFile],
  [ts.SyntaxKind.ModuleDeclaration, ApiSplitProcessorHelper.processModuleDeclaration],
  [ts.SyntaxKind.InterfaceDeclaration, ApiSplitProcessorHelper.processInterfaceDeclaration],
  [ts.SyntaxKind.ClassDeclaration, ApiSplitProcessorHelper.processClassDeclaration]
]);