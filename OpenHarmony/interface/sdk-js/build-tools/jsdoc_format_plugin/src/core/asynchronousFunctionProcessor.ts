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
import { LogReportStringUtils } from '../utils/stringUtils';
import { CommentHelper, LogResult } from './coreImpls';
import type {
  Context, ISourceCodeProcessor, MethodNodeType,
  ModifyLogResult, ProcessResult, comment
} from './typedef';
import { JSDocModifyType, ErrorInfo } from './typedef';

export class AsynchronousFunctionProcessor implements ISourceCodeProcessor {

  context?: Context;

  async process(context: Context, content: string): Promise<ProcessResult> {
    const sourceParser = context.getSourceParser(content);
    this.context = context;
    const sourceFile: ts.SourceFile | undefined = sourceParser.createSourceFile(content);
    if (!sourceFile) {
      return { code: Code.OK, content: content };
    }
    const preNode: PreNode = new PreNode('', []);
    ts.forEachChild(sourceFile, (cNode) => {
      this.nodeVisitor(cNode, preNode);
    });
    return {
      code: Code.OK,
      content: sourceParser.printSourceFile(sourceFile)
    };
  }

  logReportProcess(node: MethodNodeType, comments: Array<comment.CommentInfo>): void {
    const apiName: string = node.name ? node.name.getText() : '';
    const description: string = LogReportStringUtils.createErrorInfo(ErrorInfo.AYYNCHRONOUS_FUNCTION_JSDOC_COPY, [`${apiName}`]);
    const modifyLogResult: ModifyLogResult = LogResult.createModifyResult(node, comments, description, this.context,
      apiName, JSDocModifyType.AYYNCHRONOUS_FUNCTION_JSDOC_COPY);
    this.context?.getLogReporter().addModifyResult(modifyLogResult);
  }

  nodeVisitor(cNode: ts.Node, preNode: PreNode): void {
    if (ts.isModuleDeclaration(cNode) && cNode.body && ts.isModuleBlock(cNode.body)) {
      const preNode: PreNode = new PreNode('', []);
      ts.forEachChild(cNode.body, (child) => {
        this.nodeVisitor(child, preNode);
      });
      return;
    }

    if (ts.isSourceFile(cNode) || ts.isClassDeclaration(cNode) || ts.isInterfaceDeclaration(cNode)) {
      const preNode: PreNode = new PreNode('', []);
      ts.forEachChild(cNode, (child) => {
        this.nodeVisitor(child, preNode);
      });
      return;
    }

    if ((ts.isFunctionDeclaration(cNode) || ts.isMethodDeclaration(cNode) || ts.isMethodSignature(cNode)) &&
      this.isAsynchronousFunction(cNode)) {
      const nodeComments: Array<comment.CommentInfo> = CommentHelper.getNodeLeadingComments(cNode, cNode.getSourceFile());
      let functionName: string = '';
      if (cNode.name && ts.isIdentifier(cNode.name)) {
        functionName = cNode.name.escapedText.toString();
      }
      if (nodeComments.length !== 0) {
        if (functionName !== '') {
          preNode.name = functionName;
          preNode.doc = nodeComments;
        } else {
          preNode.name = '';
          preNode.doc = [];
        }
      } else {
        if (preNode.name === '') {
          return;
        }
        if (preNode.name === functionName) {
          // 添加报告输出处理
          this.logReportProcess(cNode, preNode.doc);
          CommentHelper.setComment(cNode, [CommentHelper.getEmptyLineComment(), ...preNode.doc]);
          return;
        }
        preNode.name = '';
        preNode.doc = [];
      }

    } else {
      preNode.name = '';
      preNode.doc = [];
    }
  }

  isAsynchronousFunction(node: MethodNodeType): boolean {
    if (node.type && (node.type.kind === ts.SyntaxKind.TypeReference) &&
      (node.type as ts.TypeReferenceNode).typeName.getText() === 'Promise') {
      return true;
    }
    if (node.parameters.length !== 0) {
      for (let i = node.parameters.length - 1; i >= 0; i--) {
        const param: ts.ParameterDeclaration = node.parameters[i];
        if (param.type && (param.type.kind === ts.SyntaxKind.TypeReference) &&
          (param.type as ts.TypeReferenceNode).typeName.getText() === 'AsyncCallback') {
          return true;
        }
      }
    }
    return false;
  }
}

class PreNode {
  name: string;
  doc: Array<comment.CommentInfo>;
  constructor(name: string, doc: Array<comment.CommentInfo>) {
    this.name = name;
    this.doc = doc;
  }
}