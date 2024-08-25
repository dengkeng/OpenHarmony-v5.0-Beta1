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
  Context, ISourceCodeProcessor, JsDocCheckResult, JsDocModificationInterface, ProcessResult,
  LogReporter, IllegalTagsInfo, rawInfo, CheckLogResult, ModifyLogResult, comment
} from './typedef';
import { JSDocModifyType, ErrorInfo, JSDocCheckErrorType } from './typedef';
import { CommentHelper, LogResult } from './coreImpls';
const apiChecker = require('api-checker');

/**
 *  JSDoc整改入口
 */
export class CommentModificationProcessor implements ISourceCodeProcessor {

  logReporter?: LogReporter;
  context?: Context;
  rawSourceCodeInfo?: rawInfo.RawSourceCodeInfo;

  async process(context: Context, content: string): Promise<ProcessResult> {
    this.context = context;
    const newParser = context.getSourceParser(content);
    this.logReporter = context.getLogReporter();
    this.rawSourceCodeInfo = context.getRawSourceCodeInfo();
    await apiChecker.initEnv(context.getOptions().workingBranch);
    const newSourceFile = newParser.visitEachNodeComment(this, false);
    return {
      code: Code.OK,
      content: newSourceFile ? newParser.printSourceFile(newSourceFile) : content
    };
  }

  onVisitNode(node: comment.CommentNode): void {
    if (node.astNode) {
      const curNode: ts.Node = node.astNode;
      // 获取诊断信息
      const checkResults = apiChecker.checkJSDoc(node.astNode, node.astNode?.getSourceFile(), this.context?.getInputFile());
      const newCommentIndexs: number[] = [];
      const newCommentInfos: comment.CommentInfo[] = node.commentInfos ? [...node.commentInfos] : [];
      // 获取需要整改的JSDoc数组
      newCommentInfos?.forEach((commentInfo: comment.CommentInfo, index: number) => {
        if (commentInfo.isApiComment) {
          newCommentIndexs.push(index);
          // 添加继承接口
          this.addInheritTags(node, curNode, commentInfo, newCommentInfos, index === newCommentInfos.length - 1,
            index + 1);
        }
      });
      if (newCommentIndexs.length > 0 && node.commentInfos) {
        // JSDoc校验&整改
        if (newCommentIndexs.length === checkResults.length) {
          newCommentIndexs.forEach((item: number, index: number) => {
            // 匹配处理校验结果与JSDoc数组
            const checkResult: JsDocCheckResult = checkResults[index];
            const curCommentInfo: comment.CommentInfo = newCommentInfos[item];
            // 添加缺失标签
            this.addMissingTags(node, curNode, curCommentInfo, newCommentInfos, checkResult.missingTags, index + 1);
            // 输出诊断日志
            this.exportIllegalInfo(curNode, newCommentInfos, checkResult.illegalTags, index + 1);
            // 调整标签顺序
            this.modifyTagsOrder(curNode, curCommentInfo, newCommentInfos, checkResult.orderResult.checkResult,
              index + 1);
          });
        } else {
          // 捕获异常
          const apiName: string = JSDocModificationManager.getApiName(curNode);
          const checkLogResult: CheckLogResult = LogResult.createCheckResult(curNode, newCommentInfos,
            JSDocModificationManager.createErrorInfo(ErrorInfo.JSDOC_FORMAT_ERROR, []), this.context, apiName,
            JSDocCheckErrorType.API_FORMAT_ERROR);
          this.logReporter?.addCheckResult(checkLogResult);
        }
      }
      CommentHelper.setComment(node.astNode, newCommentInfos);
    }
  }
  addInheritTags(node: comment.CommentNode, curNode: ts.Node, commentInfo: comment.CommentInfo,
    newCommentInfos: comment.CommentInfo[], deprecatedCheckResult: boolean, jsdocNumber: number): void {
    const apiName: string = JSDocModificationManager.getApiName(curNode);
    INHERIT_TAGS_ARRAY.forEach((tagName: string) => {
      if (tagName !== 'deprecated' || (tagName === 'deprecated' && deprecatedCheckResult)) {
        const modifyResult: boolean = JSDocModificationManager.addTagFrommParentNode(node, commentInfo, tagName,
          this.context);
        if (modifyResult) {
          if (tagName === 'permission') {
            const checkLogResult: CheckLogResult = LogResult.createCheckResult(curNode, newCommentInfos,
              JSDocModificationManager.createErrorInfo(ErrorInfo.COMPLETE_INHERIT_PERMISSION_TAG_ERROR, [`${jsdocNumber}`, `${tagName}`]),
              this.context, apiName, JSDocCheckErrorType.INCOMPLETE_TAG);
            this.logReporter?.addCheckResult(checkLogResult);
          } else {
            const modifyLogResult: ModifyLogResult = LogResult.createModifyResult(curNode, newCommentInfos,
              JSDocModificationManager.createErrorInfo(ErrorInfo.COMPLETE_INHERIT_TAG_INFORMATION, [`${jsdocNumber}`, `${tagName}`]),
              this.context, apiName, JSDocModifyType.MISSING_TAG_COMPLETION);
            this.logReporter?.addModifyResult(modifyLogResult);
          }
        }
      }
    });
  }
  addMissingTags(node: comment.CommentNode, curNode: ts.Node, curCommentInfo: comment.CommentInfo,
    newCommentInfos: comment.CommentInfo[], missingTags: string[], jsdocNumber: number): void {
    const apiName: string = JSDocModificationManager.getApiName(curNode);
    missingTags.forEach((tagName: string) => {
      const modifier = jsDocModifier.get(tagName);
      let modifyResult: boolean = false;
      if (modifier) {
        modifyResult = modifier(node, curCommentInfo, tagName, this.context);
        if (modifyResult) {
          const modifyLogResult: ModifyLogResult = LogResult.createModifyResult(curNode, newCommentInfos,
            JSDocModificationManager.createErrorInfo(ErrorInfo.COMPLETE_TAG_INFORMATION, [`${jsdocNumber}`, `${tagName}`]),
            this.context, apiName, JSDocModifyType.MISSING_TAG_COMPLETION);
          this.logReporter?.addModifyResult(modifyLogResult);
        }
      }
      if (!modifier || !modifyResult) {
        let modifyErrorInfo: string = ErrorInfo.COMPLETE_TAG_ERROR;
        let insteadInfo: string[] = [`${jsdocNumber}`, `${tagName}`];
        if (tagName === 'interface') {
          modifyErrorInfo = ErrorInfo.COMPLETE_INTERFACE_TAG_ERROR;
          insteadInfo = [`${jsdocNumber}`];
        }
        const checkLogResult: CheckLogResult = LogResult.createCheckResult(curNode, newCommentInfos,
          JSDocModificationManager.createErrorInfo(modifyErrorInfo, insteadInfo),
          this.context, apiName, JSDocCheckErrorType.INCOMPLETE_TAG);
        this.logReporter?.addCheckResult(checkLogResult);
      }
    });
  }
  modifyTagsOrder(curNode: ts.Node, curCommentInfo: comment.CommentInfo, newCommentInfos: comment.CommentInfo[],
    orderResult: boolean, jsdocNumber: number): void {
    const apiName: string = JSDocModificationManager.getApiName(curNode);
    curCommentInfo.commentTags = JSDocModificationManager.modifyJsDocTagsOrder(curCommentInfo.commentTags);
    if (!orderResult) {
      const modifyLogResult: ModifyLogResult = LogResult.createModifyResult(curNode, newCommentInfos,
        JSDocModificationManager.createErrorInfo(ErrorInfo.MODIFY_TAG_ORDER_INFORMATION, [`${jsdocNumber}`]),
        this.context, apiName, JSDocModifyType.TAG_ORDER_AJUSTMENT);
      this.logReporter?.addModifyResult(modifyLogResult);
    }
  }
  exportIllegalInfo(curNode: ts.Node, newCommentInfos: comment.CommentInfo[],
    illegalTags: IllegalTagsInfo[], jsdocNumber: number): void {
    const apiName: string = JSDocModificationManager.getApiName(curNode);
    illegalTags.forEach((illegalTag: IllegalTagsInfo) => {
      if (!illegalTag.checkResult) {
        const checkLogResult: CheckLogResult = LogResult.createCheckResult(curNode, newCommentInfos,
          JSDocModificationManager.createErrorInfo(ErrorInfo.JSDOC_ILLEGAL_ERROR + illegalTag.errorInfo, [`${jsdocNumber}`]),
          this.context, apiName, JSDocCheckErrorType.TAG_VALUE_ERROR);
        this.logReporter?.addCheckResult(checkLogResult);
      }
    });
  }
}

/**
 * JSDoc整改工具类
 */
class JSDocModificationManager {

  /**
   * 获取commentInfo初始值
   */
  static getNewCommentInfoObj(commentInfo: comment.CommentInfo): comment.CommentTag {
    return {
      tag: '',
      name: '',
      type: '',
      optional: false,
      description: '',
      source: '',
      lineNumber: commentInfo.commentTags.length > 0 ?
        commentInfo.commentTags[commentInfo.commentTags.length - 1].lineNumber + 1 : 0,
      tokenSource: []
    };
  }

  /**
   * 添加无值标签
   */
  static addTagWithoutValue(node: comment.CommentNode, commentInfo: comment.CommentInfo, tagName: string,
    context: Context | undefined): boolean {
    const newCommentTag: comment.CommentTag = JSDocModificationManager.getNewCommentInfoObj(commentInfo);
    newCommentTag.tag = tagName;
    commentInfo.commentTags.push(newCommentTag);
    return true;
  }

  /**
   * 添加有值标签
   */
  static addTagWithValue(node: comment.CommentNode, commentInfo: comment.CommentInfo, tagName: string,
    context: Context | undefined): boolean {
    const newCommentTag: comment.CommentTag = JSDocModificationManager.getNewCommentInfoObj(commentInfo);
    newCommentTag.tag = tagName;
    let tagValue = '';
    let tagType = '';
    if (node.astNode) {
      if (tagName === 'returns' && (ts.isMethodDeclaration(node.astNode) || ts.isMethodSignature(node.astNode) ||
        ts.isFunctionDeclaration(node.astNode) || ts.isCallSignatureDeclaration(node.astNode)) &&
        node.astNode.type) {
        if (ts.isTypeLiteralNode(node.astNode.type)) {
          tagType = 'object';
        } else if (ts.isFunctionTypeNode(node.astNode.type)) {
          tagType = 'function';
        } else {
          tagType = node.astNode.type.getText();
        }
      } else if ((ts.isModuleDeclaration(node.astNode) || ts.isEnumDeclaration(node.astNode)) && node.astNode.name &&
        ts.isIdentifier(node.astNode.name)) {
        tagValue = node.astNode.name.escapedText.toString();
      } else if (ts.isClassDeclaration(node.astNode) && node.astNode.heritageClauses) {
        const clauses = node.astNode.heritageClauses;
        const extendClasses: string[] = [];
        clauses.forEach((clause: ts.HeritageClause) => {
          if (/^extends /.test(clause.getText()) && clause.types) {
            clause.types.forEach((type: ts.ExpressionWithTypeArguments) => {
              extendClasses.push(type.getText());
            });
          }
        });
        tagValue = extendClasses.join(', ');
      }
    }
    newCommentTag.name = tagValue;
    newCommentTag.type = tagType;
    commentInfo.commentTags.push(newCommentTag);
    return true;
  }

  /**
   * 添加继承标签
   */
  static addTagFrommParentNode(node: comment.CommentNode, commentInfo: comment.CommentInfo, tagName: string,
    context: Context | undefined): boolean {
    let checkResult: boolean = false;
    commentInfo.commentTags.forEach((tag: comment.CommentTag) => {
      if (tag.tag === tagName) {
        checkResult = true;
      }
    });
    if (checkResult) {
      return false;
    }
    if (node.parentNode) {
      const pTag: comment.CommentTag | undefined = getParentTag(node.parentNode, tagName);
      if (pTag) {
        if (tagName !== 'permission') {
          commentInfo.commentTags.push(pTag);
        }
        return true;
      }
    }
    return false;
    function getParentTag(pNode: comment.CommentNode, tagName: string): comment.CommentTag | undefined {
      if (pNode.commentInfos && pNode.commentInfos[pNode.commentInfos.length - 1] &&
        pNode.commentInfos[pNode.commentInfos.length - 1].commentTags) {
        const pTags: comment.CommentTag[] = pNode.commentInfos[pNode.commentInfos.length - 1].commentTags;
        for (let i = 0; i < pTags.length; i++) {
          if (pTags[i].tag === tagName) {
            return pTags[i];
          }
        }
      }
      if (pNode.parentNode) {
        return getParentTag(pNode.parentNode, tagName);
      }

      return undefined;
    }
  }

  /**
   * 添加param标签
   */
  static addParamTag(node: comment.CommentNode, commentInfo: comment.CommentInfo, tagName: string,
    context: Context | undefined): boolean {
    if (node.astNode && (ts.isMethodDeclaration(node.astNode) || ts.isMethodSignature(node.astNode) ||
      ts.isFunctionDeclaration(node.astNode) || ts.isCallSignatureDeclaration(node.astNode) ||
      ts.isConstructorDeclaration(node.astNode))) {
      let paramTagNum: number = 0;
      commentInfo.commentTags.forEach((tag: comment.CommentTag) => {
        if (tag.tag === 'param') {
          paramTagNum++;
        }
      });
      const parameters = node.astNode.parameters;
      for (let i = 0; i < parameters.length; i++) {
        const newCommentTag: comment.CommentTag = JSDocModificationManager.getNewCommentInfoObj(commentInfo);
        const curIndex: number = paramTagNum + i;
        newCommentTag.tag = tagName;
        const curParameter: ts.ParameterDeclaration = parameters[curIndex];
        if (curParameter) {
          const apiName: string = node.astNode.name ? node.astNode.name.getText() : '';
          const commentInfos: comment.CommentInfo[] = node.commentInfos ? node.commentInfos : [];
          let paramType: string = '';
          if (curParameter.type) {
            if (ts.isTypeLiteralNode(curParameter.type)) {
              paramType = 'object';
            } else if (ts.isFunctionTypeNode(curParameter.type)) {
              paramType = 'function';
            } else {
              paramType = curParameter.type.getText();
            }
          }
          newCommentTag.type = paramType;
          newCommentTag.name = curParameter.name ? curParameter.name.getText() : '';
          commentInfo.commentTags.push(newCommentTag);
          // 提示description缺失信息
          const checkLogResult: CheckLogResult = LogResult.createCheckResult(node.astNode, commentInfos,
            JSDocModificationManager.createErrorInfo(ErrorInfo.PARAM_FORAMT_DESCRIPTION_ERROR, [`${curIndex + 1}`]), context, apiName,
            JSDocCheckErrorType.PARAM_DESCRIPTION_WARNING);
          context?.getLogReporter().addCheckResult(checkLogResult);
        }
      }
    }
    return true;
  }

  /**
   * 调整标签顺序
   */
  static modifyJsDocTagsOrder(commentTags: comment.CommentTag[]): comment.CommentTag[] {
    const orderSet = new Set(JSDOC_ORDER_TAGS_ARRAY);
    const newTags: comment.CommentTag[] = [];
    JSDOC_ORDER_TAGS_ARRAY.forEach((tagName: string) => {
      commentTags.forEach((curTag: comment.CommentTag) => {
        if (tagName === curTag.tag) {
          newTags.push(curTag);
        }
      });
    });
    commentTags.forEach((tag: comment.CommentTag) => {
      if (!orderSet.has(tag.tag)) {
        newTags.push(tag);
      }
    });
    return newTags;
  }

  /**
   * 组装错误信息
   */
  static createErrorInfo(errorInfo: string, params: string[]): string {
    params.forEach((param: string) => {
      errorInfo = errorInfo.replace('$$', param);
    });
    return errorInfo;
  }

  /**
   * 获取apiName
   */
  static getApiName(node: ts.Node): string {
    let apiName: string = '';
    if ((ts.isVariableDeclaration(node) || ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) ||
      ts.isInterfaceDeclaration(node) || ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node) ||
      ts.isNamespaceExportDeclaration(node) || ts.isPropertySignature(node) || ts.isEnumMember(node) ||
      ts.isMethodSignature(node) || ts.isMethodDeclaration(node) || ts.isPropertyDeclaration(node) ||
      ts.isCallSignatureDeclaration(node) || ts.isTypeAliasDeclaration(node)) && node.name) {
      apiName = node.name.getText();
    } else if (ts.isConstructorDeclaration(node)) {
      apiName = 'constructor';
    } else if (ts.isVariableStatement(node)) {
      apiName = node.declarationList.declarations[0].name.getText();
    } else if (ts.isVariableDeclarationList(node)) {
      apiName = node.declarations[0].name.getText();
    }
    return apiName;
  }
}

const jsDocModifier: Map<string, JsDocModificationInterface> = new Map([
  ['constant', JSDocModificationManager.addTagWithoutValue],
  ['deprecated', JSDocModificationManager.addTagFrommParentNode],
  ['extends', JSDocModificationManager.addTagWithValue],
  ['famodelonly', JSDocModificationManager.addTagFrommParentNode],
  ['namespace', JSDocModificationManager.addTagWithValue],
  ['param', JSDocModificationManager.addParamTag],
  ['returns', JSDocModificationManager.addTagWithValue],
  ['stagemodelonly', JSDocModificationManager.addTagFrommParentNode],
  ['syscap', JSDocModificationManager.addTagFrommParentNode],
  ['systemapi', JSDocModificationManager.addTagFrommParentNode],
  ['test', JSDocModificationManager.addTagFrommParentNode],
]);

/**
 * 标签顺序白名单
 */
const JSDOC_ORDER_TAGS_ARRAY = [
  'namespace', 'extends', 'typedef', 'interface', 'permission', 'enum', 'constant', 'type', 'param', 'default',
  'returns', 'readonly', 'throws', 'static', 'fires', 'syscap', 'systemapi', 'famodelonly', 'FAModelOnly',
  'stagemodelonly', 'StageModelOnly', 'crossplatform', 'since', 'deprecated', 'useinstead', 'test', 'form', 'example'
];

/**
 * 继承标签白名单
 */
const INHERIT_TAGS_ARRAY = ['deprecated', 'famodelonly', 'stagemodelonly', 'systemapi', 'test', 'permission'];
