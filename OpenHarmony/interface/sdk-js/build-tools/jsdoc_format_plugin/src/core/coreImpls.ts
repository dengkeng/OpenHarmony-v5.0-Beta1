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

import path from 'path';
import excelJs from 'exceljs';
import fs from 'fs';
import { Command } from 'commander';
import { ConstantValue, Instruct, StringResourceId } from '../utils/constant';
import { FileUtils } from '../utils/fileUtils';
import { LogUtil } from '../utils/logUtil';
import { StringResource, StringUtils } from '../utils/stringUtils';
import type {
  Context, LogReporter, CheckLogResult, ModifyLogResult, LogWriter, JSDocModifyType,
  JSDocCheckErrorType, CommentData
} from './typedef';
import { comment, Options, sourceParser, rawInfo } from './typedef';
import ts from 'typescript';
import type { CommentRange, TransformationContext, TransformationResult } from 'typescript';

export class ContextImpl implements Context {
  options: Options;
  inputFile: string;
  outputFile: string;
  rawSourceCodeInfo?: rawInfo.RawSourceCodeInfo;
  logReporter?: LogReporter;

  constructor(inputFile: string, outputFile: string, options?: Options) {
    this.inputFile = inputFile;
    this.outputFile = outputFile;
    this.options = options ? options : new Options();
  }

  setLogReporter(logReporter: LogReporter): void {
    this.logReporter = logReporter;
  }

  getOptions(): Options {
    return this.options;
  }

  setRawSourceInfo(rawInfo: rawInfo.RawSourceCodeInfo): void {
    this.rawSourceCodeInfo = rawInfo;
  }

  getRawSourceCodeInfo(): rawInfo.RawSourceCodeInfo {
    return this.rawSourceCodeInfo || new RawSourceCodeInfoImpl('');
  }

  getLogReporter(): LogReporter {
    if (this.logReporter === undefined) {
      this.logReporter = new LogReporterImpl();
      let writer: LogWriter;
      if (this.getOptions().isTest) {
        writer = new logWriter.JsonWriter();
      } else {
        writer = new logWriter.ExcelWriter(this.logReporter);
      }
      this.logReporter.setWriter(writer);
    }
    return this.logReporter;
  }

  getOutputFile(): string {
    return this.outputFile;
  }

  getInputFile(): string {
    return this.inputFile;
  }

  getSourceParser(code: string): sourceParser.SourceCodeParser {
    return new SourceCodeParserImpl(code, this.options);
  }
}


export class OutputFileHelper {

  static getOutputFilePath(inputParam: InputParameter, sourceFile: string): string {
    return inputParam.isHandleMultiFiles() ? OutputFileHelper.getMultiOutputFilePath(inputParam, sourceFile) :
      OutputFileHelper.getSingleOutputFilePath(inputParam);
  }

  static getMultiOutputFilePath(inputParam: InputParameter, sourceFile: string): string {
    // 计算原文件与输入目录的相对路径
    const relativePath = path.relative(inputParam.inputFilePath!, sourceFile);
    // 如果未设置 outputPath, 同级目录创建新目录
    return path.resolve(this.getMultiOutputDir(inputParam), relativePath);
  }

  static getMultiOutputDir(inputParam: InputParameter): string {
    if (inputParam.outputFilePath) {
      return inputParam.outputFilePath;
    }
    const fileName = path.basename(inputParam.inputFilePath!);
    const dirname = path.dirname(inputParam.inputFilePath!);
    return path.resolve(dirname, `${fileName}_new`);
  }

  static getSingleOutputFilePath(inputParam: InputParameter): string {
    if (inputParam.outputFilePath) {
      return inputParam.outputFilePath;
    }
    // 同级目录创建新文件
    const fileName = path.basename(inputParam.inputFilePath!, ConstantValue.DTS_EXTENSION);
    return path.join(inputParam.inputFilePath!, '..', `${fileName}_new${ConstantValue.DTS_EXTENSION}`);
  }

  // 获取报告输出路径
  static getLogReportFilePath(inputParam: InputParameter): string {
    const fileName = path.basename(inputParam.inputFilePath, '.d.ts');
    if (inputParam.outputFilePath) {
      const dirName = path.dirname(inputParam.outputFilePath);
      return path.join(dirName, `${fileName}`);
    } else {
      const dirName = path.dirname(inputParam.inputFilePath);
      return path.join(dirName, `${fileName}`);
    }
  }
}

function getCommentNode(node: ts.Node, parentNode: comment.CommentNode | undefined, sourceFile: ts.SourceFile): comment.CommentNode {
  const leadingComments: comment.CommentInfo[] = CommentHelper.getNodeLeadingComments(node, sourceFile);
  const currentCommentNode: comment.CommentNode = {
    astNode: node,
    parentNode: parentNode,
    commentInfos: []
  };
  currentCommentNode.commentInfos?.push(...leadingComments);
  return currentCommentNode;
}

export class SourceCodeParserImpl extends sourceParser.SourceCodeParser {
  options: Options;

  /**
   * 可能存在注释的节点类型。
   */
  commentNodeWhiteList: ts.SyntaxKind[] = [
    ts.SyntaxKind.VariableDeclaration, ts.SyntaxKind.VariableDeclarationList, ts.SyntaxKind.FunctionDeclaration,
    ts.SyntaxKind.ClassDeclaration, ts.SyntaxKind.InterfaceDeclaration, ts.SyntaxKind.TypeAliasDeclaration,
    ts.SyntaxKind.EnumDeclaration, ts.SyntaxKind.ModuleDeclaration, ts.SyntaxKind.NamespaceExportDeclaration,
    ts.SyntaxKind.PropertySignature, ts.SyntaxKind.CallSignature, ts.SyntaxKind.MethodSignature, ts.SyntaxKind.MethodDeclaration,
    ts.SyntaxKind.EnumMember, ts.SyntaxKind.VariableStatement, ts.SyntaxKind.PropertyDeclaration, ts.SyntaxKind.Constructor,
    ts.SyntaxKind.TypeLiteral, ts.SyntaxKind.ImportDeclaration, ts.SyntaxKind.LabeledStatement
  ];
  visitNodeChildrenWhilteList: ts.SyntaxKind[] = [
    ts.SyntaxKind.ModuleDeclaration, ts.SyntaxKind.ModuleBlock, ts.SyntaxKind.NamespaceExportDeclaration, ts.SyntaxKind.ClassDeclaration,
    ts.SyntaxKind.InterfaceDeclaration, ts.SyntaxKind.EnumDeclaration, ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.Parameter,
    ts.SyntaxKind.TypeLiteral, ts.SyntaxKind.PropertySignature, ts.SyntaxKind.TypeAliasDeclaration
  ];

  constructor(code: string, options: Options) {
    super(code);
    this.options = options;
  }

  private shouldNotify(node: ts.Node): boolean {
    // if kind = ImportDeclaration, comments may be license declarations
    return this.commentNodeWhiteList.includes(node.kind);
  }

  private shouldForEachChildren(node: ts.Node): boolean {
    return true;
  }

  createSourceFile(content: string, name?: string | undefined): ts.SourceFile | undefined {
    const sourceFile = ts.createSourceFile(name ? name : 'memory', content, this.options.scriptTarget, true);
    // 没有解析成AST树，非代码文件
    if (sourceFile.statements.length === 0) {
      return undefined;
    }
    return sourceFile;
  }

  transform(callback: sourceParser.ITransformCallback): ts.SourceFile | undefined {
    let transformSourceFile = this.createSourceFile(this.content, 'transform');
    if (!transformSourceFile) {
      return undefined;
    }
    function transformCallback(context: TransformationContext) {
      return (rootNode: ts.Node) => {
        function visitor(node: ts.Node): ts.Node {
          const commentNode = getCommentNode(node, undefined, transformSourceFile!);
          const newNode: ts.Node | undefined = callback.onTransformNode(commentNode);
          return ts.visitEachChild(newNode ? newNode : node, visitor, context);
        }
        return ts.visitEachChild(rootNode, visitor, context);
      };
    };
    const rootNode = callback.onTransformNode({ astNode: transformSourceFile });
    if (rootNode && ts.isSourceFile(rootNode) && rootNode !== transformSourceFile) {
      transformSourceFile = rootNode;
    }
    const transformResult: TransformationResult<ts.Node> = ts.transform(transformSourceFile, [transformCallback]);
    if (transformResult.transformed.length > 0) {
      return transformResult.transformed[0] as ts.SourceFile;
    }
    return transformSourceFile;
  }

  visitEachNodeComment(callback: sourceParser.INodeVisitorCallback, onlyVisitHasComment?: boolean): ts.SourceFile | undefined {
    const forEachSourceFile = this.createSourceFile(this.content, 'forEach');
    if (!forEachSourceFile) {
      return undefined;
    }
    const thiz = this;
    const handledComments: Set<string> = new Set();
    function nodeVisitor(node: ts.Node, parentNode: comment.CommentNode | undefined, sourceFile: ts.SourceFile): void {
      const currentCommentNode = getCommentNode(node, parentNode, sourceFile);
      const NOTE_LENGTH = 0;
      thiz.skipHandledComments(handledComments, currentCommentNode);
      const hasComment: boolean = currentCommentNode.commentInfos ?
        currentCommentNode.commentInfos.length > NOTE_LENGTH : false;
      const { line, character } = node.getSourceFile().getLineAndCharacterOfPosition(node.getStart());
      if (thiz.shouldNotifyCallback(node, hasComment, onlyVisitHasComment)) {
        LogUtil.d('SourceCodeParserImpl', `kind: ${node.kind}, line: ${line + 1}, ${JSON.stringify(currentCommentNode.commentInfos)}`);
        callback.onVisitNode(currentCommentNode);
      } else {
        LogUtil.d('SourceCodeParserImpl',
          `skip, [ ${node.getText()} ] kind: ${node.kind}, line: ${line + 1}, character: ${character}, comment size: ${currentCommentNode.commentInfos?.length}`);
      }
      if (thiz.shouldForEachChildren(node)) {
        node.forEachChild((child) => {
          nodeVisitor(child, currentCommentNode, sourceFile);
        });
      }
    }
    forEachSourceFile.forEachChild((child) => {
      nodeVisitor(child, undefined, forEachSourceFile);
    });
    return forEachSourceFile;
  }

  private skipHandledComments(handledComments: Set<string>, commentNode: comment.CommentNode): void {
    const unHandledComments: Array<comment.CommentInfo> = [];
    commentNode.commentInfos?.forEach((info) => {
      const key = `${info.pos}:${info.end}`;
      if (info.isInstruct || !handledComments.has(key)) {
        unHandledComments.push(info);
        handledComments.add(key);
      }
    });
    if (unHandledComments.length !== commentNode.commentInfos?.length) {
      commentNode.commentInfos = unHandledComments;
    }
  }

  private shouldNotifyCallback(node: ts.Node, hasComment: boolean, onlyVisitHasComment?: boolean): boolean {
    if (!this.shouldNotify(node)) {
      return false;
    }
    return !(onlyVisitHasComment && onlyVisitHasComment === true && !hasComment);
  }

  printSourceFile(sourceFile: ts.SourceFile): string {
    const printer = ts.createPrinter(this.options.printerOptions);
    let codeString = printer.printFile(sourceFile);
    // replace empty line instruct
    codeString = codeString.replaceAll(/\s*\/\/Instruct_new_line/g, '\n');
    return codeString;
  }
}


export class CommentHelper {
  static LICENSE_KEYWORD = 'Copyright';
  static REFERENCE_REGEXP = /\/\/\/\s*<reference\s*path/g;
  static REFERENCE_COMMENT_REGEXP = /\/\s*<reference\s*path/g;
  static MULTI_COMMENT_DELIMITER = '/**';

  /**
   * 给节点追加注释(注意：无法在原始注释中追加，只能将原始注释完全复制一份并修改再做完整替换)
   * 
   * @param node ast 节点对象
   * @param commentInfos 注释列表
   */
  static addComment(node: ts.Node, commentInfos: Array<comment.CommentInfo>): void {
    if (commentInfos.length === 0) {
      return;
    }
    CommentHelper.ignoreOriginalComment(node);
    commentInfos.forEach((info) => {
      // might be a license
      if (info.ignore) {
        return;
      }
      const assembledComment = CommentHelper.assembleComment(info);
      const kind = info.isMultiLine ? ts.SyntaxKind.MultiLineCommentTrivia : ts.SyntaxKind.SingleLineCommentTrivia;
      if (info.isLeading) {
        ts.addSyntheticLeadingComment(node, kind, assembledComment, true);
      } else {
        ts.addSyntheticTrailingComment(node, kind, assembledComment, true);
      }
    });
  }

  /**
   * 封装符合格式的注释
   * 
   * @param commentInfo 
   * @returns 
   */
  static assembleComment(commentInfo: comment.CommentInfo): string {
    const writer = new CommentWriter(commentInfo.isMultiLine);
    return writer.publish(commentInfo);
  }


  /**
   * 设置节点注释，覆盖已有的注释。(注意：原始文件的注释不会被替换，只在输出时忽略原始注释，打印新的注释)
   * 
   * @param node 
   * @param commentInfos 
   * @param commentKind 
   * @returns 
   */
  static setComment(node: ts.Node, commentInfos: Array<comment.CommentInfo>, commentKind?: number): void {
    if (commentInfos.length === 0) {
      return;
    }
    CommentHelper.ignoreOriginalComment(node);
    const syntheticLeadingComments: Array<ts.SynthesizedComment> = new Array();
    commentInfos.forEach((info) => {
      // might be a license
      if (info.ignore) {
        return;
      }
      syntheticLeadingComments.push({
        text: CommentHelper.assembleComment(info),
        pos: -1,
        end: -1,
        hasLeadingNewline: true,
        hasTrailingNewLine: true,
        kind: info.isMultiLine ? ts.SyntaxKind.MultiLineCommentTrivia : ts.SyntaxKind.SingleLineCommentTrivia
      });
    });

    if (!commentKind || commentKind === comment.CommentLocationKind.LEADING) {
      ts.setSyntheticLeadingComments(node, syntheticLeadingComments);
    } else {
      ts.setSyntheticTrailingComments(node, syntheticLeadingComments);
    }
  }

  /**
   * 打印源码时忽略节点的原始注释
   * 
   * @param node 
   */
  private static ignoreOriginalComment(node: ts.Node): void {
    // ignore the original comment
    ts.setEmitFlags(node, ts.EmitFlags.NoLeadingComments);
  }

  /**
   * 将多段注释文本解析成注释对象。
   * 
   * @param comment
   * @returns 
   */
  static parseComment(comment: string, commentKind: ts.CommentKind, isLeading: boolean): comment.CommentInfo {
    const { parse } = require('comment-parser');
    const commentInfo: comment.CommentInfo = {
      text: comment,
      isMultiLine: commentKind === ts.SyntaxKind.MultiLineCommentTrivia,
      isLeading: isLeading,
      description: '',
      commentTags: [],
      parsedComment: undefined,
      pos: -1,
      end: -1,
      ignore: false,
      isApiComment: false,
      isInstruct: false
    };
    let commentString = comment;
    let parsedComments = parse(commentString);
    const START_POSITION_INDEX = 2;
    // 无法被解析的注释,可能以 /* 开头或是单行注释
    if (parsedComments.length === 0) {
      // 注释是 /// <reference path="" /> 或 单行注释
      if (StringUtils.hasSubstring(commentString, this.REFERENCE_REGEXP) ||
        commentKind === ts.SyntaxKind.SingleLineCommentTrivia) {
        commentInfo.isMultiLine = false;
        // 注释内容需丢弃 "//"
        commentInfo.text = commentString.substring(START_POSITION_INDEX, commentString.length);
      }
      return commentInfo;
    }
    commentInfo.parsedComment = parsedComments[0];
    commentInfo.description = parsedComments[0].description;
    parsedComments[0].tags.forEach((tagObject: CommentData) => {
      commentInfo.commentTags.push({
        tag: tagObject.tag,
        name: tagObject.name,
        type: tagObject.type,
        optional: tagObject.optional,
        description: tagObject.description,
        source: tagObject.source[0].source,
        lineNumber: tagObject.source[0].number,
        tokenSource: tagObject.source,
        defaultValue: tagObject.default ? tagObject.default : undefined
      });
    });
    commentInfo.isApiComment = true;
    return commentInfo;
  }

  /**
   * 获取指定AST节点上的注释，若无注释返回空数组。
   * 
   * @param node 
   * @param sourceFile 
   * @returns 
   */
  static getNodeLeadingComments(node: ts.Node, sourceFile: ts.SourceFile): comment.CommentInfo[] {
    try {
      const leadingCommentRange: CommentRange[] | undefined = ts.getLeadingCommentRanges(sourceFile.getFullText(), node.getFullStart());
      if (leadingCommentRange?.length) {
        const parsedCommentInfos: Array<comment.CommentInfo> = [];
        leadingCommentRange.forEach((range) => {
          const comment = sourceFile.getFullText().slice(range.pos, range.end);
          const commentInfo = CommentHelper.parseComment(comment, range.kind, true);
          commentInfo.pos = range.pos;
          commentInfo.end = range.end;
          parsedCommentInfos.push(commentInfo);
          this.fixReferenceComment(commentInfo, parsedCommentInfos);
        });
        this.fixLicenseComment(node, parsedCommentInfos);
        return parsedCommentInfos;
      }
      return [];
    } catch (error) {
      LogUtil.d('CommentHelper', `node(kind=${node.kind}) is created in memory.`);
      return [];
    }
  }

  private static fixReferenceComment(commentInfo: comment.CommentInfo, parsedCommentInfos: Array<comment.CommentInfo>): void {
    if (commentInfo.isMultiLine || commentInfo.isApiComment ||
      !StringUtils.hasSubstring(commentInfo.text, this.REFERENCE_COMMENT_REGEXP)) {
      return;
    }
    parsedCommentInfos.push(this.getEmptyLineComment());
  }

  /**
   * 如果license注释与头注释间没有空白行会导致license丢失.
   *
   * @param commentInfos
   */
  private static fixLicenseComment(node: ts.Node, commentInfos: comment.CommentInfo[]): void {
    if (commentInfos.length === 0) {
      return;
    }
    // 如果只有一个注释并且是license, license 与 node 间需要一个空行
    if (commentInfos.length === 1) {
      if (StringUtils.hasSubstring(commentInfos[0].text, this.LICENSE_KEYWORD)) {
        const copyRightPosition = node.getSourceFile().getLineAndCharacterOfPosition(commentInfos[0].end);
        const nodePosition = node.getSourceFile().getLineAndCharacterOfPosition(node.getStart());
        if ((nodePosition.line - copyRightPosition.line) === 1) {
          commentInfos.push(this.getEmptyLineComment());
        } else {
          commentInfos[0].ignore = true;
        }
      }
      return;
    }
    const firstCommentInfo: comment.CommentInfo = commentInfos[0];
    if (!StringUtils.hasSubstring(firstCommentInfo.text, this.LICENSE_KEYWORD)) {
      return;
    }
    firstCommentInfo.isApiComment = false;
    // license 注释在第一位
    const firstPosition = node.getSourceFile().getLineAndCharacterOfPosition(firstCommentInfo.end);
    const secondPosition = node.getSourceFile().getLineAndCharacterOfPosition(commentInfos[1].pos);
    // 无空格
    if ((secondPosition.line - firstPosition.line) === 1) {
      firstCommentInfo.ignore = false;
    } else {
      firstCommentInfo.ignore = true;
    }
    // license注释与头注释之间没有import语句会导致两者间的空行丢失, 插入空行指令
    commentInfos.splice(1, 0, this.getEmptyLineComment());
  }

  static getEmptyLineComment(): comment.CommentInfo {
    return {
      text: Instruct.EMPTY_LINE,
      isMultiLine: false,
      isLeading: true,
      description: '',
      commentTags: [],
      parsedComment: undefined,
      pos: -1,
      end: -1,
      ignore: false,
      isApiComment: false,
      isInstruct: true
    };
  }

  static getNodeTrailingComments(node: ts.Node, sourceFile: ts.SourceFile): comment.CommentInfo[] {
    try {
      const trailingCommentRange: CommentRange[] | undefined = ts.getTrailingCommentRanges(sourceFile.getFullText(), node.getEnd() + 1);
      if (trailingCommentRange?.length) {
        const commentNodes = trailingCommentRange.map((range) => {
          const comment = sourceFile.getFullText().slice(range.pos, range.end);
          return CommentHelper.parseComment(comment.replace(/^\s*\/\//g, ''), range.kind, false);
        });
        return commentNodes;
      }
      return [];
    } catch (error) {
      LogUtil.w('CommentHelper', 'getNodeTrailingComments:' + error);
      return [];
    }
  }
}

/**
 * 注释封装类
 */
class CommentWriter {
  isMultiLine: boolean;
  commentBlockDelimiter = '/**';

  constructor(isMultiLine: boolean) {
    this.isMultiLine = isMultiLine;
  }

  /**
   * 构建完整的注释文本段
   */
  publish(commentInfo: comment.CommentInfo): string {
    const parsedComment: comment.ParsedComment | undefined = commentInfo.parsedComment;
    // 如果没有解析过的注释对象(可能是license)，使用原始注释内容
    let plainComment = parsedComment ? this.restoreParsedComment(parsedComment, commentInfo.commentTags) : commentInfo.text;
    const START_POSITION_INDEX = 2;
    if (commentInfo.isMultiLine) {
      // 删除起始 /* 和末尾 */ 符号
      plainComment = plainComment.substring(START_POSITION_INDEX, plainComment.length - START_POSITION_INDEX);
    }
    return plainComment;
  }

  private restoreParsedComment(parsedComment: comment.ParsedComment, commentTags: Array<comment.CommentTag>): string {
    const newSourceArray: Array<comment.CommentSource> = [];
    const { stringify } = require('comment-parser');
    if (parsedComment.source.length === 1) {
      return stringify(parsedComment);
    }
    for (let source of parsedComment.source) {
      // 保留描述信息,去除标签注释
      if (source.tokens.tag !== '') {
        break;
      }
      // 描述信息内有空行
      if (source.tokens.description === '') {
        continue;
      }
      // 描述信息写在/** 之后
      if (source.tokens.delimiter === this.commentBlockDelimiter) {
        source.tokens.delimiter = '*';
        source.tokens.postDelimiter = ' ';
      }
      // 除了起始符号为空，其他场景则重置为一个空格
      // ts api 提供的写注释接口缩进是参考当前节点的，因此一个空格可以保证格式正确
      if (source.tokens.start !== '') {
        source.tokens.start = ' ';
      }
      newSourceArray.push(source);
    }
    // 添加注释首行
    newSourceArray.splice(0, 0, { number: 0, source: '', tokens: this.getCommentStartToken() });
    const lastSource = newSourceArray[newSourceArray.length - 1];
    if (commentTags.length !== 0) {
      if (!this.isEndLine(lastSource.tokens)) {
        this.addNewEmptyLineIfNeeded(newSourceArray, lastSource);
        this.addTags(newSourceArray, commentTags);
      }
    } else {
      newSourceArray.push({ number: 0, source: '', tokens: this.getCommentEndToken() });
    }
    parsedComment.source = newSourceArray;
    return stringify(parsedComment);
  }

  private addNewEmptyLineIfNeeded(newSourceArray: Array<comment.CommentSource>, lastSource: comment.CommentSource): void {
    if (this.shouldInsertNewEmptyLine(lastSource.tokens)) {
      // 注释还原成字符串时， number, source 属性不会被用到 
      newSourceArray.push({ number: 0, source: '', tokens: this.getNewLineToken() });
    }
  }

  private addTags(newSourceArray: Array<comment.CommentSource>, commentTags: Array<comment.CommentTag>): void {
    commentTags.forEach((commentTag) => {
      // tag的描述为多行,复用原始的描述信息
      const tokenSourceLen = commentTag.tokenSource.length;
      if (tokenSourceLen > 1) {
        // 数组第一个为包含tag的注释
        const tagSameLineDescription = commentTag.tokenSource[0].tokens.description;
        newSourceArray.push({ number: 0, source: '', tokens: this.getCommentToken(commentTag, tagSameLineDescription) });
        // 将tag剩余的描述信息放入
        for (let index = 1; index < tokenSourceLen; index++) {
          const tagDescriptionSource = commentTag.tokenSource[index];
          // 末尾的tag会包含注释结束符, tag 间可能有空行
          if (tagDescriptionSource.tokens.end !== '*/' && tagDescriptionSource.tokens.description !== '') {
            tagDescriptionSource.tokens.start = ' ';
            newSourceArray.push(tagDescriptionSource);
          }
        }
      } else {
        // tag注释只有一行
        newSourceArray.push({ number: 0, source: '', tokens: this.getCommentToken(commentTag, commentTag.description) });
      }
    });
    newSourceArray.push({ number: 0, source: '', tokens: this.getEndLineToken() });
  }

  private getCommentToken(commentTag: comment.CommentTag, description: string): comment.CommentToken {
    const tokens: comment.CommentToken = {
      // 起始空格
      start: ' ',
      // * 定界符
      delimiter: '*',
      // 定界符之后空格
      postDelimiter: ' ',
      // 标签
      tag: `@${commentTag.tag}`,
      // 标签后空格
      postTag: ' ',
      // 标签名称
      name: commentTag.optional ?
        (commentTag.defaultValue ? `[${commentTag.name} = ${commentTag.defaultValue}]` : `[${commentTag.name}]`) : commentTag.name,
      // 标签名称后空格
      postName: commentTag.name === '' ? '' : ' ',
      // 类型
      type: commentTag.type === '' ? '' : `{ ${commentTag.type} }`,
      // 类型之后空格
      postType: commentTag.type === '' ? '' : ' ',
      // 描述
      description: description,
      end: '',
      lineEnd: ''
    };
    return tokens;
  }

  private getCommentEndToken(): comment.CommentToken {
    return {
      start: ' ',
      delimiter: '',
      postDelimiter: '',
      tag: '',
      postTag: '',
      name: '',
      postName: '',
      type: '',
      postType: '',
      description: '',
      end: '*、',
      lineEnd: ''
    };
  }

  private getCommentStartToken(): comment.CommentToken {
    return {
      start: '',
      delimiter: this.commentBlockDelimiter,
      postDelimiter: '',
      tag: '',
      postTag: '',
      name: '',
      postName: '',
      type: '',
      postType: '',
      description: '',
      end: '',
      lineEnd: ''
    };
  }

  private getNewLineToken(): comment.CommentToken {
    return {
      start: ' ',
      delimiter: '*',
      postDelimiter: '',
      tag: '',
      postTag: '',
      name: '',
      postName: '',
      type: '',
      postType: '',
      description: '',
      end: '',
      lineEnd: ''
    };
  }

  private getEndLineToken(): comment.CommentToken {
    return {
      start: ' ',
      delimiter: '',
      postDelimiter: '',
      tag: '',
      postTag: '',
      name: '',
      postName: '',
      type: '',
      postType: '',
      description: '',
      end: '*/',
      lineEnd: ''
    };
  }

  private shouldInsertNewEmptyLine(token: comment.CommentToken): boolean {
    const lastDescriptionNotEmpty = token.tag === '' && token.delimiter === '*' && token.description !== '';
    const commentStartLine = token.tag === '' && token.delimiter === this.commentBlockDelimiter;
    return lastDescriptionNotEmpty && !commentStartLine;
  }

  private isEndLine(token: comment.CommentToken): boolean {
    return token.tag === '' && token.end === '*/';
  }
}

export class AstNodeHelper {
  static noNeedSignatureNodeTypes: Array<number> = [
    ts.SyntaxKind.ModuleBlock, ts.SyntaxKind.Block, ts.SyntaxKind.CaseBlock
  ];
  static skipSignatureNode: Array<number> = [
    ts.SyntaxKind.PropertySignature, ts.SyntaxKind.MethodSignature, ts.SyntaxKind.EnumMember, ts.SyntaxKind.Constructor,
    ts.SyntaxKind.PropertyDeclaration, ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.TypeLiteral
  ];

  /**
   * 获取节点的签名信息。签名信息会追加父节点签名信息，确保全局唯一。
   * 注释改动导致行数变化, AST节点的顺序不会影响签名。
   *
   * @param node Ast节点
   * @returns string 节点签名信息
   */
  static getNodeSignature(node: ts.Node): string {
    if (!node || AstNodeHelper.noNeedSignatureNodeTypes.includes(node.kind)) {
      return '';
    }
    let nodeSignature = `${AstNodeHelper.getType(node)}#`;
    node.forEachChild((child) => {
      if (!AstNodeHelper.skipSignatureNode.includes(child.kind) && !AstNodeHelper.noNeedSignatureNodeTypes.includes(child.kind)) {
        nodeSignature += `${AstNodeHelper.getChildPlainText(child)}`;
      }
    });
    const qualifiedSignature = this.getParentNodeSignature(node.parent) + nodeSignature;
    LogUtil.d('AstNodeHelper', `qualifiedSignature = ${qualifiedSignature}`);
    return qualifiedSignature;
  }

  private static getChildPlainText(node: ts.Node): string {
    if (node.getChildCount() === 0) {
      return node.getText();
    }
    let content = '';
    node.forEachChild((child) => {
      content += `${this.getChildPlainText(child)}`;
    });
    return content;
  }

  private static getType(node: ts.Node): string {
    return `${ts.SyntaxKind[node.kind]}`;
  }

  private static getParentNodeSignature(node: ts.Node): string {
    if (!node || node.kind === ts.SyntaxKind.SourceFile) {
      return '';
    }
    const parentNodeSignature = this.getNodeSignature(node);
    if (parentNodeSignature === '') {
      return this.getNodeSignature(node.parent);
    }
    return parentNodeSignature;
  }
}

/**
 * 
 * 命令行入参对象
 * 
 */
export class InputParameter {
  inputFilePath: string = '';
  outputFilePath: string | undefined;
  logLevel: string = '';
  splitUnionTypeApi: boolean = false;
  branch: string = 'master';
  test: boolean = false;
  options: Options = new Options();

  parse(): void {
    const program = new Command();
    program
      .name('jsdoc-tool')
      .description('CLI to format d.ts')
      .version('0.1.0')
      .allowUnknownOption(true)
      .requiredOption('-i, --input <path>', `${StringResource.getString(StringResourceId.COMMAND_INPUT_DESCRIPTION)}`)
      .option('-o, --output <path>', `${StringResource.getString(StringResourceId.COMMAND_OUT_DESCRIPTION)}`)
      .option('-l, --logLevel <INFO,WARN,DEBUG,ERR>', `${StringResource.getString(StringResourceId.COMMAND_LOGLEVEL_DESCRIPTION)}`, 'INFO')
      .option('-s, --split', `${StringResource.getString(StringResourceId.COMMAND_SPLIT_API)}`, false)
      .option('-b, --branch <string>', `${StringResource.getString(StringResourceId.COMMAND_BRANCH)}`, 'master')
      .option('-t, --test', `${StringResource.getString(StringResourceId.COMMAND_TEST)}`, false);

    program.parse();
    const options = program.opts();
    this.inputFilePath = options.input;
    this.outputFilePath = options.output;
    this.logLevel = options.logLevel;
    this.splitUnionTypeApi = options.split;
    this.branch = options.branch;
    this.test = options.test;
    this.checkInput();
  }

  private checkInput(): void {
    this.inputFilePath = path.resolve(this.inputFilePath);
    this.outputFilePath = this.outputFilePath ? path.resolve(this.outputFilePath) : undefined;

    if (this.outputFilePath && (this.outputFilePath === path.basename(this.outputFilePath))) {
      throw StringResource.getString(StringResourceId.INVALID_PATH);
    }

    this.checkFileExists(this.inputFilePath);

    if (FileUtils.isDirectory(this.inputFilePath)) {
      if (this.outputFilePath) {
        const extName = path.extname(this.outputFilePath);
        // if input is a directory, output must be a directory
        if (extName !== '') {
          throw `-o, --output ${StringResource.getString(StringResourceId.OUTPUT_MUST_DIR)}`;
        }
        const relativePath = path.relative(this.inputFilePath, this.outputFilePath);
        // the output directory cannot be a subdirectory of the input directory
        if (relativePath === '' || !relativePath.startsWith('..')) {
          throw `-o, --output ${StringResource.getString(StringResourceId.OUTPUT_SUBDIR_INPUT)}`;
        }
      }
    } else {
      if (!this.inputFilePath.endsWith(ConstantValue.DTS_EXTENSION)) {
        throw StringResource.getString(StringResourceId.NOT_DTS_FILE);
      }
      // if input is a file, output file must be a file
      if (this.outputFilePath) {
        const extName = path.extname(this.outputFilePath);
        if (extName === '') {
          throw `-o, --output ${StringResource.getString(StringResourceId.OUTPUT_MUST_FILE)}`;
        }
        // output file is same with input file
        if (this.outputFilePath === this.inputFilePath) {
          throw `-o, --output ${StringResource.getString(StringResourceId.OUTPUT_SAME_WITH_INPUT)}`;
        }
      }
    }
    this.options.splitUnionTypeApi = this.splitUnionTypeApi;
    this.options.workingBranch = this.branch;
    this.options.isTest = this.test;
  }

  private checkFileExists(filePath: string): void {
    if (!FileUtils.isExists(filePath)) {
      throw `${StringResource.getString(StringResourceId.INPUT_FILE_NOT_FOUND)}: ${filePath}`;
    }
  }

  isHandleMultiFiles(): boolean {
    return FileUtils.isDirectory(this.inputFilePath);
  }

  getOptions(): Options {
    return this.options;
  }
}

export class RawSourceCodeInfoImpl extends rawInfo.RawSourceCodeInfo {
  rawInfoMap: Map<string, rawInfo.RawNodeInfo> = new Map();

  addRawNodeInfo(ndoeSignature: string, node: ts.Node, line: number, character: number): void {
    this.rawInfoMap.set(ndoeSignature, {
      line: line,
      character: character,
      astNode: node
    });
  }

  findRawNodeInfo(node: ts.Node): rawInfo.RawNodeInfo | undefined {
    const nodeSignature = AstNodeHelper.getNodeSignature(node);
    return this.rawInfoMap.get(nodeSignature);
  }

  toString(): string {
    let value = '';
    this.rawInfoMap.forEach((info, signature) => {
      value += `[${signature}, ${info.line}]\n`;
    });
    return value;
  }
}

/**
 * 报告结果实现类
 */
export class LogReporterImpl implements LogReporter {

  checkResults: Array<CheckLogResult> = [];
  modifyResults: Array<ModifyLogResult> = [];
  writer: LogWriter | undefined;

  checkResultMap: Map<string, string> = new Map([
    ['filePath', '文件地址'],
    ['apiName', '接口名称'],
    ['apiContent', '接口内容'],
    ['errorType', '异常类型'],
    ['errorInfo', '告警信息'],
    ['version', '版本号'],
    ['moduleName', '模块名称']
  ]);

  modifyResultMap: Map<string, string> = new Map([
    ['filePath', '文件地址'],
    ['apiName', '接口名称'],
    ['apiContent', '接口内容'],
    ['modifyType', '整改类型'],
    ['description', '整改内容'],
    ['version', '版本号'],
    ['description', '整改说明'],
    ['moduleName', '模块名称']
  ]);

  constructor() { }

  setWriter(writer: LogWriter): void {
    this.writer = writer;
  }

  addCheckResult(checkResult: CheckLogResult): void {
    this.checkResults.push(checkResult);
  }

  addModifyResult(modifyResult: ModifyLogResult): void {
    this.modifyResults.push(modifyResult);
  }

  getCheckResultMap(): Map<string, string> {
    return this.checkResultMap;
  }

  getModifyResultMap(): Map<string, string> {
    return this.modifyResultMap;
  }

  async writeCheckResults(path: string): Promise<void> {
    await this.writer?.writeResults(this.checkResults, undefined, path);
  }

  async writeModifyResults(path: string): Promise<void> {
    await this.writer?.writeResults(undefined, this.modifyResults, path);
  }

  async writeAllResults(path: string): Promise<void> {
    await this.writer?.writeResults(this.checkResults, this.modifyResults, path);
  }
}

export namespace logWriter {
  export class ExcelWriter implements LogWriter {
    workBook: excelJs.Workbook = new excelJs.Workbook();
    checkResultsColumns: Array<object> = [];
    modifyResultsColumns: Array<object> = [];

    constructor(logReporter: LogReporter) {
      // 初始化列名
      this.initCheckResultsColumns(logReporter.getCheckResultMap());
      this.initModifyResultsColumns(logReporter.getModifyResultMap());
    }

    initCheckResultsColumns(checkResultMap: Map<string, string>): void {
      checkResultMap.forEach((value: string, key: string) => {
        this.checkResultsColumns.push({
          'header': value,
          'key': key
        });
      });
    }

    initModifyResultsColumns(modifyResultMap: Map<string, string>): void {
      modifyResultMap.forEach((value: string, key: string) => {
        this.modifyResultsColumns.push({
          'header': value,
          'key': key
        });
      });
    }

    async writeResults(checkResults: Array<CheckLogResult> | undefined,
      modifyResults: Array<ModifyLogResult> | undefined, filePath: string): Promise<void> {
      if (checkResults) {
        const checkResultsSheet: excelJs.Worksheet = this.workBook.addWorksheet('待确认报告');
        checkResultsSheet.columns = this.checkResultsColumns;
        checkResultsSheet.addRows(checkResults);
      }
      if (modifyResults) {
        const modifyResultsSheet: excelJs.Worksheet = this.workBook.addWorksheet('整改报告');
        modifyResultsSheet.columns = this.modifyResultsColumns;
        modifyResultsSheet.addRows(modifyResults);
      }
      const fileName: string = `${filePath}.xlsx`;
      await this.workBook.xlsx.writeFile(fileName);
    }
  }

  interface JsonResult {
    checkResults: Array<CheckLogResult> | undefined,
    modifyResults: Array<ModifyLogResult> | undefined
  }

  export class JsonWriter implements LogWriter {
    async writeResults(checkResults: Array<CheckLogResult> | undefined,
      modifyResults: Array<ModifyLogResult> | undefined, filePath: string): Promise<void> {
      const results: JsonResult = {
        checkResults: undefined,
        modifyResults: undefined
      };
      if (checkResults) {
        results.checkResults = checkResults;
      }
      if (modifyResults) {
        results.modifyResults = modifyResults;
      }
      const SPACE_NUMBER = 2;
      const jsonText: string = JSON.stringify(results, null, SPACE_NUMBER);
      const fileName: string = `${filePath}.json`;
      fs.writeFileSync(fileName, jsonText);
    }
  }
}

export class LogResult {
  static createCheckResult(node: ts.Node, comments: Array<comment.CommentInfo>, errorInfo: string,
    context: Context | undefined, apiName: string, errorType: JSDocCheckErrorType): CheckLogResult {
    const url: string = context ? context.getInputFile() : '';
    const moduleName: string = path.basename(url, ConstantValue.DTS_EXTENSION);
    const rawCodeInfo = context ? context.getRawSourceCodeInfo().findRawNodeInfo(node) : undefined;
    const filePath: string = `${url}(${rawCodeInfo?.line},${rawCodeInfo?.character})`;
    let version = 'N/A';
    if (comments.length !== 0) {
      comments[comments.length - 1].commentTags.forEach((commentTag) => {
        if (commentTag.tag === 'since') {
          version = commentTag.name ? commentTag.name : 'N/A';
        }
      });
    }
    let apiContent: string = '';
    comments.forEach((curComment: comment.CommentInfo) => {
      if (curComment.isApiComment) {
        apiContent += `${curComment.text}\n`;
      }
    });
    apiContent += node.getText();
    const checkLogResult: CheckLogResult = {
      filePath: filePath,
      apiName: apiName,
      apiContent: apiContent,
      errorType: errorType,
      version: version,
      errorInfo: errorInfo,
      moduleName: moduleName
    };
    return checkLogResult;
  }

  static createModifyResult(node: ts.Node, comments: Array<comment.CommentInfo>, description: string,
    context: Context | undefined, apiName: string, jsDocModifyType: JSDocModifyType): ModifyLogResult {
    const url: string = context ? context.getInputFile() : '';
    const moduleName: string = path.basename(url, ConstantValue.DTS_EXTENSION);
    const rawCodeInfo = context ? context.getRawSourceCodeInfo().findRawNodeInfo(node) : undefined;
    const filePath: string = `${url}(${rawCodeInfo?.line},${rawCodeInfo?.character})`;
    let version = 'N/A';
    if (comments.length !== 0) {
      comments[comments.length - 1].commentTags.forEach((commentTag) => {
        if (commentTag.tag === 'since') {
          version = commentTag.name ? commentTag.name : 'N/A';
        }
      });
    }
    let apiContent: string = '';
    comments.forEach((curComment: comment.CommentInfo) => {
      if (curComment.isApiComment) {
        apiContent += `${curComment.text}\n`;
      }
    });
    apiContent += node.getText();
    const modifyLogResult: ModifyLogResult = {
      filePath: filePath,
      apiName: apiName,
      apiContent: apiContent,
      modifyType: jsDocModifyType,
      version: version,
      description: description,
      moduleName: moduleName
    };
    return modifyLogResult;
  }
}