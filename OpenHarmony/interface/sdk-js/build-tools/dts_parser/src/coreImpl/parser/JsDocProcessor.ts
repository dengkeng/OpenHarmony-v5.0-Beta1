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
import { LogUtil } from '../../utils/logUtil';
import { StringUtils } from '../../utils/StringUtils';
import { ApiType } from '../../typedef/parser/ApiInfoDefination';

export class CommentHelper {
  static licenseKeyword: string = 'Copyright';
  static referenceRegexp: RegExp = /\/\/\/\s*<reference\s*path/g;
  static referenceCommentRegexp: RegExp = /\/\s*<reference\s*path/g;
  static mutiCommentDelimiter: string = '/**';
  static fileJsDoc: RegExp = /\@kit/g;

  /**
   * 获取指定AST节点上的注释，若无注释返回空数组。
   *
   * @param { ts.Node } node 当前节点
   * @param { ts.SourceFile } sourceFile sourceFile节点
   * @returns { Comment.CommentInfo[] } 处理后的JsDoc数组
   */
  static getNodeLeadingComments(node: ts.Node, sourceFile: ts.SourceFile): Comment.CommentInfo[] {
    try {
      const leadingCommentRange: ts.CommentRange[] | undefined = ts.getLeadingCommentRanges(
        sourceFile.getFullText(),
        node.getFullStart()
      );
      if (leadingCommentRange && leadingCommentRange.length) {
        const parsedCommentInfos: Array<Comment.CommentInfo> = [];
        leadingCommentRange.forEach((range: ts.CommentRange) => {
          const comment: string = sourceFile.getFullText().slice(range.pos, range.end);
          const commentInfo: Comment.CommentInfo = CommentHelper.parseComment(comment, range.kind, true);
          commentInfo.pos = range.pos;
          commentInfo.end = range.end;
          parsedCommentInfos.push(commentInfo);
        });
        return parsedCommentInfos;
      }
      return [];
    } catch (error) {
      LogUtil.d('CommentHelper', `node(kind=${node.kind}) is created in memory.`);
      return [];
    }
  }

  /**
   * 将多段注释文本解析成注释对象。
   *
   * @param { string } comment 多端JsDoc字符串
   * @param { ts.CommentKind } commentKind 注释的类型
   * @param { boolean } isLeading 是否是头注释
   * @returns { Comment.CommentInfo } 返回处理后的JsDoc对象
   */
  static parseComment(comment: string, commentKind: ts.CommentKind, isLeading: boolean): Comment.CommentInfo {
    const { parse } = require('comment-parser');
    const commentInfo: Comment.CommentInfo = {
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
      isInstruct: false,
      isFileJsDoc: false,
    };
    let commentString: string = comment;
    let parsedComments = parse(commentString);
    // 无法被解析的注释,可能以 /* 开头或是单行注释
    if (parsedComments.length === 0) {
      // 注释是 /// <reference path="" /> 或 单行注释
      if (
        StringUtils.hasSubstring(commentString, this.referenceRegexp) ||
        commentKind === ts.SyntaxKind.SingleLineCommentTrivia
      ) {
        commentInfo.isMultiLine = false;
        // 注释内容需丢弃 "//"
        const startIndex: number = 2;
        commentInfo.text = commentString.substring(startIndex, commentString.length);
      }
      return commentInfo;
    }
    commentInfo.parsedComment = parsedComments[0];
    commentInfo.description = parsedComments[0].description;
    for (let i = 0; i < parsedComments[0].tags.length; i++) {
      const tag = parsedComments[0].tags[i];
      commentInfo.commentTags.push({
        tag: tag.tag,
        name: tag.name,
        type: tag.type,
        optional: tag.optional,
        description: tag.description,
        source: tag.source[0].source,
        lineNumber: tag.source[0].number,
        tokenSource: tag.source,
        defaultValue: tag.default ? tag.default : undefined,
      });
    }
    if (StringUtils.hasSubstring(commentString, this.fileJsDoc)) {
      commentInfo.isFileJsDoc = true;
    }
    commentInfo.isApiComment = true;
    return commentInfo;
  }
}

export class JsDocProcessorHelper {
  static setSyscap(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setSyscap(commentTag.name);
  }

  static setSince(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setSince(commentTag.name);
  }

  static setIsForm(jsDocInfo: Comment.JsDocInfo): void {
    jsDocInfo.setIsForm(true);
  }

  static setIsCrossPlatForm(jsDocInfo: Comment.JsDocInfo): void {
    jsDocInfo.setIsCrossPlatForm(true);
  }

  static setIsSystemApi(jsDocInfo: Comment.JsDocInfo): void {
    jsDocInfo.setIsSystemApi(true);
  }

  static setIsAtomicService(jsDocInfo: Comment.JsDocInfo): void {
    jsDocInfo.setIsAtomicService(true);
  }

  static setDeprecatedVersion(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setDeprecatedVersion(commentTag.description);
  }

  static setUseinstead(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setUseinstead(commentTag.name);
  }

  static setPermission(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    const description: string = commentTag.description;
    const name: string = commentTag.name;
    const permissions: string = description ? `${name} ${description}` : `${name}`;
    jsDocInfo.setPermission(permissions);
  }

  static addErrorCode(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    if (!commentTag || isNaN(Number(commentTag.name))) {
      return;
    }
    jsDocInfo.addErrorCode(Number(commentTag.name));
  }

  static setTypeInfo(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setTypeInfo(commentTag.type);
  }

  static setIsConstant(jsDocInfo: Comment.JsDocInfo): void {
    jsDocInfo.setIsConstant(true);
  }

  static setModelLimitation(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setModelLimitation(commentTag.tag);
  }

  static setKitContent(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setKit(commentTag.source.replace(/\* @kit\s+|\r|\n/g, '').trim());
  }

  static setIsFile(jsDocInfo: Comment.JsDocInfo, commentTag: Comment.CommentTag): void {
    jsDocInfo.setIsFile(true);
  }

  /**
   * 基于comment-parser解析的注释对象得到JsDocInfo对象
   *
   * @param { Comment.CommentInfo } jsDoc 一段JsDoc的信息解析的注释对象
   * @returns 返回JsDoc得到的JsDocInfo对象
   */
  static processJsDoc(jsDoc: Comment.CommentInfo, parentKitInfo: string, parentIsFile: boolean): Comment.JsDocInfo {
    const jsDocInfo: Comment.JsDocInfo = new Comment.JsDocInfo();
    jsDocInfo.setDescription(jsDoc.description);
    jsDocInfo.setKit(parentKitInfo);
    jsDocInfo.setIsFile(parentIsFile);
    for (let i = 0; i < jsDoc.commentTags.length; i++) {
      const commentTag: Comment.CommentTag = jsDoc.commentTags[i];
      jsDocInfo.addTag(commentTag);
      const jsDocProcessor = jsDocProcessorMap.get(commentTag.tag.toLowerCase());
      if (!jsDocProcessor) {
        continue;
      }
      jsDocProcessor(jsDocInfo, commentTag);
    }
    return jsDocInfo;
  }

  /**
   * 基于当前node节点，返回节点上多段JsDoc解析后的对象数组
   *
   * @param { ts.Node } node node节点
   * @param { ts.SourceFile } sourceFile node节点的sourceFile
   * @returns 返回解析后的多段JsDoc的信息数组
   */
  static processJsDocInfos(node: ts.Node, apiType: string, parentKitInfo: string, parentIsFile: boolean): Comment.JsDocInfo[] {
    const sourceFile = node.getSourceFile();
    const allCommentInfos: Comment.CommentInfo[] = CommentHelper.getNodeLeadingComments(node, sourceFile);
    const commentInfos: Comment.CommentInfo[] = allCommentInfos.filter((commentInfo: Comment.CommentInfo) => {
      return (
        (commentInfo.isApiComment && !commentInfo.isFileJsDoc && apiType !== ApiType.SOURCE_FILE) ||
        (commentInfo.isApiComment && commentInfo.isFileJsDoc && apiType === ApiType.SOURCE_FILE)
      );
    });

    const jsDocInfos: Comment.JsDocInfo[] = [];
    if (commentInfos.length === 0 && parentKitInfo !== '') {
      const jsDocInfo: Comment.JsDocInfo = new Comment.JsDocInfo();
      jsDocInfo.setKit(parentKitInfo);
      jsDocInfo.setIsFile(parentIsFile);
      jsDocInfos.push(jsDocInfo);
    }
    for (let i = 0; i < commentInfos.length; i++) {
      const commentInfo: Comment.CommentInfo = commentInfos[i];
      const jsDocInfo: Comment.JsDocInfo = JsDocProcessorHelper.processJsDoc(commentInfo, parentKitInfo, parentIsFile);
      jsDocInfos.push(jsDocInfo);
    }
    return jsDocInfos;
  }
}

const jsDocProcessorMap: Map<string, Comment.JsDocProcessorInterface> = new Map([
  [Comment.JsDocTag.SYSCAP, JsDocProcessorHelper.setSyscap],
  [Comment.JsDocTag.SINCE, JsDocProcessorHelper.setSince],
  [Comment.JsDocTag.FORM, JsDocProcessorHelper.setIsForm],
  [Comment.JsDocTag.CROSS_PLAT_FORM, JsDocProcessorHelper.setIsCrossPlatForm],
  [Comment.JsDocTag.SYSTEM_API, JsDocProcessorHelper.setIsSystemApi],
  [Comment.JsDocTag.STAGE_MODEL_ONLY, JsDocProcessorHelper.setModelLimitation],
  [Comment.JsDocTag.FA_MODEL_ONLY, JsDocProcessorHelper.setModelLimitation],
  [Comment.JsDocTag.DEPRECATED, JsDocProcessorHelper.setDeprecatedVersion],
  [Comment.JsDocTag.USEINSTEAD, JsDocProcessorHelper.setUseinstead],
  [Comment.JsDocTag.TYPE, JsDocProcessorHelper.setTypeInfo],
  [Comment.JsDocTag.PERMISSION, JsDocProcessorHelper.setPermission],
  [Comment.JsDocTag.THROWS, JsDocProcessorHelper.addErrorCode],
  [Comment.JsDocTag.CONSTANT, JsDocProcessorHelper.setIsConstant],
  [Comment.JsDocTag.ATOMIC_SERVICE, JsDocProcessorHelper.setIsAtomicService],
  [Comment.JsDocTag.KIT, JsDocProcessorHelper.setKitContent],
  [Comment.JsDocTag.FILE, JsDocProcessorHelper.setIsFile],
]);
