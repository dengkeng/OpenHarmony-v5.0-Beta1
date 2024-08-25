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
import { FileUtils } from '../utils/fileUtils';
import { LogUtil } from '../utils/logUtil';
import { StringUtils } from '../utils/stringUtils';
import { CommentHelper } from './coreImpls';
import type { Context, ISourceCodeProcessor, ProcessResult, sourceParser } from './typedef';
import type { comment} from './typedef';

export class OutputProcessor implements ISourceCodeProcessor {
  async process(context: Context, content: string): Promise<ProcessResult> {
    try {
      let outputContent = content;
      const formater = new Formatter(content);
      outputContent = formater.format(context);

      const prettier = require('prettier');
      outputContent = prettier.format(outputContent, context.getOptions().formaterOption);

      const numberLiteralCaseRule = new NumberLiteralCaseRule(true, context.getSourceParser(outputContent));
      outputContent = numberLiteralCaseRule.apply(outputContent);

      FileUtils.writeStringToFile(outputContent, context.getOutputFile());
      return { code: Code.OK, content: outputContent };
    } catch (error) {
      LogUtil.e('OutputProcessor', `error: ${context.getInputFile()}, ${error}`);
      return { code: Code.OK, content: content };
    }
  }
}

class Formatter implements sourceParser.INodeVisitorCallback {
  source: string;

  constructor(source: string) {
    this.source = source;
  }

  onVisitNode(node: comment.CommentNode): void {
    if (node.astNode && node.commentInfos && node.commentInfos.length > 0) {
      CommentHelper.addComment(node.astNode, node.commentInfos);
    }
  }

  format(context: Context): string {
    const sourceParser = context.getSourceParser(this.source);
    const sourceFile = sourceParser.visitEachNodeComment(this);
    return sourceFile ? sourceParser.printSourceFile(sourceFile) : this.source;
  }
}

/**
 * 转换16进制字符大小写
 */
class NumberLiteralCaseRule {
  upperCase: boolean;
  sourceParser: sourceParser.SourceCodeParser;
  content: string | undefined;

  constructor(upperCase: boolean, sourceParser: sourceParser.SourceCodeParser) {
    this.upperCase = upperCase;
    this.sourceParser = sourceParser;
  }

  apply(content: string): string {
    const sourceFile = this.sourceParser.createSourceFile(content, 'numberLiteral');
    if (!sourceFile) {
      return content;
    }
    this.content = content;
    sourceFile.forEachChild((child) => {
      this.nodeVisitor(child);
    });
    return this.content;
  }

  private nodeVisitor(node: ts.Node): void {
    if (!ts.isNumericLiteral(node)) {
      node.forEachChild((child) => {
        this.nodeVisitor(child);
      });
    }
    const value = node.getText().trim();
    if (!this.isHexString(value)) {
      return;
    }
    const START_POSITION_INDEX = 2;
    let literalStr = value.substring(START_POSITION_INDEX, value.length);
    let replacement = undefined;
    if (this.upperCase && !this.isHexUpperCase(literalStr)) {
      replacement = `0x${literalStr.toUpperCase()}`;
    }
    if (!this.upperCase && !this.isHexLowerCase(literalStr)) {
      replacement = `0x${literalStr.toLowerCase()}`;
    }
    if (!replacement) {
      return;
    }
    this.content = StringUtils.replaceAt(this.content!, node.getStart(), replacement);
  }

  private isHexString(str: string): boolean {
    return /^0x([abcdefABCDEF\d]*)$/g.test(str);
  }

  private isHexUpperCase(str: string): boolean {
    for (let c of str) {
      if (c >= '0' && c <= '9') {
        continue;
      }
      if (c >= 'a' && c <= 'f') {
        return false;
      }
    }
    return true;
  }

  private isHexLowerCase(str: string): boolean {
    for (let c of str) {
      if (c >= '0' && c <= '9') {
        continue;
      }
      if (c >= 'A' && c <= 'F') {
        return false;
      }
    }
    return true;
  }
}