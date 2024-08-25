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

import { Code } from '../utils/constant';
import { StringUtils } from '../utils/stringUtils';
import { AstNodeHelper, RawSourceCodeInfoImpl } from './coreImpls';
import type { Context, ISourceCodeProcessor, ProcessResult, sourceParser } from './typedef';
import type { comment } from './typedef';

export class RawSourceCodeProcessor implements ISourceCodeProcessor, sourceParser.INodeVisitorCallback {
  rawSourceCodeInfo?: RawSourceCodeInfoImpl;
  async process(context: Context, content: string): Promise<ProcessResult> {
    const sourceParser: sourceParser.SourceCodeParser = context.getSourceParser(content);
    this.rawSourceCodeInfo = new RawSourceCodeInfoImpl(content);
    sourceParser.visitEachNodeComment(this, false);
    context.setRawSourceInfo(this.rawSourceCodeInfo);
    return {
      code: Code.OK,
      content: content
    };
  }

  onVisitNode(node: comment.CommentNode): void {
    if (node.astNode) {
      const nodeSignature = AstNodeHelper.getNodeSignature(node.astNode);
      if (StringUtils.isEmpty(nodeSignature)) {
        return;
      }
      const sourceFile = node.astNode.getSourceFile();
      if (!sourceFile) {
        return;
      }
      const { line, character } = sourceFile.getLineAndCharacterOfPosition(node.astNode.getStart());
      this.rawSourceCodeInfo?.addRawNodeInfo(nodeSignature, node.astNode, line + 1, character);
    }
  }
}