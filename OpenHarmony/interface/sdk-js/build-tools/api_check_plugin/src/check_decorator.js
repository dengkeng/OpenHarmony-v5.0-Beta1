/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

const rules = require('../code_style_rule.json');
const { addAPICheckErrorLogs } = require('./compile_info');
const { getAPINote, ErrorType, ErrorLevel, FileType } = require('./utils');

// duplicate removal
const API_ERROR_DECORATOR_POS = new Set([]);

function checkAPIDecorators(node, sourcefile, fileName) {
  const apiNote = getAPINote(node);
  if (API_ERROR_DECORATOR_POS.has(node.pos)) {
    return;
  }

  const regex = /\*\s*\@[A-Za-z0-9]+\b/g;
  const matchResult = apiNote.match(regex);
  let hasCodeStyleError = false;
  let errorInfo = '';
  if (matchResult) {
    matchResult.forEach(decorator => {
      const docTags = [...rules.decorators.customDoc, ...rules.decorators.jsDoc];
      const decoratorRuleSet = new Set(docTags);
      const apiDecorator = decorator.replace(/^\*\s*\@/, '');
      if (!decoratorRuleSet.has(apiDecorator)) {
        hasCodeStyleError = true;
        if (errorInfo !== '') {
          errorInfo += `,${apiDecorator}`;
        } else {
          errorInfo += apiDecorator;
        }
      }
    });

    if (hasCodeStyleError) {
      API_ERROR_DECORATOR_POS.add(node.pos);
      errorInfo += '.';
      addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.UNKNOW_DECORATOR, errorInfo, FileType.JSDOC,
        ErrorLevel.MIDDLE);
    }
  }
}

exports.checkAPIDecorators = checkAPIDecorators;
