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

const { getAPINote, ErrorType, ErrorLevel, FileType } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');

function checkDeprecated(node, sourcefile, fileName) {
  const apiNote = getAPINote(node);
  const apiNoteArr = apiNote.split('*');
  let hasDeprecatedError = false;
  let errorInfo = '';
  apiNoteArr.forEach(note => {
    if (note.match(new RegExp('@deprecated'))) {
      const deprecatedNote = note.replace('@deprecated', '').trim();
      const regx = /since [0-9]/;
      const arr = deprecatedNote.match(regx);
      if (arr !== null) {
        const errorNote = deprecatedNote.replace(arr[0], '');
        if (/[A-z]/.test(errorNote)) {
          hasDeprecatedError = true;
          if (errorInfo !== '') {
            errorInfo += `,${note}`;
          } else {
            errorInfo += note;
          }
        }
      } else if (arr === null) {
        hasDeprecatedError = true;
        if (errorInfo !== '') {
          errorInfo += `,${note}`;
        } else {
          errorInfo += note;
        }
      }
    }
  });

  if (hasDeprecatedError) {
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.UNKNOW_DEPRECATED, errorInfo, FileType.JSDOC,
      ErrorLevel.MIDDLE);
  }
}
exports.checkDeprecated = checkDeprecated;
