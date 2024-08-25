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

const { ErrorType, ErrorLevel, FileType, fileTagOrder, ErrorValueInfo } = require('./utils');
const { parseJsDoc } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');

function checkFileTagOrder(node, sourcefile, fileName) {
  const comments = parseJsDoc(node);
  if (comments.length === 0) {
    return;
  }
  const fileJsdoc = comments[0].tags;
  for (let tagIndex = 0; tagIndex < fileJsdoc.length; tagIndex++) {
    if (tagIndex + 1 < fileJsdoc.length) {
      // 获取前后两个tag下标
      const firstIndex = fileTagOrder.indexOf(fileJsdoc[tagIndex].tag);
      const secondIndex = fileTagOrder.indexOf(fileJsdoc[tagIndex + 1].tag);
      // 非自定义标签在前或数组降序时报错
      if (firstIndex > secondIndex && secondIndex > -1 && firstIndex > -1) {
        addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.WRONG_SCENE, ErrorValueInfo.ERROR_FILE_TAG_ORDER,
          FileType.JSDOC, ErrorLevel.MIDDLE);
        break;
      }
    }
  };
}
exports.checkFileTagOrder = checkFileTagOrder;