/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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


const { requireTypescriptModule, ErrorType, ErrorLevel, FileType, ErrorValueInfo, checkVersionNeedCheck } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');
const ts = requireTypescriptModule();

function checkAnyInAPI(node, sourcefile, fileName) {
  if (node.kind === ts.SyntaxKind.AnyKeyword && checkVersionNeedCheck(node)) {
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.ILLEGAL_ANY, ErrorValueInfo.ILLEGAL_USE_ANY, FileType.API,
      ErrorLevel.LOW);
  }
}
exports.checkAnyInAPI = checkAnyInAPI;
