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

const path = require('path');
const fs = require('fs');
const request = require('sync-request');
const { checkSpelling } = require('./check_spelling');
const { checkAPIDecorators } = require('./check_decorator');
const { checkPermission } = require('./check_permission');
const { checkSyscap } = require('./check_syscap');
const { checkDeprecated } = require('./check_deprecated');
const { checkAPINameOfHump, checkAPIFileName } = require('./check_hump');
const { checkJSDoc } = require('./check_legality');
const { checkNaming } = require('./check_naming');
const { checkEventSubscription } = require('./check_event_subscription');
const { checkAnyInAPI } = require('./check_any');
const { checkFileTagOrder } = require('./check_file_tag_order');
const { hasAPINote, ApiCheckResult, requireTypescriptModule, commentNodeWhiteList, splitPath,
  isWhiteListFile } = require('./utils');
const ts = requireTypescriptModule();
const result = require('../check_result.json');
const rules = require('../code_style_rule.json');
const { checkApiChanges } = require('./check_diff_changes');
const whiteLists = require('../config/jsdocCheckWhiteList.json');

function checkAPICodeStyle(url, isTestCase) {
  if (fs.existsSync(url)) {
    const mdApiFiles = getMdFiles(url, isTestCase);
    tsTransform(mdApiFiles, checkAPICodeStyleCallback);
  }
}

function getMdFiles(url, isTestCase) {
  const mdFiles = [];
  const content = fs.readFileSync(url, 'utf-8');
  const filePathArr = content.split(/[(\r\n)\r\n]+/);
  filePathArr.forEach(filePath => {
    const pathElements = new Set();
    splitPath(filePath, pathElements);
    if (!pathElements.has('build-tools') || isTestCase) {
      mdFiles.push(filePath);
    }
  });
  return mdFiles;
}

function tsTransform(uFiles, callback) {
  uFiles.forEach((filePath, index) => {
    console.log(`scaning file in no ${++index}!`);
    if (/\.d\.ts/.test(filePath) && fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, 'utf-8');
      const fileName = path.basename(filePath).replace(/.d.ts/g, '.ts');
      ts.transpileModule(content, {
        compilerOptions: {
          target: ts.ScriptTarget.ES2017,
        },
        fileName: fileName,
        transformers: { before: [callback(filePath)] },
      });
    }
  });
}

function checkAPICodeStyleCallback(fileName) {
  return (context) => {
    return (node) => {
      checkAPIFileName(node, fileName);
      checkAllNode(node, node, fileName);
      return node;
    };
  };
}

function checkAllNode(node, sourcefile, fileName) {
  if (!ts.isImportDeclaration(node) && !ts.isSourceFile(node)) {
    // check hump naming
    checkAPINameOfHump(node, sourcefile, fileName);
  }
  if (hasAPINote(node)) {
    // check decorator
    checkAPIDecorators(node, sourcefile, fileName);
    // check apiNote spelling
    checkSpelling(node, sourcefile, fileName);
    // check syscap
    checkSyscap(node, sourcefile, fileName);
    // check deprecated
    checkDeprecated(node, sourcefile, fileName);
    // check permission
    checkPermission(node, sourcefile, fileName);
    // check event subscription
    checkEventSubscription(node, sourcefile, fileName);
    // check file tag order
    if (ts.isSourceFile(node)) {
      checkFileTagOrder(node, sourcefile, fileName);
    }

    const uesWhiteList = !isWhiteListFile(fileName, whiteLists.JSDocCheck);
    if (commentNodeWhiteList.includes(node.kind) && uesWhiteList) {
      checkJSDoc(node, sourcefile, fileName, true);
    }
  }
  checkAnyInAPI(node, sourcefile, fileName);
  if (ts.isIdentifier(node)) {
    // check variable spelling
    checkSpelling(node, sourcefile, fileName);
    // check naming
    if (node.parent.parent.kind !== ts.SyntaxKind.JSDoc) {
      checkNaming(node, sourcefile, fileName);
    }
  }
  node.getChildren().forEach((item) => checkAllNode(item, sourcefile, fileName));
}

function scanEntry(url, prId, isTestCase) {
  if (prId && prId !== 'NA') {
    checkApiChanges(prId);
    // scan entry
    checkAPICodeStyle(url, isTestCase);
  }
  result.scanResult.push(`api_check: ${ApiCheckResult.formatCheckResult}`);
  return result.scanResult;
}
exports.scanEntry = scanEntry;

function reqGitApi(scanResult, prId) {
  const administrators = new Set();
  const SUCCESS_CODE = 200;
  rules.administrators.forEach((administrator) => {
    administrators.add(administrator.user);
  });
  if (ApiCheckResult.formatCheckResult || !prId || prId === 'NA') {
    return scanResult;
  }
  const commentRequestPath = `https://gitee.com/api/v5/repos/openharmony/interface_sdk-js/pulls/${prId}/comments?page=1&per_page=100&direction=desc`;
  const res = request('GET', commentRequestPath, {
    headers: {
      'Content-Type': 'application/json;charset=UFT-8',
    },
  });
  if (res.statusCode !== SUCCESS_CODE) {
    throw `The giteeAPI access failed, StatusCode:${res.statusCode}`;
  }
  const resBody = new TextDecoder('utf-8').decode(res.body);
  const comments = JSON.parse(`{"resultBody": ${resBody}}`);
  const resultBody = comments.resultBody;
  if (!resultBody || resultBody.length === 0 || !(resultBody instanceof Array)) {
    throw 'The format of data returned by giteeAPI is incorrect';
  }
  for (let i = 0; i < resultBody.length; i++) {
    const comment = resultBody[i];
    if (!(comment && comment.user && comment.user.id && comment.body)) {
      continue;
    }
    const userId = String(comment.user.id);
    if (userId === rules.ciId && /^代码有更新,重置PR验证状态$/.test(comment.body)) {
      break;
    }
    if (administrators.has(userId) && /^approve api check$/.test(comment.body)) {
      ApiCheckResult.formatCheckResult = true;
      scanResult = ['api_check: true'];
      break;
    }
  }
  return scanResult;
}
exports.reqGitApi = reqGitApi;
