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
const result = require('../check_result.json');
const { apiCheckArr, getApiInfo, ErrorLevel, ApiCheckResult, apiCheckInfoArr, requireTypescriptModule } = require('../src/utils');
const ts = requireTypescriptModule();

/**
 *
 * @param {ts.Node} node current node
 * @param {ts.Sourcefile} sourcefile root node
 * @param {String} fileName full file name
 * @param {String} errorType enum object:ErrorType
 * @param {String} errorInfo error infomation
 * @param {String} type jsdoc | api
 * @param {Enum} level enum object:ErrorLevel
 */
function addAPICheckErrorLogs(node, sourcefile, fileName, errorType, errorInfo, type, level) {
  const checkFailFileNameSet = new Set(result.apiFiles);
  if (!checkFailFileNameSet.has(fileName)) {
    result.apiFiles.push(fileName);
  }
  const posOfNode = sourcefile.getLineAndCharacterOfPosition(node.getStart());
  const baseFileName = fileName.substring(fileName.indexOf('api'), fileName.length);
  const errorMessage = `API check error of [${errorType.description}]: ${errorInfo}`;
  const needMask = checkMarkError(node, errorMessage, baseFileName);
  if (needMask) {
    return;
  }
  if (level === ErrorLevel.HIGH || level === ErrorLevel.MIDDLE) {
    ApiCheckResult.formatCheckResult = false;
  }

  apiCheckArr.push({
    errorType: errorType.description,
    fileName: `${baseFileName}(line: ${posOfNode.line + 1}, col: ${posOfNode.character + 1})`,
    type,
    errorInfo,
    version: getApiInfo(node).version,
    basename: path.basename(fileName).replace(/\.d\.ts/g, ''),
    level,
    apiName: node.symbol ? node.symbol.escapedName : '',
    apiFullText: node.getFullText(),
  });

  apiCheckInfoArr.push({
    id: errorType.id,
    level,
    location: `${baseFileName}(line: ${posOfNode.line + 1}, col: ${posOfNode.character + 1})`,
    filePath: baseFileName,
    message: errorMessage,
  });
}
exports.addAPICheckErrorLogs = addAPICheckErrorLogs;

function checkMarkError(node, errorMessage, baseFileName) {
  let needMasking = false;
  let apiName = '';
  if (node.name?.text) {
    apiName = node.name.text;
  } else if (node.escapedText) {
    apiName = node.escapedText;
  }
  const apiText = node.getText().replace(/\r|\n|(\r\n)|\s/g, '');
  const apiKindName = Object.keys(ts.SyntaxKind).find(k => ts.SyntaxKind[k] === node?.kind);
  const apiParentKind = [apiKindName];
  getParentkind(node, apiParentKind);

  // unicode->json
  const maskInfos = parseUnicodeConfig();
  if (maskInfos === '') {
    return needMasking;
  }
  maskInfos.maskInformations.forEach(maskInfo => {
    if (maskInfo.kind === apiKindName &&
      maskInfo.name === apiName &&
      maskInfo.hierarchicalRelationship === JSON.stringify(apiParentKind) &&
      maskInfo.text.replace(/\s/g, '') === apiText &&
      maskInfo.errorMassage === errorMessage &&
      JSON.stringify(maskInfo.fileName) === JSON.stringify(baseFileName.split(path.sep).join('\\'))) {
      needMasking = true;
    }
  });
  return needMasking;
}

function getParentkind(node, parentkindArr) {
  if (ts.isSourceFile(node)) {
    return;
  }
  if (ts.isSourceFile(node.parent)) {
    parentkindArr.push(Object.keys(ts.SyntaxKind).find(k => ts.SyntaxKind[k] === node.parent.kind));
    return;
  }
  if (!ts.isModuleBlock(node.parent)) {
    parentkindArr.push(Object.keys(ts.SyntaxKind).find(k => ts.SyntaxKind[k] === node.parent.kind));
    getParentkind(node.parent, parentkindArr);
  } else if (ts.isModuleBlock(node.parent)) {
    getParentkind(node.parent, parentkindArr);
  }
}
exports.getParentkind = getParentkind;

function parseUnicodeConfig() {
  let maskInfos = '';
  if (!fs.existsSync(path.resolve(__dirname, '../config/errorMaskWhiteList.txt'))) {
    return maskInfos;
  }
  const maskInformations = fs.readFileSync(path.resolve(__dirname, '../config/errorMaskWhiteList.txt'), 'utf-8');
  let maskInfoString = '';
  if (maskInformations && maskInformations.indexOf('\\u') === -1) {
    return JSON.parse(maskInfoString);
  }
  let valArr = maskInformations.split('\\u');
  for (let j = 0; j < valArr.length; j++) {
    if (valArr[j] === '') {
      continue;
    }
    maskInfoString += String.fromCharCode(parseInt(valArr[j], 16));
  }
  maskInfos = JSON.parse(maskInfoString);
  return maskInfos;
}

function string2unicode() {
  const str = fs.readFileSync('../test/errorlist.json', 'utf-8');
  let ret = '';
  let ustr = '';

  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    let code16 = code.toString(16);
    if (code < 0xf) {
      ustr = '\\u' + '000' + code16;
    } else if (code < 0xff) {
      ustr = '\\u' + '00' + code16;
    } else if (code < 0xfff) {
      ustr = '\\u' + '0' + code16;
    } else {
      ustr = '\\u' + code16;
    }
    ret += ustr;
  }
  fs.writeFileSync('errorlist.txt', ret);
  return ret;
}