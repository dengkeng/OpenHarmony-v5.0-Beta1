/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const path = require('path');
const { ErrorLevel, LogType, hasAPINote, getApiInfo, requireTypescriptModule, ErrorType, getApiVersion, getCheckApiVersion } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');
const ts = requireTypescriptModule();

/**
 * 大驼峰
 * class、interface、枚举名
 * 小驼峰
 * 变量名、方法名、参数名、namespace
 * 全大写
 * 常量命名、枚举值
 */

// 大驼峰检查
function checkLargeHump(word) {
  return /^([A-Z][a-z0-9]*)*$/g.test(word);
}

// 小驼峰检查
function checkSmallHump(word) {
  return /^[a-z]+[0-9]*([A-Z][a-z0-9]*)*$/g.test(word);
}
exports.checkSmallHump = checkSmallHump;

// 全大写检查
function checkAllUppercaseHump(word) {
  return /^[A-Z]+[0-9]*([\_][A-Z0-9]+)*$/g.test(word);
}

function getName(node) {
  let str = '';
  if (node.name.escapedText) {
    str = node.name.escapedText.toString();
  } else if (node.name.text) {
    str = node.name.text.toString();
  }
  return str;
}

function isConstantDecorator(node, name) {
  return hasAPINote(node) && getApiInfo(node).isConstant && !checkAllUppercaseHump(name);
}

function filterApiVersion(node, version) {
  const apiVersion = getApiVersion(node);
  return apiVersion === version;
}

function checkAPINameOfHump(node, sourcefile, fileName) {
  let checkResult = '';
  const apiInfo = getApiInfo(node);
  if (ts.isEnumMember(node) || (ts.isVariableDeclaration(node) && !(fileName.indexOf('component\\ets\\') >= 0 ||
    fileName.indexOf('component/ets/') >= 0))) {
    const name = getName(node);
    if (!checkAllUppercaseHump(name)) {
      checkResult = `This name [${name}] should be named by all uppercase.`;
    }
  } else if (ts.isInterfaceDeclaration(node) || ts.isClassDeclaration(node) || ts.isTypeAliasDeclaration(node) ||
    ts.isEnumDeclaration(node)) {
    const name = getName(node);
    if (isConstantDecorator(node, name)) {
      checkResult = `This name [${name}] should be named by all uppercase.`;
    } else if (!apiInfo.isConstant && !checkLargeHump(name)) {
      checkResult = `This name [${name}] should be named by large hump.`;
    }
  } else if (ts.isPropertyDeclaration(node) || ts.isPropertySignature(node) || ts.isMethodDeclaration(node) ||
    ts.isFunctionDeclaration(node) || ts.isParameter(node) || ts.isModuleDeclaration(node)) {
    const name = getName(node);
    if (isConstantDecorator(node, name)) {
      checkResult = `This name [${name}] should be named by all uppercase.`;
    } else if (!apiInfo.isConstant && !checkSmallHump(name)) {
      checkResult = `This name [${name}] should be named by small hump.`;
    }
  }

  if (checkResult !== '' && filterApiVersion(node, getCheckApiVersion()) && (!apiInfo.deprecated || apiInfo.deprecated === '')) {
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.NAMING_ERRORS, checkResult, LogType.LOG_API,
      ErrorLevel.MIDDLE);
  }
}
exports.checkAPINameOfHump = checkAPINameOfHump;

function checkAPIFileName(sourcefile, fileName) {
  if (fileName.indexOf('component\\ets\\') < 0 && fileName.indexOf('component/ets/') < 0) {
    let moduleName = '';
    let exportAssignment = '';
    sourcefile.statements.forEach(statement => {
      if (ts.isModuleDeclaration(statement) && statement.name && ts.isIdentifier(statement.name)) {
        moduleName = statement.name.escapedText.toString();
      }
      if (ts.isExportAssignment(statement) && statement.expression && ts.isIdentifier(statement.expression)) {
        exportAssignment = statement.expression.escapedText.toString();
      }
    });
    const basename = path.basename(fileName).replace(/\.d\.ts$/, '');
    const lastModuleName = basename.split('.').pop();
    let checkResult = '';

    if (moduleName !== '' && exportAssignment === moduleName && !checkSmallHump(lastModuleName)) {
      checkResult = 'This API file should be named by small hump.';
    } else if (moduleName === '' && exportAssignment !== moduleName && !checkLargeHump(lastModuleName)) {
      checkResult = 'This API file should be named by large hump.';
    }
    if (checkResult !== '' && filterApiVersion(sourcefile, getCheckApiVersion())) {
      addAPICheckErrorLogs(sourcefile, sourcefile, fileName, ErrorType.NAMING_ERRORS, checkResult, LogType.LOG_FILE,
        ErrorLevel.MIDDLE);
    }
  }
}
exports.checkAPIFileName = checkAPIFileName;
