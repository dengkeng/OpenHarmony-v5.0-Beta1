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
const fs = require('fs');
const path = require('path');
const ExcelJS = require('exceljs');
const cm = require('comment-parser');
function requireTypescriptModule() {
  const buildOption = require('./build.json');
  if (buildOption.isBundle) {
    return require('typescript');
  }
  const tsPathArray = [
    path.resolve(__dirname, '../node_modules/typescript'),
    path.resolve(__dirname, '../../node_modules/typescript')
  ];
  if (fs.existsSync(tsPathArray[0])) {
    return require(tsPathArray[0]);
  } else if (fs.existsSync(tsPathArray[1])) {
    return require(tsPathArray[1]);
  }
  return null;
}
exports.requireTypescriptModule = requireTypescriptModule;
const ts = requireTypescriptModule();

const commentNodeWhiteList = [
  ts.SyntaxKind.PropertySignature, ts.SyntaxKind.CallSignature, ts.SyntaxKind.MethodSignature,
  ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.EnumMember, ts.SyntaxKind.VariableStatement,
  ts.SyntaxKind.PropertyDeclaration, ts.SyntaxKind.Constructor, ts.SyntaxKind.ModuleDeclaration,
  ts.SyntaxKind.NamespaceExportDeclaration, ts.SyntaxKind.ClassDeclaration, ts.SyntaxKind.InterfaceDeclaration,
  ts.SyntaxKind.EnumDeclaration, ts.SyntaxKind.Parameter, ts.SyntaxKind.TypeLiteral, ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.LabeledStatement, ts.SyntaxKind.TypeAliasDeclaration
];
exports.commentNodeWhiteList = commentNodeWhiteList;

const tagsArrayOfOrder = [
  'namespace', 'struct', 'extends', 'implements', 'typedef', 'interface', 'permission', 'enum', 'constant', 'type',
  'param', 'default', 'returns', 'readonly', 'throws', 'static', 'fires', 'syscap', 'systemapi', 'famodelonly',
  'FAModelOnly', 'stagemodelonly', 'StageModelOnly', 'crossplatform', 'form', 'atomicservice', 'since', 'deprecated',
  'useinstead', 'test', 'form', 'example'
];
exports.tagsArrayOfOrder = tagsArrayOfOrder;

const fileTagOrder = ['file', 'kit'];
exports.fileTagOrder = fileTagOrder;

function getAPINote(node) {
  const apiLength = node.getText().length;
  const apiFullLength = node.getFullText().length;
  return node.getFullText().substring(0, apiFullLength - apiLength);
}
exports.getAPINote = getAPINote;

function hasAPINote(node) {
  if (!node) {
    return false;
  }
  const apiNote = getAPINote(node).replace(/[\s]/g, '');
  if (apiNote && apiNote.length !== 0) {
    return true;
  }
  return false;
}
exports.hasAPINote = hasAPINote;

function removeDir(url) {
  const statObj = fs.statSync(url);
  if (statObj.isDirectory()) {
    let dirs = fs.readdirSync(url);
    dirs = dirs.map(dir => path.join(url, dir));
    for (let i = 0; i < dirs.length; i++) {
      removeDir(dirs[i]);
    }
    fs.rmdirSync(url);
  } else {
    fs.unlinkSync(url);
  }
}
exports.removeDir = removeDir;

function writeResultFile(resultData, outputPath, option) {
  const STANDARD_INDENT = 2;
  fs.writeFile(path.resolve(__dirname, outputPath), JSON.stringify(resultData, null, STANDARD_INDENT), option, err => {
    if (err) {
      console.error(`ERROR FOR CREATE FILE:${err}`);
    } else {
      console.log('API CHECK FINISH!');
    }
  });
}
exports.writeResultFile = writeResultFile;

function overwriteIndexOf(item, array) {
  const indexArr = [];
  for (let i = 0; i < array.length; i++) {
    if (array[i] === item) {
      indexArr.push(i);
    }
  }
  return indexArr;
}
exports.overwriteIndexOf = overwriteIndexOf;

const ErrorType = {
  UNKNOW_DECORATOR: {
    id: 0,
    description: 'unknow decorator',
  },
  MISSPELL_WORDS: {
    id: 1,
    description: 'misspell words',
  },
  NAMING_ERRORS: {
    id: 2,
    description: 'naming errors',
  },
  UNKNOW_PERMISSION: {
    id: 3,
    description: 'unknow permission',
  },
  UNKNOW_SYSCAP: {
    id: 4,
    description: 'unknow syscap',
  },
  UNKNOW_DEPRECATED: {
    id: 5,
    description: 'unknow deprecated',
  },
  WRONG_ORDER: {
    id: 6,
    description: 'wrong order',
  },
  WRONG_VALUE: {
    id: 7,
    description: 'wrong value',
  },
  WRONG_SCENE: {
    id: 8,
    description: 'wrong scene',
  },
  PARAMETER_ERRORS: {
    id: 9,
    description: 'wrong parameter',
  },
  API_PAIR_ERRORS: {
    id: 10,
    description: 'limited api pair errors',
  },
  ILLEGAL_ANY: {
    id: 11,
    description: 'illegal any',
  },
  API_CHANGE_ERRORS: {
    id: 12,
    description: 'api change errors',
  },
};
exports.ErrorType = ErrorType;

const LogType = {
  LOG_API: 'Api',
  LOG_JSDOC: 'JsDoc',
  LOG_FILE: 'File',
};
exports.LogType = LogType;

const ErrorLevel = {
  HIGH: 3,
  MIDDLE: 2,
  LOW: 1,
};
exports.ErrorLevel = ErrorLevel;

const FileType = {
  API: 'Api',
  JSDOC: 'JsDoc',
};
exports.FileType = FileType;

const apiCheckArr = [];
exports.apiCheckArr = apiCheckArr;

const apiCheckInfoArr = [];
exports.apiCheckInfoArr = apiCheckInfoArr;

class ApiCheckResultClass {
  formatCheckResult = true;
}
exports.ApiCheckResult = new ApiCheckResultClass();

async function excelApiCheckResult(apiCheckArr) {
  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet('Js Api', { views: [{ xSplit: 1 }] });
  sheet.getRow(1).values = ['order', 'errorType', 'fileName', 'apiName', 'apiContent', 'type', 'errorInfo', 'version', 'model'];
  for (let i = 1; i <= apiCheckArr.length; i++) {
    const apiData = apiCheckArr[i - 1];
    sheet.getRow(i + 1).values = [i, apiData.errorType, apiData.fileName, apiData.apiName, apiData.apiFullText,
      apiData.type, apiData.errorInfo, apiData.version, apiData.basename];
  }
  const buffer = await workbook.xlsx.writeBuffer();
  fs.writeFile('Js_Api.xlsx', buffer, function (err) {
    if (err) {
      console.error(err);
      return;
    }
  });
  return buffer;
}
exports.excelApiCheckResult = excelApiCheckResult;

function getApiInfo(node) {
  const notesStr = getAPINote(node);
  const apiInfo = {};
  const versionArr = [];
  if (notesStr !== '') {
    if (/\@systemapi/g.test(notesStr)) {
      apiInfo.isSystemApi = 'system api';
    }
    if (/\@constant/g.test(notesStr)) {
      apiInfo.isConstant = true;
    }
    if (/\@since\s*(\d+)/g.test(notesStr)) {
      notesStr.replace(/\@since\s*(\d+)/g, (versionInfo) => {
        versionArr.push(versionInfo);
        apiInfo.version = versionInfo.replace(/\@since/g, '').trim();
      });
      apiInfo.humpVersion = versionArr[0].replace(/\@since/g, '').trim();
    }
    if (/\@deprecated.*since\s*(\d+)/g.test(notesStr)) {
      notesStr.replace(/\@deprecated.*since\s*(\d+)/g,
        versionInfo => {
          apiInfo.deprecated = versionInfo.replace(
            /\@deprecated.*since\s*/g, '').trim();
        });
    }
    if (/\@famodelonly/g.test(notesStr)) {
      notesStr.replace(/\@famodelonly/g, modelInfo => {
        apiInfo.model = modelInfo;
      });
    } else if (/\@stagemodelonly/g.test(notesStr)) {
      notesStr.replace(/\@stagemodelonly/g, modelInfo => {
        apiInfo.model = modelInfo;
      });
    }
    if (/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(notesStr)) {
      notesStr.replace(/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g, sysCapInfo => {
        apiInfo.sysCap = sysCapInfo.replace(/\@syscap/g, '').trim();
      });
    }
    if (/\@permission\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(notesStr)) {
      notesStr.replace(/\@permission\s*((\w|\.|\/|\{|\@|\}|\s)+)/g,
        permissionInfo => {
          apiInfo.permission =
            permissionInfo.replace(/\@permission/g, '').trim();
        });
    }
  }
  return apiInfo;
}
exports.getApiInfo = getApiInfo;

function getApiVersion(node) {
  if (getApiInfo(node).humpVersion) {
    return getApiInfo(node).humpVersion;
  } else if (node.parent && !ts.isSourceFile(node.parent)) {
    return getApiVersion(node.parent);
  } else {
    return 'NA';
  }
}
exports.getApiVersion = getApiVersion;

function parseJsDoc(node) {
  if (!hasAPINote(node)) {
    return [];
  } else {
    return cm.parse(getAPINote(node));
  }
}
exports.parseJsDoc = parseJsDoc;

function getDeclareValue(declareValue) {
  let apiDeclareValue = '';
  if (!declareValue) {
    return apiDeclareValue;
  }
  if (ts.isFunctionTypeNode(declareValue)) {
    apiDeclareValue = 'Function';
  } else if (ts.isTypeLiteralNode(declareValue)) {
    apiDeclareValue = 'object';
  } else {
    apiDeclareValue = declareValue.getText().replace(/\n|\r|\s/g, '');
  }
  return apiDeclareValue;
}
exports.getDeclareValue = getDeclareValue;

const systemPermissionFile = path.resolve(__dirname, '../../../../../',
  'base/global/system_resources/systemres/main/module.json');

exports.systemPermissionFile = systemPermissionFile;

exports.checkOption = {
  permissionContent: undefined,
};

const inheritArr = ['test', 'famodelonly', 'FAModelOnly', 'stagemodelonly', 'StageModelOnly', 'deprecated',
  'systemapi'];
exports.inheritArr = inheritArr;

const ErrorValueInfo = {
  ERROR_INFO_VALUE_EXTENDS: 'the [extends] tag value is incorrect. Please check if the tag value matches the inherited class name.',
  ERROR_INFO_VALUE_ENUM: 'the [enum] tag type is incorrect. Please check if the tag type is { string } or { number }',
  ERROR_INFO_VALUE_SINCE: 'the [since] tag value is incorrect. Please check if the tag value is a numerical value',
  ERROR_INFO_RETURNS: 'the [returns] tag was used incorrectly. The returns tag should not be used when the return type is void',
  ERROR_INFO_VALUE_RETURNS: 'the [returns] tag type is incorrect. Please check if the tag type is consistent with the return type',
  ERROR_INFO_VALUE_USEINSTEAD: 'the [useinstead] tag value is incorrect. Please check the usage method',
  ERROR_INFO_VALUE_TYPE: 'the [type] tag type is incorrect. Please check if the type matches the attribute type',
  ERROR_INFO_VALUE_DEFAULT: 'the [default] tag value is incorrect. Please supplement the default value',
  ERROR_INFO_VALUE_PERMISSION: 'the [permission] tag value is incorrect. Please check if the permission field has been configured or update the configuration file',
  ERROR_INFO_VALUE_DEPRECATED: 'the [deprecated] tag value is incorrect. Please check the usage method',
  ERROR_INFO_VALUE_SYSCAP: 'the [syscap] tag value is incorrect. Please check if the syscap field is configured',
  ERROR_INFO_VALUE_NAMESPACE: 'the [namespace] tag value is incorrect. Please check if it matches the namespace name',
  ERROR_INFO_VALUE_INTERFACE: 'the [interface] label value is incorrect. Please check if it matches the interface name',
  ERROR_INFO_VALUE_TYPEDEF: 'the [typedef] tag value is incorrect. Please check if it matches the interface name',
  ERROR_INFO_TYPE_PARAM: 'the type of the [$$] [param] tag is incorrect. Please check if it matches the type of the [$$] parameter',
  ERROR_INFO_VALUE_PARAM: 'the value of the [$$] [param] tag is incorrect. Please check if it matches the [$$] parameter name',
  ERROR_INFO_VALUE1_THROWS: 'the type of the [$$] [throws] tag is incorrect. Please fill in [BusinessError]',
  ERROR_INFO_VALUE2_THROWS: 'the type of the [$$] [throws] tag is incorrect. Please check if the tag value is a numerical value',
  ERROR_INFO_INHERIT: 'it was detected that there is an inheritable label [$$] in the current file, but there are child nodes without this label',
  ERROR_ORDER: 'JSDoc label order error, please make adjustments',
  ERROR_LABELNAME: 'the [$$] tag does not exist. Please use a valid JSDoc tag',
  ERROR_LOST_LABEL: 'JSDoc tag validity verification failed. Please confirm if the [$$] tag is missing',
  ERROR_USE: 'JSDoc label validity verification failed. The [$$] label is not allowed. Please check the label usage method.',
  ERROR_MORELABEL: 'JSDoc tag validity verification failed. The [$$] [$$] tag is redundant. Please check if the tag should be deleted.',
  ERROR_REPEATLABEL: 'the validity verification of the JSDoc tag failed. The [$$] tag is not allowed to be reused, please delete the extra tags',
  ERROR_USE_INTERFACE: 'the validity verification of the JSDoc tag failed. The [interface] tag and [typedef] tag are not allowed to be used simultaneously. Please confirm the interface class.',
  ERROR_EVENT_NAME_STRING: 'The event name should be string.',
  ERROR_EVENT_NAME_NULL: 'The event name cannot be Null value.',
  ERROR_EVENT_NAME_SMALL_HUMP: 'The event name should be named by small hump. (Received [\'$$\'])',
  ERROR_EVENT_CALLBACK_OPTIONAL: 'The callback parameter of off function should be optional.',
  ERROR_EVENT_CALLBACK_MISSING: 'The off functions of one single event should have at least one callback parameter, and the callback parameter should be the last parameter.',
  ERROR_EVENT_ON_AND_OFF_PAIR: 'The on and off event subscription methods do not appear in pair.',
  ILLEGAL_USE_ANY: 'Illegal [any] keyword used in the API',
  ERROR_CHANGES_VERSION: 'Please check if the changed API version number is $$.',
  ERROR_CHANGES_API_HISTORY_PARAM_REQUIRED_CHANGE: 'Forbid changes: Optional parameters cannot be changed to required parameters.',
  ERROR_CHANGES_API_HISTORY_PARAM_RANGE_CHANGE: 'Forbid changes: Parameters type range cannot be reduced.',
  ERROR_CHANGES_API_HISTORY_PARAM_WITHOUT_TYPE_CHANGE: 'Forbid changes: Parameters Parameter must be defined by type.',
  ERROR_CHANGES_API_HISTORY_PARAM_TYPE_CHANGE: 'Forbid changes: Parameters type cannot be modified.',
  ERROR_CHANGES_API_HISTORY_PARAM_POSITION_CHANGE: 'Forbid changes: Parameters position not be allowed to be modified.',
  ERROR_CHANGES_API_NEW_REQUIRED_PARAM: 'Forbid changes: Required parameters cannot be created.',
  ERROR_CHANGES_API_DELETE_PARAM: 'Forbid changes: Parameters cannot be deleted.',
  ERROR_CHANGES_DEPRECATED: 'Forbid changes: The api has deprecated tag.',
  ERROR_CHANGES_JSDOC_NUMBER: 'Forbid changes: API changes must add a new section of JSDoc.',
  ERROR_CHANGES_JSDOC_CHANGE: 'Forbid changes: Previous JSDoc cannot be changed.',
  ERROR_CHANGES_JSDOC_TRROWS: 'Forbid changes: Throws tag cannot be created.',
  ERROR_CHANGES_JSDOC_PERMISSION: 'Forbid changes: Permission tag cannot be created or modified.',
  ERROR_FILE_TAG_ORDER: 'File tags order is incorrect.',
};
exports.ErrorValueInfo = ErrorValueInfo;

const DIFF_INFO = {
  NEW_JSDOCS_LENGTH: 1,
  NEW_JSDOC_INDEX: 2,
};
exports.DIFF_INFO = DIFF_INFO;

/**
 * link error message
 */
function createErrorInfo(errorInfo, params) {
  params.forEach((param) => {
    errorInfo = errorInfo.replace('$$', param);
  });
  return errorInfo;
}
exports.createErrorInfo = createErrorInfo;

/**
 * judge if it is an API file for Arkui
 */
function isArkUIApiFile(fileName) {
  if (fileName.indexOf('component\\ets\\') >= 0 || fileName.indexOf('component/ets/') >= 0) {
    return true;
  }
  return false;
}
exports.isArkUIApiFile = isArkUIApiFile;

function isWhiteListFile(fileName, whiteList) {
  for (let i = 0; i < whiteList.length; i++) {
    if (path.normalize(fileName).indexOf(path.normalize(whiteList[i])) !== -1) {
      return true;
    }
  }
  return false;
}
exports.isWhiteListFile = isWhiteListFile;

function getCheckApiVersion() {
  const packageJsonPath = path.join(__dirname, '../package.json');
  let packageJson;
  let checkApiVersion;
  try {
    const packageJsonContent = fs.readFileSync(packageJsonPath, 'utf8');
    packageJson = JSON.parse(packageJsonContent);
    checkApiVersion = packageJson.checkApiVersion;
  } catch (error) {
    throw `Failed to read package.json or parse JSON content: ${error}`;
  }
  if (!checkApiVersion) {
    throw 'Please configure the correct API version to be verified';
  }
  return checkApiVersion;
}
exports.getCheckApiVersion = getCheckApiVersion;

const OptionalSymbols = {
  QUERY: '?',
  LEFT_BRACKET: '[',
  RIGHT_BRACKET: ']',
  LEFT_BRACE: '{',
  RIGHT_BRACE: '}',
  LEFT_PARENTHESES: '(',
  RIGHT_PARENTHESES: ')'
};
exports.OptionalSymbols = OptionalSymbols;

function removeDuplicateObj(array) {
  const newArr = [];
  const errorInfoSet = new Set();
  for (const errorInfo of array) {
    if (!errorInfoSet.has(JSON.stringify(errorInfo))) {
      errorInfoSet.add(JSON.stringify(errorInfo));
      newArr.push(errorInfo);
    }
  }
  return newArr;
};
exports.removeDuplicateObj = removeDuplicateObj;

// check the api version
function checkVersionNeedCheck(node) {
  const apiVersion = getApiVersion(node);
  const apiCheckVersion = getCheckApiVersion();
  if (parseInt(apiVersion) >= parseInt(apiCheckVersion)) {
    return true;
  }
  return false;
}
exports.checkVersionNeedCheck = checkVersionNeedCheck;

const FUNCTION_TYPES = [ts.SyntaxKind.FunctionDeclaration, ts.SyntaxKind.MethodSignature,
ts.SyntaxKind.MethodDeclaration, ts.SyntaxKind.CallSignature, ts.SyntaxKind.Constructor];
exports.FUNCTION_TYPES = FUNCTION_TYPES;

function splitPath(filePath, pathElements) {
  let spliteResult = path.parse(filePath);
  if (spliteResult.base !== '') {
    pathElements.add(spliteResult.base);
    splitPath(spliteResult.dir, pathElements);
  }
}
exports.splitPath = splitPath;

function isAscending(arr) {
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] < arr[i - 1]) {
      return false;
    }
  }
  return true;
}
exports.isAscending = isAscending;