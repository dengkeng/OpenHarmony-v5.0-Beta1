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
const { exportDiffInfo } = require('../../api_diff/src/api_diff');
const { StatusCode } = require('../../api_diff/src/reporter');
const {
  parseJsDoc,
  requireTypescriptModule,
  ErrorType,
  LogType,
  ErrorLevel,
  ErrorValueInfo,
  getCheckApiVersion,
  FUNCTION_TYPES,
  DIFF_INFO,
  createErrorInfo
} = require('./utils');
const ts = requireTypescriptModule();
const { addAPICheckErrorLogs } = require('./compile_info');

const changeErrors = [];

/**
 * 检查历史JSDoc是否一致
 * @param {array} newNodeJSDocs 修改后API节点JSDoc数组
 * @param {array} oldNodeJSDocs 修改前API节点JSDoc数组
 * @returns {boolean}
 */
function checkHistoryJSDoc(newNodeJSDocs, oldNodeJSDocs) {
  let checkEndJSDocIndex = isNewApi(oldNodeJSDocs) ? 1 : 0;
  for (let i = 0; i < oldNodeJSDocs.length - checkEndJSDocIndex; i++) {
    const oldDescription = oldNodeJSDocs[i].description;
    const oldTags = oldNodeJSDocs[i].tags;
    const newDescription = newNodeJSDocs[i].description;
    const newTags = newNodeJSDocs[i].tags;
    if (oldDescription !== newDescription || oldTags.length !== newTags.length) {
      return false;
    }
    for (let j = 0; j < oldTags.length; j++) {
      const oldTag = oldTags[j];
      const newTag = newTags[j];
      if (
        oldTag.tag !== newTag.tag ||
        oldTag.name !== newTag.name ||
        oldTag.type !== newTag.type ||
        oldTag.optional !== newTag.optional ||
        oldTag.description !== newTag.description
      ) {
        return false;
      }
    }
  }
  return true;
}

/**
 * 根据JSDoc获取版本号
 * @param {JSDoc} JSDoc
 * @returns {number}
 */
function getJSDocVersion(JSDoc) {
  if (JSDoc) {
    for (let i = 0; i < JSDoc.tags.length; i++) {
      if (JSDoc.tags[i].tag === 'since') {
        return JSDoc.tags[i].name;
      }
    }
  }
  return NaN;
}

/**
 * 检查API变更版本是否正确
 * @param {JSDoc} currentJSDoc 修改后API节点JSDoc
 * @param {JSDoc} lastJSDoc 修改前API节点JSDoc
 * @param {ts.Node} node 修改后API节点
 */
function checkApiChangeVersion(currentJSDoc, lastJSDoc, node) {
  const currentVersion = getJSDocVersion(currentJSDoc);
  const lastVersion = getJSDocVersion(lastJSDoc);
  const checkApiVersion = getCheckApiVersion();
  if (lastVersion === 0 || currentVersion !== checkApiVersion) {
    changeErrors.push({
      node: node,
      errorInfo: createErrorInfo(ErrorValueInfo.ERROR_CHANGES_VERSION, [checkApiVersion]),
      LogType: LogType.LOG_JSDOC,
    });
  }
}

/**
 * 检查JSDoc变更
 * @param {string} tagName 标签名称
 * @param {JSDoc} currentJSDoc 修改后API节点JSDoc
 * @param {JSDoc} lastJSDoc 修改前API节点JSDoc
 * @param {function} customCheckCallback 自定义检查规则
 */
function checkJSDocChange(tagName, currentJSDoc, lastJSDoc, customCheckCallback) {
  const newTagValue = [];
  const oldTagValue = [];
  const addTags = [];
  if (currentJSDoc) {
    currentJSDoc.tags.forEach(tag => {
      if (tag.tag === tagName) {
        newTagValue.push(tag.name);
      }
    });
  }
  if (lastJSDoc) {
    lastJSDoc.tags.forEach(tag => {
      if (tag.tag === tagName) {
        oldTagValue.push(tag.name);
      }
    });
  }
  newTagValue.forEach(newValue => {
    if (!new Set(oldTagValue).has(newValue)) {
      addTags.push(newValue);
    }
  });

  customCheckCallback(newTagValue, oldTagValue, addTags);
}

/**
 * 检查权限变化
 * @param { string } newPermission
 * @param { string } oldPermission
 * @returns { boolean }
 */
function checkPermissionChange(newPermission, oldPermission) {
  const permissionChange = newPermission.replace(oldPermission, '');
  return !newPermission.includes(oldPermission) || /\band\b/.test(permissionChange);
}

/**
 * 检查JSDoc变更
 * @param {array} newNodeJSDocs 修改后API节点JSDoc列表
 * @param {enum} statusCode api_diff工具返回的变更状态
 * @param {ts.Node} node 修改后API节点
 */
function checkCurrentJSDocChange(newNodeJSDocs, statusCode, node) {
  const currentJSDoc = newNodeJSDocs[newNodeJSDocs.length - 1];
  const lastJSDoc =
    newNodeJSDocs.length === DIFF_INFO.NEW_JSDOCS_LENGTH
      ? null
      : newNodeJSDocs[newNodeJSDocs.length - DIFF_INFO.NEW_JSDOC_INDEX];

  checkApiChangeVersion(currentJSDoc, lastJSDoc, node);

  if (statusCode === StatusCode.ERRORCODE_CHANGES || statusCode === StatusCode.NEW_ERRORCODE) {
    checkJSDocChange('throws', currentJSDoc, lastJSDoc, (newTagValue, oldTagValue, addTags) => {
      if (addTags.length !== 0 && oldTagValue.length === 0) {
        changeErrors.push({
          node: node,
          errorInfo: ErrorValueInfo.ERROR_CHANGES_JSDOC_TRROWS,
          LogType: LogType.LOG_JSDOC,
        });
      }
    });
  } else if (statusCode === StatusCode.PERMISSION_CHANGES) {
    checkJSDocChange('permission', currentJSDoc, lastJSDoc, (newTagValue, oldTagValue, addTags) => {
      let checkResult = true;
      // 从无到有新增权限
      checkResult = !(newTagValue.length === 1 && oldTagValue.length === 0);
      // 权限值变更
      if (newTagValue.length === 1 && oldTagValue.length === 1) {
        const newPermission = newTagValue[0];
        const oldPermission = oldTagValue[0];
        checkResult = checkResult && 
          !(newPermission !== oldPermission && checkPermissionChange(newPermission, oldPermission));
      }

      if (!checkResult) {
        changeErrors.push({
          node: node,
          errorInfo: ErrorValueInfo.ERROR_CHANGES_JSDOC_PERMISSION,
          LogType: LogType.LOG_JSDOC,
        });
      }
    });
  }
}

/**
 * 检查API历史版本JSDoc是否包含废弃标签
 *
 * @param {array} historyJSDocs 历史接口JSDoc信息
 * @returns {boolean}
 */
function checkApiDeprecatedStatus(historyJSDocs) {
  for (let i = 0; i < historyJSDocs.length; i++) {
    const doc = historyJSDocs[i];
    for (let j = 0; j < doc.tags.length; j++) {
      const tag = doc.tags[j];
      if (tag === 'deprecated') {
        return true;
      }
    }
  }
  return false;
}

/**
 * 检查JSDoc变更内容
 * @param {array} newNodeJSDocs 修改后API节点JSDoc数组
 * @param {array} oldNodeJSDocs 修改前API节点JSDoc数组
 * @param {object} change api_diff获取的变更数据
 */
function checkJSDocChangeInfo(newNodeJSDocs, oldNodeJSDocs, change) {
  if (checkApiDeprecatedStatus(oldNodeJSDocs)) {
    changeErrors.push({
      node: change.newNode,
      errorInfo: ErrorValueInfo.ERROR_CHANGES_DEPRECATED,
      LogType: LogType.LOG_JSDOC,
    });
  }
  if (newNodeJSDocs.length !== oldNodeJSDocs.length + 1 && !isNewApi(oldNodeJSDocs)) {
    changeErrors.push({
      node: change.newNode,
      errorInfo: ErrorValueInfo.ERROR_CHANGES_JSDOC_NUMBER,
      LogType: LogType.LOG_JSDOC,
    });
  } else if (!checkHistoryJSDoc(newNodeJSDocs, oldNodeJSDocs)) {
    changeErrors.push({
      node: change.newNode,
      errorInfo: ErrorValueInfo.ERROR_CHANGES_JSDOC_CHANGE,
      LogType: LogType.LOG_JSDOC,
    });
  } else {
    checkCurrentJSDocChange(newNodeJSDocs, change.statusCode, change.newNode);
  }
}

/**
 * 检查JSDoc变更
 * @param {object} change api_diff获取的变更数据
 */
function checkJSDocChangeEntry(change) {
  const newNodeJSDocs = parseJsDoc(change.newNode);
  const oldNodeJSDocs = parseJsDoc(change.oldNode);

  checkJSDocChangeInfo(newNodeJSDocs, oldNodeJSDocs, change);
}

/**
 * 解析接口参数类型数据
 * @param {array} paramType 接口参数类型
 * @returns {array}
 */
function analysisParamType(paramType) {
  const types = [];
  if (paramType.kind === ts.SyntaxKind.UnionType) {
    paramType.types.forEach(type => {
      types.push(type.getText());
    });
  } else {
    types.push(paramType.getText());
  }
  return types;
}

/**
 * 检查API接口历史参数
 * @param {array} currentParameters 修改后API节点参数
 * @param {array} lastParameters 修改前API节点参数
 */
function checkHistoryParameters(currentParameters, lastParameters, change) {
  for (let i = currentParameters.length - 1; i >= 0; i--) {
    const historyParamType = analysisParamType(lastParameters[i].type);
    const currentParamType = analysisParamType(currentParameters[i].type);

    // 拦截可选变必选
    if (currentParameters[i].isRequired && !lastParameters[i].isRequired) {
      changeErrors.push({
        node: change.newNode,
        errorInfo: ErrorValueInfo.ERROR_CHANGES_API_HISTORY_PARAM_REQUIRED_CHANGE,
        LogType: LogType.LOG_API,
      });
    }

    // 变更后参数无类型定义
    if (currentParamType.length === 0) {
      changeErrors.push({
        node: change.newNode,
        errorInfo: ErrorValueInfo.ERROR_CHANGES_API_HISTORY_PARAM_WITHOUT_TYPE_CHANGE,
        LogType: LogType.LOG_API,
      });
      // 变更后参数范围大于等于变更前
    } else if (currentParamType.length >= historyParamType.length) {
      checkHistoryParametersType(historyParamType, currentParamType, changeErrors, change);
      // 变更后参数范围小于变更前
    } else {
      changeErrors.push({
        node: change.newNode,
        errorInfo: ErrorValueInfo.ERROR_CHANGES_API_HISTORY_PARAM_RANGE_CHANGE,
        LogType: LogType.LOG_API,
      });
    }
  }

  // 拦截参数位置变更
  for (let i = 0; i < currentParameters.length; i++) {
    for (let j = 0; j < lastParameters.length; j++) {
      if (
        currentParameters[i].paramName === lastParameters[j].paramName &&
        currentParameters[i].order !== lastParameters[j].order
      ) {
        changeErrors.push({
          node: change.newNode,
          errorInfo: ErrorValueInfo.ERROR_CHANGES_API_HISTORY_PARAM_POSITION_CHANGE,
          LogType: LogType.LOG_API,
        });
      }
    }
  }
}

function checkHistoryParametersType(historyParamType, currentParamType, changeErrors, change) {
  for (let j = 0; j < historyParamType.length; j++) {
    if (!new Set(currentParamType).has(historyParamType[j])) {
      changeErrors.push({
        node: change.newNode,
        errorInfo: ErrorValueInfo.ERROR_CHANGES_API_HISTORY_PARAM_TYPE_CHANGE,
        LogType: LogType.LOG_API,
      });
    }
  }
}

/**
 * 检查API接口新增参数
 * @param {array} parameters 新增参数列表
 */
function checkCurrentParameters(parameters, change) {
  for (let i = 0; i < parameters.length; i++) {
    if (parameters[i].isRequired) {
      changeErrors.push({
        node: change.newNode,
        errorInfo: ErrorValueInfo.ERROR_CHANGES_API_NEW_REQUIRED_PARAM,
        LogType: LogType.LOG_API,
      });
      break;
    }
  }
}

/**
 * 解析接口参数数据
 * @param {array} params tsNode参数列表
 * @returns {array}
 */
function analysisParameters(params) {
  const paramInfoData = [];
  params.forEach((param, index) => {
    const data = {
      paramName: param.name ? param.name.getText() : '',
      order: index,
      isRequired: param.questionToken && param.questionToken.kind === ts.SyntaxKind.QuestionToken ? false : true,
      type: param.type,
    };
    paramInfoData.push(data);
  });
  return paramInfoData;
}

/**
 * 判断是否为新增接口或已变更为最新版本接口
 * @param {array} oldNodeJSDocs 修改前API节点JSDoc数组
 */
function isNewApi(oldNodeJSDocs) {
  const checkApiVersion = getCheckApiVersion();
  const oldNodeVersion = getJSDocVersion(oldNodeJSDocs[oldNodeJSDocs.length - 1]);

  if (oldNodeVersion === checkApiVersion) {
    return true;
  }
  return false;
}

/**
 * 检查API变更
 * @param {object} change api_diff获取的变更数据
 */
function checkApiChangeEntry(change) {
  // 检查JSDoc
  const newNodeJSDocs = parseJsDoc(change.newNode);
  const oldNodeJSDocs = parseJsDoc(change.oldNode);

  checkJSDocChangeInfo(newNodeJSDocs, oldNodeJSDocs, change);

  // 新增接口不检查接口变更
  if (isNewApi(oldNodeJSDocs) && oldNodeJSDocs.length === 1) {
    return;
  }
  const currentParameters = analysisParameters(change.newNode.parameters);
  const lastParameters = analysisParameters(change.oldNode.parameters);

  if (currentParameters.length === lastParameters.length) {
    checkHistoryParameters(currentParameters, lastParameters, change);
  } else if (currentParameters.length > lastParameters.length) {
    if (lastParameters.length !== 0) {
      checkHistoryParameters(currentParameters.slice(0, lastParameters.length), lastParameters, change);
    }
    checkCurrentParameters(currentParameters.slice(lastParameters.length, currentParameters.length), change);
  } else {
    changeErrors.push({
      node: change.newNode,
      errorInfo: ErrorValueInfo.ERROR_CHANGES_API_DELETE_PARAM,
      LogType: LogType.LOG_API,
    });
  }
}

/**
 * 分析变更内容
 * @param {array} changes api_diff获取的变更数据列表
 */
function analyseChanges(changes) {
  const functionTypeSet = new Set(FUNCTION_TYPES);
  changes.forEach(change => {
    if (
      change.statusCode === StatusCode.ERRORCODE_CHANGES ||
      change.statusCode === StatusCode.NEW_ERRORCODE ||
      change.statusCode === StatusCode.PERMISSION_CHANGES
    ) {
      checkJSDocChangeEntry(change);
    } else if (
      change.statusCode === StatusCode.FUNCTION_CHANGES &&
      functionTypeSet.has(change.oldNode.kind) &&
      functionTypeSet.has(change.newNode.kind)
    ) {
      checkApiChangeEntry(change);
    }
  });
}

/**
 * 封装错误信息
 */
function logChangeErrors() {
  changeErrors.forEach(error => {
    const sourceFileNode = ts.getSourceFileOfNode(error.node);
    addAPICheckErrorLogs(
      error.node,
      sourceFileNode,
      sourceFileNode.fileName,
      ErrorType.API_CHANGE_ERRORS,
      error.errorInfo,
      error.LogType,
      ErrorLevel.MIDDLE
    );
  });
}

/**
 * API变更检查入口
 */
function checkApiChanges(prId) {
  let isApiChanged = false;
  const oldFiles = [];
  // 编译流水线根目录
  const rootDir = path.resolve(__dirname, `../../../../../Archive/patch_info/openharmony_interface_sdk-js_${prId}`);
  if (!fs.existsSync(rootDir)) {
    return;
  }
  const oldApiPath = path.resolve(rootDir, './old');
  const newFiles = [];
  const newApiPath = path.resolve(rootDir, './new');
  const fileNames = fs.readdirSync(rootDir);
  let patchConfigPath = '';
  for (let i = 0; i < fileNames.length; i++) {
    if (/\.json$/.test(fileNames[i])) {
      patchConfigPath = path.resolve(rootDir, fileNames[i]);
      break;
    }
  }
  const patchConfig = JSON.parse(fs.readFileSync(patchConfigPath));
  for (const file in patchConfig) {
    // 判断为文件修改
    if (patchConfig[file] === 'M' && /\.d\.ts$/.test(file)) {
      const oldMdFilePath = path.resolve(oldApiPath, file);
      const newMdFilePath = path.resolve(newApiPath, file);

      if (fs.existsSync(oldMdFilePath) && fs.existsSync(newMdFilePath)) {
        oldFiles.push(oldMdFilePath);
        newFiles.push(newMdFilePath);
        isApiChanged = true;
      }
    }
  }

  if (isApiChanged) {
    const diffResult = exportDiffInfo(newFiles, oldFiles, newApiPath, oldApiPath);
    analyseChanges(diffResult);
    logChangeErrors();
  }
}
exports.checkApiChanges = checkApiChanges;
