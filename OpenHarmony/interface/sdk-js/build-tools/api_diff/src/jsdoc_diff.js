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

const ts = require('typescript');
const { ApiDigestInfo } = require('./api_data');
const { DiffReporter } = require('./reporter');
const { StatusCode } = require('./reporter');
const { getCheckApiVersion } = require('../../api_check_plugin/src/utils');

class TagItem {
  constructor() { }

  addSinceVersion(version) {
    this.setProperty('sinceVersion', version);
  }

  getSinceVersion() {
    return this.sinceVersion;
  }

  addSyscap(sysCap) {
    this.setProperty('sysCap', sysCap);
  }

  getSyscap() {
    return this.sysCap;
  }

  addAppModel(model) {
    this.setProperty('appModel', model);
  }

  getAppModel() {
    return this.appModel;
  }

  addDeprecated(deprecated) {
    this.setProperty('deprecated', deprecated);
  }

  getDeprecated() {
    return this.deprecated;
  }

  addErrorCode(errorCode) {
    this.setProperty('errorCode', errorCode);
  }

  getErrorCode() {
    return this.errorCode;
  }

  addApiLevel(level) {
    this.setProperty('apiLevel', level);
  }

  getApiLevel() {
    return this.apiLevel;
  }

  addTypeTag(type) {
    this.setProperty('type', type);
  }

  getTypeTag() {
    return this.type;
  }

  addUseInstead(useinstead) {
    this.setProperty('useinstead', useinstead);
  }

  getUseInstead() {
    return this.useinstead;
  }

  addPermission(permission) {
    this.setProperty('permission', permission);
  }

  getPermission() {
    return this.permission;
  }

  addForm(form) {
    this.setProperty('form', form);
  }

  getForm() {
    return this.form;
  }

  addCrossplatform(crossplatform) {
    this.setProperty('crossplatform', crossplatform);
  }

  getCrossplatform() {
    return this.crossplatform;
  }

  setProperty(name, value) {
    if (this[name]) {
      this[name].push(value);
    } else {
      this[name] = [value];
    }
  }
}

function isArrayEquals(first, second) {
  if (!first && !second) {
    return true;
  }
  const ret = first && second && first.length === second.length;
  if (ret) {
    first.sort();
    second.sort();
    for (let index = 0; index < first.length; index++) {
      if (first[index] !== second[index]) {
        return false;
      }
    }
  }
  return ret;
}

function arrayToString(array) {
  if (!array || array.length === 0) {
    return '';
  }
  return array.join();
}

/**
 * 获取API @deprecated 标签信息, 继承父类
 * 
 * @param {ApiDigestInfo} api 
 * @returns {Array}
 */
function getApiDeprecated(api) {
  let curApi = api;
  while (curApi) {
    const jsdocTagItem = getTagItemFromJSDoc(curApi);
    if (jsdocTagItem.getDeprecated()) {
      return jsdocTagItem.getDeprecated();
    }
    curApi = curApi.getParent();
  }
  return [];
}

function matchSyscapInFile(api) {
  let syscap = getApiSyscap(api)[0];
  let curApi = api;
  while (!syscap && !ts.isSourceFile(curApi.node)) {
    curApi = curApi.getParent();
  }
  if (!syscap && ts.isSourceFile(curApi.node)) {
    const fileContent = curApi.node.getFullText();
    if (/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g.test(fileContent)) {
      fileContent.replace(/\@syscap\s*((\w|\.|\/|\{|\@|\}|\s)+)/g, sysCapInfo => {
        syscap = sysCapInfo.replace(/\@syscap/g, '').trim();
      });
    }
  }
  return syscap;
}

/**
 * 获取 API @syscap 标签信息，继承父类
 * 
 * @param {ApiDigestInfo} api 
 * @returns {Array}
 */
function getApiSyscap(api) {
  let curApi = api;
  while (curApi && !ts.isSourceFile(curApi.node)) {
    const jsdocTagItem = getTagItemFromJSDoc(curApi);
    if (jsdocTagItem.getSyscap()) {
      return jsdocTagItem.getSyscap();
    }
    curApi = curApi.getParent();
  }
  return [];
}

/**
 * 获取API @useinstead，继承父类
 * 
 * @param {ApiDigestInfo} api 
 * @returns {Array}
 */
function getApiUseInstead(api) {
  let curApi = api;
  while (curApi) {
    const jsdocTagItem = getTagItemFromJSDoc(curApi);
    if (jsdocTagItem.getUseInstead()) {
      return jsdocTagItem.getUseInstead();
    }
    curApi = curApi.getParent();
  }
  return [];
}

/**
 * 从 JSDoc 对象获取所有Tag标签信息
 * 
 * @param {ApiDigestInfo} api 
 * @returns {Object}
 */
function getTagItemFromJSDoc(api) {
  let jsdocTagItem = api.getJSDocTagItem();
  if (!jsdocTagItem) {
    jsdocTagItem = createTagItemFromJSDoc(api.jsdoc);
    api.setJSDocTagItem(jsdocTagItem);
  }
  return jsdocTagItem;
}

function wrapApiChanges(api, statusCode, oldMessage, newMessage, hint, oldNode, newNode, syscap) {
  return {
    api: api,
    statusCode: statusCode,
    oldMessage: oldMessage,
    newMessage: newMessage,
    hint: hint,
    oldNode: oldNode,
    newNode: newNode,
    syscap: syscap,
  };
}

/**
 * 比较JSDoc的差异
 * 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {DiffReporter} diffReporter 
 */
function compareJSDocs(oldApi, newApi, diffReporter) {
  const oldTagItem = getTagItemFromJSDoc(oldApi);
  const newTagItem = getTagItemFromJSDoc(newApi);
  const useinstead = getApiUseInstead(newApi);
  const hint = useinstead.length > 0 ? `useinstead: ${useinstead[0]}` : '';
  diffHistoricalJsDoc(oldApi, newApi, diffReporter, hint);
  diffErrorCode(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffPermission(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffForm(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffCrossplatform(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffDeprecated(diffReporter, oldApi, newApi, hint);
  diffApiLevel(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffAppModel(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
  diffType(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint);
}

function getLatestVersion(jsdocs) {
  let apiLatestVersion = '';
  if (!jsdocs || jsdocs.length === 0) {
    return apiLatestVersion;
  }
  const jsdoc = jsdocs[jsdocs.length - 1];
  jsdoc.tags?.forEach(tagObject => {
    if (tagObject.tag === 'since') {
      apiLatestVersion = tagObject.name;
    }
  });
  return apiLatestVersion;
}

function diffHistoricalJsDoc(oldApi, newApi, diffReporter, hint) {
  const currentVersion = getCheckApiVersion();
  const oldJsDocTextArr = oldApi.getAstNode().getFullText().replace(oldApi.getAstNode().getText(), '').split('*/');
  const newJsDocTextArr = newApi.getAstNode().getFullText().replace(oldApi.getAstNode().getText(), '').split('*/');
  if (!oldApi.jsdoc) {
    return;
  }
  const oldLatestVersion = getLatestVersion(oldApi.jsdoc);
  const newLatestVersion = getLatestVersion(newApi.jsdoc);
  if (oldLatestVersion === currentVersion) {
    oldJsDocTextArr.splice(-2);
  } else {
    oldJsDocTextArr.splice(-1);
  }

  if (newLatestVersion === currentVersion) {
    newJsDocTextArr.splice(-2);
  } else {
    newJsDocTextArr.splice(-1);
  }

  if (oldJsDocTextArr.length !== newJsDocTextArr.length) {
    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.HOSTORICAL_JSDOC_CHANGE,
      '',
      '',
      hint,
      oldApi.node,
      newApi.node
    ));
    return;
  }
  for (let i = 0; i < oldJsDocTextArr.length; i++) {
    if (oldJsDocTextArr[i].replace(/\r|\n|\s+/g, '') !== newJsDocTextArr[i].replace(/\r|\n|\s+/g, '')) {
      diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.HOSTORICAL_JSDOC_CHANGE,
        '',
        '',
        hint,
        oldApi.node,
        newApi.node
      ));
    }
  }
}

/**
 * 比较@type
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffType(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  const oldType = oldTagItem.getTypeTag();
  const newType = newTagItem.getTypeTag();
  if (!isArrayEquals(oldType, newType)) {
    diffReporter.addChangedApi(wrapApiChanges(newApi, StatusCode.TYPE_CHNAGES,
      arrayToString(oldType), arrayToString(newType),
      hint, '', '', matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.TYPE_CHNAGES,
      arrayToString(oldType),
      arrayToString(newType),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@FAModelOnly @StageModelOnly
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffAppModel(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  const oldAppModel = oldTagItem.getAppModel();
  const newAppModel = newTagItem.getAppModel();
  if (!isArrayEquals(oldAppModel, newTagItem.getAppModel())) {
    diffReporter.addChangedApi(wrapApiChanges(newApi, StatusCode.MODEL_CHNAGES,
      arrayToString(oldAppModel), arrayToString(newAppModel),
      hint, '', '', matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.MODEL_CHNAGES,
      arrayToString(oldAppModel),
      arrayToString(newAppModel),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@systemapi
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffApiLevel(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  const oldApiLevel = oldTagItem.getApiLevel();
  const newApiLevel = newTagItem.getApiLevel();
  if (!isArrayEquals(oldApiLevel, newApiLevel)) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.SYSTEM_API_CHNAGES,
      arrayToString(oldApiLevel),
      arrayToString(newApiLevel),
      hint, '', '', matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.SYSTEM_API_CHNAGES,
      arrayToString(oldApiLevel),
      arrayToString(newApiLevel),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@crossplatform
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffCrossplatform(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  if (!isArrayEquals(oldTagItem.getCrossplatform(), newTagItem.getCrossplatform())) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.CROSSPLATFORM_CHANGED, arrayToString(oldTagItem.getCrossplatform()),
      arrayToString(newTagItem.getCrossplatform()),
      hint, '', '', matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.CROSSPLATFORM_CHANGED,
      arrayToString(oldTagItem.getCrossplatform()),
      arrayToString(newTagItem.getCrossplatform()),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@form
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffForm(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  if (!isArrayEquals(oldTagItem.getForm(), newTagItem.getForm())) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.FORM_CHANGED, arrayToString(oldTagItem.getForm()),
      arrayToString(newTagItem.getForm()),
      hint, '', '', matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.FORM_CHANGED,
      arrayToString(oldTagItem.getForm()),
      arrayToString(newTagItem.getForm()),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@syscap
 * 
 * @param {DiffReporter} diffReporter 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffSyscap(diffReporter, oldApi, newApi, hint) {
  const oldSyscap = getApiSyscap(oldApi);
  const newSyscap = getApiSyscap(newApi);
  if (!isArrayEquals(oldSyscap, newSyscap)) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.SYSCAP_CHANGES, arrayToString(oldSyscap),
      arrayToString(newSyscap),
      hint, '', '', matchSyscapInFile(newApi)
    ));
    diffReporter.addDiffInfo(wrapApiChanges(
      newApi, StatusCode.SYSCAP_CHANGES, arrayToString(oldSyscap),
      arrayToString(newSyscap),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@since
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffSinceVersion(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  const oldVersion = oldTagItem.getSinceVersion();
  const newVersion = newTagItem.getSinceVersion();
  if (!isArrayEquals(oldVersion, newVersion)) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.VERSION_CHNAGES, arrayToString(oldVersion),
      arrayToString(newVersion),
      hint, '', '', matchSyscapInFile(newApi)
    ));
    diffReporter.addDiffInfo(wrapApiChanges(
      newApi, StatusCode.VERSION_CHNAGES, arrayToString(oldVersion),
      arrayToString(newVersion),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较@deprecated
 * 
 * @param {DiffReporter} diffReporter 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffDeprecated(diffReporter, oldApi, newApi, hint) {
  const oldDeprecated = getApiDeprecated(oldApi);
  const newDeprecated = getApiDeprecated(newApi);
  if (!isArrayEquals(oldDeprecated, newDeprecated)) {
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, StatusCode.DEPRECATED_CHNAGES,
      arrayToString(oldDeprecated), arrayToString(newDeprecated),
      hint, '', '', matchSyscapInFile(newApi)
    ));
    diffReporter.addDiffInfo(wrapApiChanges(
      newApi, StatusCode.DEPRECATED_CHNAGES, arrayToString(oldDeprecated),
      arrayToString(newDeprecated),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较权限的差异@permission
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffPermission(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  if (!isArrayEquals(oldTagItem.getPermission(), newTagItem.getPermission())) {
    diffReporter.addChangedApi(wrapApiChanges(newApi, StatusCode.PERMISSION_CHANGES,
      arrayToString(oldTagItem.getPermission()),
      arrayToString(newTagItem.getPermission()),
      hint,
      oldApi.node,
      newApi.node,
      matchSyscapInFile(newApi)
    ));

    diffReporter.addDiffInfo(wrapApiChanges(newApi, StatusCode.PERMISSION_CHANGES,
      arrayToString(oldTagItem.getPermission()),
      arrayToString(newTagItem.getPermission()),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 比较错误码的差异@throws
 * 
 * @param {DiffReporter} diffReporter 
 * @param {TagItem} oldTagItem 
 * @param {TagItem} newTagItem 
 * @param {ApiDigestInfo} oldApi 
 * @param {ApiDigestInfo} newApi 
 * @param {string} hint 
 */
function diffErrorCode(diffReporter, oldTagItem, newTagItem, oldApi, newApi, hint) {
  if (!isArrayEquals(oldTagItem.getErrorCode(), newTagItem.getErrorCode())) {
    let statusCode = '';
    if (oldTagItem.getErrorCode() === undefined) {
      statusCode = StatusCode.NEW_ERRORCODE;
    } else {
      statusCode = StatusCode.ERRORCODE_CHANGES;
    }
    diffReporter.addChangedApi(wrapApiChanges(
      newApi, statusCode, arrayToString(oldTagItem.getErrorCode()),
      arrayToString(newTagItem.getErrorCode()),
      hint,
      oldApi.node,
      newApi.node,
      matchSyscapInFile(newApi)
    ));
    diffReporter.addDiffInfo(wrapApiChanges(
      newApi, statusCode, arrayToString(oldTagItem.getErrorCode()),
      arrayToString(newTagItem.getErrorCode()),
      hint,
      oldApi.node,
      newApi.node
    ));
  }
}

/**
 * 解析 @since 7
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendSinceTag(tagObject, tagItem) {
  tagItem.addSinceVersion(tagObject.name ? tagObject.name : '');
}

/**
 * 解析 @syscap
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendSyscapTag(tagObject, tagItem) {
  tagItem.addSyscap(tagObject.name ? tagObject.name : '');
}

/**
 * 解析 @permission
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendPermissionTag(tagObject, tagItem) {
  const permissionRegExp = RegExp(/ohos\.permission\.\w+/g);
  let sourceText = '';
  tagObject.source.forEach((src) => {
    sourceText += src.source;
  });
  const permissionArray = sourceText.match(permissionRegExp);
  if (permissionArray) {
    permissionArray.forEach((permission) => {
      tagItem.addPermission(permission);
    });
  }
}

/**
 * 解析 @deprecated 标签
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendDeprecatedTag(tagObject, tagItem) {
  tagItem.addDeprecated(tagObject.description);
}

/**
 * 解析 @FAModelOnly @StageModelOnly
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendModelTag(tagObject, tagItem) {
  tagItem.addAppModel(tagObject.tag);
}

/**
 * 解析 @systemapi
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendApiLevelTag(tagObject, tagItem) {
  tagItem.addApiLevel(tagObject.tag);
}

/**
 * 解析 @type {string}
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendTypeTag(tagObject, tagItem) {
  tagItem.addTypeTag(tagObject.type);
}

/**
 * 解析 @useinstedad 标签
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendUseInsteadTag(tagObject, tagItem) {
  tagItem.addUseInstead(tagObject.name);
}

/**
 * 解析 @throws { BusinessError } 201 - 标签
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendErrorCodeTag(tagObject, tagItem) {
  tagItem.addErrorCode(tagObject.name);
}

/**
 * 解析 @form - 标签
 * 
 * @param {Object} tagObject 
 * @param {TagItem} tagItem 
 */
function appendForm(tagObject, tagItem) {
  tagItem.addForm(tagObject.tag);
}

function appendCrossplatform(tagObject, tagItem) {
  tagItem.addCrossplatform(tagObject.tag);
}

const tagHandlerMap = new Map([
  ['syscap', appendSyscapTag],
  ['permission', appendPermissionTag],
  ['deprecated', appendDeprecatedTag],
  ['famodelonly', appendModelTag],
  ['stagemodelonly', appendModelTag],
  ['systemapi', appendApiLevelTag],
  ['type', appendTypeTag],
  ['useinstead', appendUseInsteadTag],
  ['throws', appendErrorCodeTag],
  ['form', appendForm],
  ['crossplatform', appendCrossplatform]
]);



/**
 * 从 comment-parser 库解析的JSDoc对象中提取标签信息
 * 
 * @param {Object} jsdocs 
 */
function createTagItemFromJSDoc(jsdocs) {
  const tagItem = new TagItem();
  if (!jsdocs || jsdocs.length === 0) {
    return tagItem;
  }
  const singleJSDoc = jsdocs[jsdocs.length - 1];
  const firstJsDoc = jsdocs[0];
  if (singleJSDoc.tags) {
    singleJSDoc.tags.forEach((tagObject) => {
      const handler = tagHandlerMap.get(tagObject.tag.toLowerCase());
      if (handler) {
        handler(tagObject, tagItem);
      }
    });
  }

  if (firstJsDoc.tags) {
    firstJsDoc.tags.forEach((tagObject) => {
      if (tagObject.tag.toLowerCase() === 'since') {
        appendSinceTag(tagObject, tagItem);
      }
    });
  }
  return tagItem;
}

exports.JSDocDiffer = {
  collectJSDocDiffs: compareJSDocs,
};