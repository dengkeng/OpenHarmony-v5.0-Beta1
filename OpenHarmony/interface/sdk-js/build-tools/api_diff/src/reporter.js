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

const path = require('path');

const ApiStatusCode = {
  DELETE: 0,
  DELETE_DTS: 1,
  DELETE_CLASS: 2,
  NEW_API: 3,
  VERSION_CHNAGES: 4,
  DEPRECATED_CHNAGES: 5,
  NEW_ERRORCODE: 6,
  ERRORCODE_CHANGES: 7,
  SYSCAP_CHANGES: 8,
  SYSTEM_API_CHNAGES: 9,
  PERMISSION_DELETE: 10,
  PERMISSION_NEW: 11,
  PERMISSION_CHANGES: 12,
  MODEL_CHNAGES: 13,
  TYPE_CHNAGES: 14,
  CLASS_CHANGES: 15,
  FUNCTION_CHANGES: 16,
  CHANGELOG: 17,
  DTS_CHANGED: 18,
  FORM_CHANGED: 19,
  CROSSPLATFORM_CHANGED: 20,
  NEW_DTS: 21,
  NEW_CLASS: 22,
  HOSTORICAL_JSDOC_CHANGE: 23
};

const StatusMessages = [];
StatusMessages[ApiStatusCode.DELETE] = '删除';
StatusMessages[ApiStatusCode.DELETE_DTS] = 'd.ts删除';
StatusMessages[ApiStatusCode.NEW_DTS] = 'd.ts新增';
StatusMessages[ApiStatusCode.DELETE_CLASS] = '类型删除';
StatusMessages[ApiStatusCode.NEW_CLASS] = '类型新增';
StatusMessages[ApiStatusCode.NEW_API] = '新增';
StatusMessages[ApiStatusCode.VERSION_CHNAGES] = '起始版本有变化';
StatusMessages[ApiStatusCode.DEPRECATED_CHNAGES] = '废弃版本有变化';
StatusMessages[ApiStatusCode.NEW_ERRORCODE] = '新增(错误码)';
StatusMessages[ApiStatusCode.ERRORCODE_CHANGES] = '错误码有变化';
StatusMessages[ApiStatusCode.SYSCAP_CHANGES] = 'SysCap有变化';
StatusMessages[ApiStatusCode.SYSTEM_API_CHNAGES] = '访问级别有变化';
StatusMessages[ApiStatusCode.PERMISSION_DELETE] = '删除(权限)';
StatusMessages[ApiStatusCode.PERMISSION_NEW] = '新增(权限)';
StatusMessages[ApiStatusCode.PERMISSION_CHANGES] = '权限有变化';
StatusMessages[ApiStatusCode.MODEL_CHNAGES] = 'model有变化';
StatusMessages[ApiStatusCode.TYPE_CHNAGES] = 'type有变化';
StatusMessages[ApiStatusCode.CLASS_CHANGES] = '类型有变化';
StatusMessages[ApiStatusCode.FUNCTION_CHANGES] = '函数有变化';
StatusMessages[ApiStatusCode.CHANGELOG] = 'changelog';
StatusMessages[ApiStatusCode.DTS_CHANGED] = 'd.ts有变化';
StatusMessages[ApiStatusCode.FORM_CHANGED] = '卡片应用支持性有变化';
StatusMessages[ApiStatusCode.CROSSPLATFORM_CHANGED] = '跨平台能力有变化';
StatusMessages[ApiStatusCode.HOSTORICAL_JSDOC_CHANGE] = '历史jsdoc有变化';

function reportDeletedApi(api, syscap) {
  return wrapApiDiffInfo(api, ApiStatusCode.DELETE, '', '', '', syscap);
}

function reportDeletedClass(api, syscap) {
  const reporterData = new ReporterData(api);
  reporterData.setStatusCode(ApiStatusCode.DELETE_CLASS)
    .setStatusMessage(StatusMessages[ApiStatusCode.DELETE_CLASS] + `(${api.getApiType().name})`)
    .setOldMessage('')
    .setNewMessage('')
    .setSyscap(syscap);
  return reporterData;
}

function reportDeletedPackage(packageName, dtsName) {
  const reporterData = new ReporterData(undefined);
  reporterData.setStatusCode(ApiStatusCode.DELETE_DTS)
    .setPackageName(packageName)
    .setOldMessage('d.ts声明文件已删除')
    .setNewMessage('')
    .setDtsName(path.basename(dtsName))
    .setDtsPath(dtsName);
  return reporterData;
}

function reportNewPackage(packageName, dtsName, syscap) {
  const reporterData = new ReporterData(undefined);
  reporterData.setStatusCode(ApiStatusCode.NEW_DTS)
    .setPackageName(packageName)
    .setOldMessage('')
    .setNewMessage('新增d.ts声明文件')
    .setDtsName(path.basename(dtsName))
    .setDtsPath(dtsName)
    .setSyscap(syscap);
  return reporterData;
}

function reportNewApi(api, syscap) {
  return wrapApiDiffInfo(api, ApiStatusCode.NEW_API, '', '', '', syscap);
}

function reportApiChanges(apiChanges) {
  return wrapApiDiffInfo(apiChanges.api, apiChanges.statusCode,
    `${apiChanges.oldMessage}`, `${apiChanges.newMessage}`, `${apiChanges.hint}`, `${apiChanges.syscap}`);
}

function wrapApiDiffInfo(api, statusCode, oldMessage, newMessage, hint, syscap) {
  const reporterData = new ReporterData(api);
  reporterData.setStatusCode(statusCode)
    .setOldMessage(oldMessage)
    .setNewMessage(newMessage)
    .setHint(hint)
    .setSyscap(syscap);
  return reporterData;
}

function addNodeInfo(diffItem, changeInfo) {
  diffItem.oldNode = changeInfo.oldNode;
  diffItem.newNode = changeInfo.newNode;
  return diffItem;
}

exports.StatusCode = ApiStatusCode;
exports.StatusMessages = StatusMessages;

class ReporterData {
  constructor(apiDigestInfo) {
    if (apiDigestInfo) {
      this.packageName = apiDigestInfo.getPackageName();
      this.className = apiDigestInfo.getClassName();
      this.rawText = apiDigestInfo.getRawText();
      this.dtsName = path.basename(apiDigestInfo.getPath());
      this.dtsPath = apiDigestInfo.getPath();
    } else {
      this.packageName = '';
      this.className = '';
      this.rawText = '';
      this.dtsName = '';
      this.dtsPath = '';
    }
    this.hint = '';
    this.changelogs = new Set();
  }

  setDtsPath(dtsPath) {
    this.dtsPath = dtsPath;
    return this;
  }


  setPackageName(packageName) {
    this.packageName = packageName;
    return this;
  }

  setDtsName(dtsName) {
    this.dtsName = path.basename(dtsName);
    return this;
  }

  setClassName(className) {
    this.className = className;
    return this;
  }

  setStatusCode(statusCode) {
    this.statusCode = statusCode;
    this.status = StatusMessages[statusCode];
    return this;
  }

  setStatusMessage(msg) {
    this.status = msg;
    return this;
  }

  setOldMessage(oldMessage) {
    this.oldMessage = oldMessage;
    return this;
  }

  setNewMessage(newMessage) {
    this.newMessage = newMessage;
    return this;
  }

  setHint(hint) {
    this.hint = hint;
    return this;
  }

  setSyscap(syscap) {
    if (!syscap) {
      this.syscap = '';
      return this;
    }
    this.syscap = syscap.split('.')[1];
    return this;
  }
}

class DiffReporter {
  constructor() {
    this.diffs = new Map();
    this.diffInfos = [];
  }

  addDeletedApi(api, syscap) {
    this.setMap(reportDeletedApi(api, syscap));
  }

  addDeletedPackage(packageName, dtsName) {
    this.setMap(reportDeletedPackage(packageName, dtsName));
  }

  addNewPackage(packageName, dtsName, syscap) {
    this.setMap(reportNewPackage(packageName, dtsName, syscap));
  }

  addNewApi(api, syscap) {
    this.setMap(reportNewApi(api, syscap));
  }

  addChangedApi(apiChanges) {
    let reportItem;
    if (apiChanges.statusCode === ApiStatusCode.DELETE_CLASS) {
      reportItem = reportDeletedClass(apiChanges.api, apiChanges.syscap);
    } else {
      reportItem = reportApiChanges(apiChanges);
    }
    this.setMap(reportItem);
  }

  addDiffInfo(apiChanges) {
    const reportItem = reportApiChanges(apiChanges);
    this.diffInfos.push(addNodeInfo(reportItem, apiChanges));
  }

  setMap(api) {
    const key = `${api.dtsPath}#${this.formatApiText(api.rawText)}`;
    if (this.diffs.get(key)) {
      this.diffs.get(key).push(api);
    } else {
      this.diffs.set(key, [api]);
    }
  }

  getResults() {
    return this.diffs;
  }

  getDiffInfos() {
    return this.diffInfos;
  }

  formatApiText(apiText) {
    return apiText.replace(/\r|\n|\s+|\,|\;/g, '');
  }
}

exports.DiffReporter = DiffReporter;