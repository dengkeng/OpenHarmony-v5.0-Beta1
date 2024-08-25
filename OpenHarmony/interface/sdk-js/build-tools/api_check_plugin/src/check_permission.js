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
const { getAPINote, ErrorType, ErrorLevel, FileType, systemPermissionFile, checkOption } = require('./utils');
const { addAPICheckErrorLogs } = require('./compile_info');

const permissionCheckWhitelist = new Set(['@ohos.wifi.d.ts', '@ohos.wifiManager.d.ts']);

/**
 * 门禁环境优先使用systemPermissionFile
 * 本地环境从指定分支上下载
 * 下载失败则使用默认配置
 *
 * @returns Set<string>
 */
function getPermissionBank() {
  const permissionTags = ['ohos.permission.HEALTH_DATA', 'ohos.permission.HEART_RATE', 'ohos.permission.ACCELERATION'];
  let permissionFileContent;
  if (fs.existsSync(systemPermissionFile)) {
    permissionFileContent = require(systemPermissionFile);
  } else if (checkOption.permissionContent) {
    permissionFileContent = JSON.parse(checkOption.permissionContent);
  } else {
    permissionFileContent = require('../config/config.json');
  }
  const permissionTagsObj = permissionFileContent.module.definePermissions;
  permissionTagsObj.forEach((item) => {
    permissionTags.push(item.name);
  });
  const permissionRuleSets = new Set(permissionTags);
  return permissionRuleSets;
}
exports.getPermissionBank = getPermissionBank;

function checkPermission(node, sourcefile, fileName) {
  const permissionRuleSet = getPermissionBank();
  const apiNote = getAPINote(node);
  let hasPermissionError = false;
  let errorInfo = '';
  let apiNoteArr = [];
  if (apiNote.match(new RegExp('@permission'))) {
    apiNoteArr = apiNote.split(/ *\* *\@/g);
  }
  apiNoteArr.forEach(note => {
    // 找到jsdoc中的permission标签关键字并拿到待校验的permission字段
    if (note.match(new RegExp(/^permission\b/))) {
      const permissionNote = note.replace(/(^permission\b|[(\r\n)\r\n ]|(\*\/|\*))/g, '').trim();
      if (/(or|and)/g.test(permissionNote)) {
        const permissionArr = permissionNote.replace(/( |or|and|\(|\))/g, '$').split('$');
        permissionArr.forEach(permissionStr => {
          if (permissionStr !== '') {
            if (!permissionRuleSet.has(permissionStr)) {
              hasPermissionError = true;
              if (errorInfo !== '') {
                errorInfo += `,${permissionStr}`;
              } else {
                errorInfo += permissionStr;
              }
            }
          }
        });
      } else {
        if (!permissionRuleSet.has(permissionNote)) {
          hasPermissionError = true;
          if (errorInfo !== '') {
            errorInfo += `,${permissionNote}`;
          } else {
            errorInfo += permissionNote;
          }
        }
      }
    }
  });

  if (hasPermissionError && !permissionCheckWhitelist.has(path.basename(fileName))) {
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.UNKNOW_PERMISSION, errorInfo, FileType.API,
      ErrorLevel.MIDDLE);
  } else if (hasPermissionError && permissionCheckWhitelist.has(path.basename(fileName))) {
    addAPICheckErrorLogs(node, sourcefile, fileName, ErrorType.UNKNOW_PERMISSION, errorInfo, FileType.API,
      ErrorLevel.LOW);
  }
}
exports.checkPermission = checkPermission;
