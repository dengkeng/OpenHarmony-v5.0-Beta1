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

const fs = require('fs');
const path = require('path');
const urlPrefix = 'https://gitee.com/openharmony/utils_system_resources/raw/';
const urlSuffix = '/systemres/main/config.json';

exports.checkJSDoc = function (node, sourceFile, fileName) {
  const checkLegality = require('./src/check_legality');
  return checkLegality.checkJsDocOfCurrentNode(node, sourceFile, fileName, false, false);
};

exports.initEnv = function (version) {
  const { checkOption } = require('./src/utils');
  return new Promise((resolve, reject) => {
    const permissionName = getPermissionName(version);
    const permissionConfig = getLocalPermissionConfig(permissionName);
    if (permissionConfig) {
      checkOption.permissionContent = permissionConfig;
      resolve();
      return;
    }
    const workingBranch = version || 'mas' + 'ter';
    const url = `${urlPrefix}${workingBranch}${urlSuffix}`;
    updatePermissionConfig(url, (content) => {
      if (content) {
        checkOption.permissionContent = content;
        savePermissionConfig(content, permissionName);
      }
      resolve();
    });
  });
};

function updatePermissionConfig(url, callback) {
  let requestText;
  const https = require('https');
  const request = https.get(url, { timeout: 2000 }, (res) => {
    res.on('data', (chunk) => {
      if (typeof chunk === 'string') {
        requestText = chunk;
      } else {
        const dataStr = new TextDecoder().decode(chunk);
        requestText = requestText ? (requestText + dataStr) : dataStr;
      }
    });
  }).on('error', () => {
    console.warn('use the default permission list.');
  }).on('close', () => {
    callback(requestText);
  }).on('timeout', () => {
    request.destroy();
  });
}

function getLocalPermissionConfig(name) {
  const localPermissionFile = path.resolve(__dirname, name);
  if (fs.existsSync(localPermissionFile)) {
    const content = fs.readFileSync(localPermissionFile);
    try {
      JSON.parse(content);
      return content;
    } catch (err) {
      console.warn(`parse error ${localPermissionFile}`);
    }
  }
  return undefined;
}

function savePermissionConfig(content, name) {
  const localPermissionFile = path.resolve(__dirname, name);
  fs.writeFileSync(localPermissionFile, content);
  console.log(`update permission configuration to ${localPermissionFile}`);
}

function getPermissionName(version) {
  return `permissions_${version}.config.json`;
}
