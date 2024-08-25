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
const SECOND_PARAM = 2;

function checkEntry(prId) {
  let result = ['api_check: false'];
  const sourceDirname = __dirname;
  __dirname = 'interface/sdk-js/build-tools/api_check_plugin';
  const mdFilesPath = path.resolve(sourceDirname, '../../../../', 'all_files.txt');
  const MAX_TIMES = 3;
  let buffer = new Buffer.from('');
  let i = 0;
  let execute = false;
  try {
    const execSync = require('child_process').execSync;
    do {
      try {
        buffer = execSync('cd interface/sdk-js/build-tools/api_diff && npm install && cd ../api_check_plugin && npm install', {
          timeout: 120000,
        });
        execute = true;
      } catch (error) {}
    } while (++i < MAX_TIMES && !execute);
    if (!execute) {
      throw 'npm install timeout';
    }
    const { scanEntry, reqGitApi } = require(path.resolve(__dirname, './src/api_check_plugin'));
    result = scanEntry(mdFilesPath, prId, false);
    result = reqGitApi(result, prId);
    removeDir(path.resolve(__dirname, '../api_diff/node_modules'));
    removeDir(path.resolve(__dirname, 'node_modules'));
  } catch (error) {
    // catch error
    result.push(`API_CHECK_ERROR : ${error}`);
    result.push(`buffer : ${buffer.toString()}`);
  } finally {
    const { apiCheckInfoArr, removeDuplicateObj } = require('./src/utils');
    const apiCheckResultArr = removeDuplicateObj(apiCheckInfoArr);
    apiCheckResultArr.forEach((errorInfo) => {
      result.unshift(errorInfo);
    });
    writeResultFile(result, path.resolve(__dirname, './Result.txt'), {});
  }
}

function removeDir(url) {
  const statObj = fs.statSync(url);
  if (statObj.isDirectory()) {
    let dirs = fs.readdirSync(url);
    dirs = dirs.map((dir) => path.join(url, dir));
    for (let i = 0; i < dirs.length; i++) {
      removeDir(dirs[i]);
    }
    fs.rmdirSync(url);
  } else {
    fs.unlinkSync(url);
  }
}

function writeResultFile(resultData, outputPath, option) {
  const STANDARD_INDENT = 2;
  fs.writeFile(path.resolve(__dirname, outputPath), JSON.stringify(resultData, null, STANDARD_INDENT), option, (err) => {
    if (err) {
      console.error(`ERROR FOR CREATE FILE:${err}`);
    } else {
      console.log('API CHECK FINISH!');
    }
  });
}

checkEntry(process.argv[SECOND_PARAM]);
