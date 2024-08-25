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

function checkEntryLocalText(url, prId) {
  const path = require('path');
  let result = [];
  try {
    let execSync = require("child_process").execSync;
    execSync("cd ../../api_diff && npm install && cd ../api_check_plugin && npm install");
    const { excelApiCheckResult, apiCheckArr, removeDir } =
      require(path.resolve(__dirname, '../src/utils'));
    const { scanEntry } = require('../src/api_check_plugin');
    result = scanEntry(url, prId, false);
    excelApiCheckResult(apiCheckArr);
    removeDir(path.resolve(__dirname, "../../api_diff/node_modules"));
    removeDir(path.resolve(__dirname, "../node_modules"));
  } catch (error) {
    result.push(`API_CHECK_ERROR :${error}`);
    console.error(`API_CHECK_ERROR :${error}`);
  } finally {
    const { apiCheckInfoArr, removeDuplicateObj } = require('../src/utils');
    const apiCheckResultArr = removeDuplicateObj(apiCheckInfoArr);
    apiCheckResultArr.forEach(errorInfo => {
      result.unshift(errorInfo);
    });
    const { writeResultFile } = require('../src/utils');
    writeResultFile(result, path.resolve(__dirname, './Result.txt'), {});
  }
}

// 修改为实际的prId
const prId = 'xxx';
checkEntryLocalText('./mdFiles.txt', prId);
