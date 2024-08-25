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

const { expect } = require('chai');
const { apiCheckInfoArr, removeDuplicateObj } = require('../../src/utils');
const { scanEntry } = require('../../src/api_check_plugin');
const path = require('path');
const fs = require('fs');

describe('diffSingleFile', function () {
  const testCasesDir = path.join(__dirname, '..', '/ut');
  const testCasesFileNames = fs.readdirSync(testCasesDir);
  const expectFileDir = path.join(__dirname, '..', '/expect');
  const outputFilePath = path.join(__dirname, '..', 'output');
  if (!fs.existsSync(outputFilePath)) {
    fs.mkdirSync(outputFilePath);
  }
  testCasesFileNames.forEach(fileName => {
    const expectFilePath = path.resolve(expectFileDir, `${fileName.replace(/.d.ts/g, '.txt')}`);
    it(`testDiff# ${fileName}`, function () {
      let result = [];
      const url = path.join(testCasesDir, fileName);
      const prId = 'xxx';
      fs.writeFileSync(path.join(__dirname, 'testMdfile.txt'), url);
      scanEntry(path.join(__dirname, 'testMdfile.txt'), prId, true);
      const apiCheckResultArr = removeDuplicateObj(apiCheckInfoArr);
      result.push(apiCheckResultArr[apiCheckResultArr.length - 1]);
      const resultFilePath = path.join(outputFilePath, `output_${fileName.replace(/.d.ts/g, '.txt')}`);
      fs.writeFileSync(resultFilePath, JSON.stringify(result));
      const resultFileContent = fs.readFileSync(resultFilePath, 'utf-8').replace(/\n|\r|\s/g, '');
      const expectContent = fs.readFileSync(expectFilePath, 'utf-8').replace(/\n|\r|\s/g, '');
      expect(resultFileContent).to.be.equal(expectContent);
    });
  });
});
