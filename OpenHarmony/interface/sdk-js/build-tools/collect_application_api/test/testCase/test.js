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
const path = require('path');
const fs = require('fs');
const { ApiCollector } = require('../../src/api_collector');

describe('collectApi', function () {
  // 传参获得
  const sdkPath = process.argv[process.argv.length - 1];
  const appDir = path.join(__dirname, '..', '/ut/');
  const outputDir = path.join(__dirname, '..', '/output');
  const expectFileDir = path.join(__dirname, '..', '/expect/');
  const appProjectNames = fs.readdirSync(appDir);
  appProjectNames.forEach(projectName => {
    let appProjectPath = path.join(appDir, projectName);
    let expectFilePath = path.join(expectFileDir, `${projectName}.json`);
    it('testFile# ' + path.basename(appProjectPath), function () {
      const expectFileContent = fs.readFileSync(expectFilePath, 'utf-8').replace(/\n|\r|\s/g, '');
      const argv = {
        app: appProjectPath,
        sdk: sdkPath,
        output: outputDir,
        format: 'json',
      };
      const collector = new ApiCollector(argv);
      collector.start();
      const outputFileName = fs.readdirSync(outputDir);
      const outputFilePath = path.join(outputDir, outputFileName[0]);
      const outputFileContent = fs.readFileSync(outputFilePath, 'utf-8').replace(/\n|\r|\s/g, '');
      expect(outputFileContent).to.be.equal(expectFileContent);
    });
  });
});