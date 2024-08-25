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

function copyESLibs() {
  const targetLibPath = path.resolve(__dirname, '..', 'libs');
  if (!fs.existsSync(targetLibPath)) {
    fs.mkdirSync(targetLibPath);
  }
  const esLibPath = path.resolve(__dirname, '../node_modules/typescript/lib');
  const libFiles = fs.readdirSync(esLibPath);
  const excludeFiles = ['lib.dom.d.ts'];
  libFiles.forEach((file) => {
    const srcFilePath = path.resolve(esLibPath, file);
    if (fs.statSync(srcFilePath).isDirectory()) {
      return;
    }
    const targetFile = path.resolve(targetLibPath, file);
    if (fs.existsSync(targetFile)) {
      return;
    }
    
    if (file.endsWith('.d.ts') && file.startsWith('lib.') && !excludeFiles.includes(file)) {
      fs.copyFileSync(srcFilePath, targetFile);
    }
  });
  excludeFiles.forEach((excludeFile) => {
    const targetFile = path.resolve(targetLibPath, excludeFile);
    if (fs.existsSync(targetFile)) {
      fs.unlinkSync(targetFile);
    }
  });
}

copyESLibs();

exports.copyESLibs = copyESLibs;