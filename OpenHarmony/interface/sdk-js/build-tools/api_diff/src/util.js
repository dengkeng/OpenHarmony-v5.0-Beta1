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
const fs = require('fs');


function listApiDeclarationFiles(dir) {
  const allFiles = [];
  const apiSubDirs = ['api', 'component'];
  apiSubDirs.forEach((subdir) => {
    internalListFiles(path.resolve(dir, subdir),
      (filePath) => path.basename(filePath).endsWith('.d.ts'), allFiles);
  });
  return allFiles;
}

function internalListFiles(dir, filter, output) {
  if (!fs.existsSync(dir)) {
    return;
  }
  const files = fs.readdirSync(dir);
  files.forEach((element) => {
    const filePath = path.join(dir, element);
    const status = fs.statSync(filePath);
    if (status.isDirectory()) {
      internalListFiles(filePath, filter, output);
    } else if (filter(filePath)) {
      output.push(filePath);
    }
  });
}

function isInDirectory(parentDir, subPath) {
  const relative = path.relative(parentDir, subPath);
  return relative === '' || !relative.startsWith('..');
}

exports.listApiDeclarationFiles = listApiDeclarationFiles;
exports.isInDirectory = isInDirectory;
