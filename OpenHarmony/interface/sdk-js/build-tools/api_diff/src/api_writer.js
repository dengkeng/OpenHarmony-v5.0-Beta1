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

const excel = require('exceljs');
const path = require('path');
const fs = require('fs');
const { StatusCode, StatusMessages } = require('./reporter');

let subsystemMap = new Map();
let fileNameMap = new Map();

function getSubsystemMap() {
  const subsystemFilePath = path.join(__dirname, '..', 'subsystem.json');
  const fileContent = JSON.parse(fs.readFileSync(subsystemFilePath, 'utf-8'));
  fileContent.forEach(content => {
    subsystemMap.set(content.syscap, content.subsystem);
    fileNameMap.set(content.syscap, content.fileName);
  });
}


exports.JSONReporter = {
  write: function (diffs, dest, oldVersion, newVersion) {
    const outputFile = path.resolve(dest, `diff(${oldVersion}_${newVersion}).json`);
    fs.writeFileSync(outputFile, JSON.stringify(diffs));
    console.log(`report is in ${outputFile}`);
  },
};

exports.ChangelogReporter = {
  write: function (diffs, dest) {
    const outputFile = path.resolve(dest, 'changelog.json');
    fs.writeFileSync(outputFile, JSON.stringify(diffs));
    console.log(`report is in ${outputFile}`);
  },
};

exports.ExcelReporter = {
  write: async function (diffs, dest, oldVersion, newVersion) {
    getSubsystemMap();
    const workbook = new excel.Workbook();
    const sheet = workbook.addWorksheet('api差异', { viers: [{ xSplit: 1 }] });
    sheet.getRow(1).values = ['操作标记', '差异项-旧版本', '差异项-新版本', 'd.ts文件', '归属子系统'];
    diffs.forEach((diffInfo, index) => {
      const messageObj = getDiffMessage(diffInfo);
      const syscap = diffInfo.syscap ? diffInfo.syscap : '';
      const subsystem = diffInfo.packageName === 'ArkUI' ? 'ACE开发框架' : subsystemMap.get(syscap);
      const ADD_NUMBER = 2;
      sheet.getRow(index + ADD_NUMBER).values = [
        diffInfo.status,
        messageObj.oldMessage,
        messageObj.newMessage,
        diffInfo.dtsName,
        subsystem
      ];
    });
    const buffer = await workbook.xlsx.writeBuffer();
    const outputFile = path.resolve(dest, 'diff.xlsx');
    fs.writeFileSync(outputFile, buffer);
    console.log(`report is in ${outputFile}`);
  },
};

exports.MarkDownReporter = {
  write: function (diffs, dest) {
    fileNameMap.forEach((fileName, syscap) => {
      let diffsInSameSystem = [];
      diffs.forEach(diffInfo => {
        if (diffInfo.syscap === syscap) {
          diffsInSameSystem.push(diffInfo);
        }
      });
      if (diffsInSameSystem.length === 0) {
        return;
      }

      sortDiffInfoByStatus(diffsInSameSystem, fileName, dest);
    });
  },
};

function sortDiffInfoByStatus(diffsInSameSystem, fileName, dest) {
  const sortDiffInfos = [];
  StatusMessages.forEach(status => {
    diffsInSameSystem.forEach(diffInfo => {
      if (diffInfo.status === status) {
        sortDiffInfos.push(diffInfo);
      }
    });
  });
  exportDiffMd(fileName, sortDiffInfos, dest);
}

function exportDiffMd(fileName, diffInfos, dest) {
  let finalContent = '| 操作 | 旧版本 | 新版本 | d.ts文件 |\n' + '| ---- | ------ | ------ | -------- |\n';
  for (let i = 0; i < diffInfos.length; i++) {
    let apiData = diffInfos[i];
    const messageObj = getDiffMessage(apiData);
    const oldData = messageObj.oldMessage.replace(/\r|\n/g, '<br>').replace(/\|/g, '\\|').replace(/\<(?!br>)/g, '\\<');
    const newData = messageObj.newMessage.replace(/\r|\n/g, '<br>').replace(/\|/g, '\\|').replace(/\<(?!br>)/g, '\\<');
    finalContent += `|${apiData.status}|${oldData}|${newData}|${apiData.dtsName}|\n`;
  }
  const mdFilesDir = `${dest}\\diff合集`;
  if (!fs.existsSync(mdFilesDir)) {
    fs.mkdirSync(mdFilesDir);
  }

  fs.writeFileSync(`${dest}\\diff合集\\js-apidiff-${fileName}.md`, finalContent);

}


function getDiffMessage(diffInfo) {
  let oldMessage = 'NA';
  let newMessage = 'NA';
  if (diffInfo.statusCode === StatusCode.DELETE) {
    oldMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}`;
  } else if (diffInfo.statusCode === StatusCode.DELETE_CLASS) {
    oldMessage = `类名声明：${diffInfo.rawText}`;
  } else if (diffInfo.statusCode === StatusCode.NEW_API) {
    newMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}`;
  } else if (diffInfo.statusCode === StatusCode.DELETE_DTS) {
    oldMessage = `文件名：${diffInfo.dtsName}`;
  } else if (diffInfo.statusCode === StatusCode.FUNCTION_CHANGES) {
    oldMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.oldMessage}`;
    newMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.newMessage}`;
  } else if (diffInfo.statusCode === StatusCode.DEPRECATED_CHNAGES) {
    const useinsteadInfo = diffInfo.hint.replace('useinstead:', '');
    oldMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}\n旧版本信息：${diffInfo.oldMessage}`;
    newMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}\n新版本信息：${diffInfo.newMessage}\n代替接口：${useinsteadInfo}`;
  } else {
    oldMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}\n旧版本信息：${diffInfo.oldMessage}`;
    newMessage = `类名：${diffInfo.className};\n方法or属性：${diffInfo.rawText}\n新版本信息：${diffInfo.newMessage}`;
  }
  return { oldMessage, newMessage };
}