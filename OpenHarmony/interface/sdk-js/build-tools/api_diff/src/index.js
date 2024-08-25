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

const { ApiDiffer } = require('./api_diff');
const { StatusCode } = require('./reporter');
const { JSONReporter, ExcelReporter, ChangelogReporter, MarkDownReporter } = require('./api_writer');
const { applyChangeLogs } = require('./format_data');

exports.ApiDiffPlugin = {
  pluginOptions: {
    name: 'diff',
    version: '0.1.0',
    description: 'Compare the differences between the two SDKS',
    commands: [
      {
        isRequiredOption: false,
        options: ['--old <string>', 'old sdk path'],
      },
      {
        isRequiredOption: false,
        options: ['--new <string>', 'new sdk path'],
      },
      {
        isRequiredOption: true,
        options: ['--oldVersion <string>', 'old sdk version'],
      },
      {
        isRequiredOption: true,
        options: ['--newVersion <string>', 'new sdk version'],
      },
      {
        isRequiredOption: true,
        options: ['--output <string>', 'output file path'],
      },
      {
        isRequiredOption: false,
        options: ['--format <json, excel, changelog>', 'output file format'],
      },
      {
        isRequiredOption: false,
        options: ['--newPath <string>', 'new interface_sdk-js path'],
      },
      {
        isRequiredOption: false,
        options: ['--oldPath <string>', 'old interface_sdk-js path'],
      },
      {
        isRequiredOption: false,
        options: ['--changelogUrl <string>', 'changelog url'],
      }
    ],
  },

  start: async function (argv) {
    const oldSdk = argv.old ? argv.old : argv.oldPath;
    const newSdk = argv.new ? argv.new : argv.newPath;
    const oldVersion = argv.oldVersion;
    const newVersion = argv.newVersion;
    const startTime = Date.now();
    const diffInfoMap = await ApiDiffer.compareSdks(oldSdk, newSdk);
    const changelogUrl = argv.changelogUrl;
    let diffMap = new Map();
    if (changelogUrl) {
      diffMap = await applyChangeLogs(diffInfoMap, oldVersion, newVersion, changelogUrl);
    } else {
      diffMap = diffInfoMap;
    }
    const diffs = this.coverToArray(diffMap);
    if (!argv.format || argv.format === 'json') {
      JSONReporter.write(diffs, argv.output, oldVersion, newVersion);
    } else if (argv.format === 'excel') {
      ExcelReporter.write(diffs, argv.output, oldVersion, newVersion);
      MarkDownReporter.write(diffs, argv.output);
    } else if (argv.format === 'changelog') {
      const changeLogData = [];
      this.formatToChangelog(diffs, changeLogData);
      ChangelogReporter.write(changeLogData, argv.output);
    }
    console.log(`elapsed time: ${Date.now() - startTime}`);
  },

  formatToChangelog(diffs, changeLogData) {
    diffs.forEach(diffData => {
      if (diffData.statusCode === StatusCode.NEW_API) {
        changeLogData.push(this.formatDiffApi('N/A', diffData.rawText, diffData.className, diffData.className,
          diffData.dtsName, diffData.dtsName));
        return;
      } else if (diffData.statusCode === StatusCode.DELETE) {
        changeLogData.push(this.formatDiffApi(diffData.rawText, 'N/A', diffData.className, diffData.className,
          diffData.dtsName, diffData.dtsName));
        return;
      } else if (diffData.statusCode === StatusCode.DELETE_CLASS) {
        changeLogData.push(this.formatDiffApi('N/A', 'N/A', 'N/A', 'N/A', diffData.dtsName, 'N/A'));
        return;
      } else if (diffData.statusCode === StatusCode.FUNCTION_CHANGES) {
        changeLogData.push(this.formatDiffApi(diffData.oldMessage, diffData.newMessage, diffData.className,
          diffData.className, diffData.dtsName, diffData.dtsName));
        return;
      } else {
        changeLogData.push(this.formatDiffApi(diffData.rawText, diffData.rawText, diffData.className,
          diffData.className, diffData.dtsName, diffData.dtsName));
      }
    });
  },

  formatDiffApi(oldApi, newApi, oldType, newType, oldDtsName, newDtsName) {
    return {
      'oldApi': oldApi,
      'newApi': newApi,
      'oldType': oldType,
      'newType': newType,
      'oldDtsName': oldDtsName,
      'newDtsName': newDtsName,
      'changelog': '',
      'compatible': '',
    };
  },

  coverToArray(diffMap) {
    const values = diffMap.values();
    const diffs = [];
    const diffSet = new Set();
    for (const data of values) {
      data.forEach(diffApi => {
        diffApi.changelogs = [...diffApi.changelogs];
        diffSet.add(JSON.stringify(diffApi));
      });
    }

    diffSet.forEach(data => {
      diffs.push(JSON.parse(data));
    });
    return diffs;
  },

  stop: function () { },
};