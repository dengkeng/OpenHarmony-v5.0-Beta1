/*
* Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
const fs = require('fs');
const path = require('path')
const stdio = require("stdio");
const main = require("./TsGen/tsMain");

let ops = stdio.getopt({
    // 输入的.h文件路径，必填
    'filename': { key: 'f', args: 1, description: ".h file", default: "" },
    // 可选参数，测试文件路径
    'testFilename': { key: 't', args: 1, description: "Ability.test.ets file", default: "" },
    // 可选参数， 声明文件路径
    'indexFilename': { key: 'i', args: 1, description: "index.d.ts file", default: "" },
    // 可选参数， cpp文件路径
    'outCppPath': { key: 'o', args: 1, description: ".cpp dir path", default: "" },
});

// 获取命令行参数 .h文件路径
let filePath = ops.filename
let testFilePath = ops.testFilename
let tsFilePath = ops.indexFilename
let cppFilePath = ops.outCppPath
// 读取文件内容 判断参数是否为空
if (filePath !== '') {
    // 若用户没有提供路径 则程序提供默认路径
    if (!tsFilePath) {
        createDirectorySync(path.join(filePath, '../tsout'))
        tsFilePath = path.join(filePath, '../tsout/index.d.ts');
    }
    if (!testFilePath) {
        testFilePath = path.join(filePath, '../testout');
        createDirectorySync(testFilePath)
    }
    if(!cppFilePath) {
        // 若用户未给定cpp生成路径，则在.h路径下直接生成out路径
        cppFilePath = path.join(filePath, '../cppout');
        createDirectorySync(cppFilePath)
    }

    main.doGenerate(filePath, testFilePath, tsFilePath, cppFilePath);
}

function createDirectorySync(directoryPath) {
  try {
    fs.mkdirSync(directoryPath, { recursive: true });
  } catch (err) {
    console.error(`无法创建文件夹 ${directoryPath}: ${err}`);
  }
}