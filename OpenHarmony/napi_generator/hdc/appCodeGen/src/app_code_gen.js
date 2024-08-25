/*
* Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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
const main = require("./main");

const re = require("./tools/re");
const { checkFileError } = require("./tools/common");
const { NapiLog } = require("./tools/NapiLog");
const path = require("path");
const stdio = require("stdio");
var fs = require('fs');
const { print } = require("./tools/tool");

let ops = stdio.getopt({
    'filename': { key: 'f', args: 1, description: ".d.ts file", default: "@ohos.napitest.d.ts" },
    'out': { key: 'o', args: 1, description: "output directory", default: "." },
    'loglevel': { key: 'l', args: 1, description: "Log Level : 0~3", default: "1" },

    /* 需要测试的接口函数可配置：写在json文件里:
     * [{
     * "classOrInterfName": "",
     * "functionName": "funNum"
     * }]     
     * 配置cfg.json文件路径
     */
    'functionsCfg': {key: 'c', args: 1, description: "configured file including the functions for test", default: ""}
});
    
NapiLog.init(ops.loglevel, path.join("" + ops.out, "napi_gen.log"))

let fileNames = ops.filename;
if (fileNames == null) {
    NapiLog.logInfo("fileNames cannot be empty!");
} else if (fileNames !== '') {
    readFiles();
}

function readFiles() {
    fileNames = fileNames.replace(/(^\s*)|(\s*$)/g, ''); // trim before and after espace
    let regex = ',';
    let filenameArray = fileNames.toString().split(regex);

    let n = filenameArray.length;
    for (let i = 0; i < n; i++) {
        let fileName = filenameArray[i];
        if (fileName !== ' ') {
            fileName = fileName.replace(/(^\s*)|(\s*$)/g, '');
            checkGenerate(fileName);
        }
    }
}

/**
 * 获取Json配置文件内容
 * @returns 
 */
function getJsonCfg(currentPath) { 
    let jsonCfg = null; // cfg.json 配置文件
    currentPath = currentPath.replace(/(^\s*)|(\s*$)/g, ''); // trim before and after espace
    let jsonFilePath = path.join(currentPath);
    let jsonFile = fs.readFileSync(jsonFilePath, { encoding: "utf8" });
    jsonCfg = JSON.parse(jsonFile);
    return jsonCfg;
}

function checkGenerate(fileName) {
    NapiLog.logInfo("check file []".format(fileName))

    let fn = re.getFileInPath(fileName);
    let tt = re.match('(@ohos\.)*([.a-z_A-Z0-9]+).d.ts', fn);
    if (tt) {
        let result = checkFileError(fileName);
        let funcConfig
        if (ops.functionsCfg) {
            funcConfig = getJsonCfg(ops.functionsCfg);
        }
        if (result[0]) {
            main.doGenerate(fileName, ops.out, funcConfig);
        }
        else {
            NapiLog.logError(result[1]);
        }
    }
    else {
        NapiLog.logError('file name ' + fn + ' format invalid in function of checkGenerate!');
    }
}

let ret = NapiLog.getResult();
if (ret[0]) {
    print('success');
    NapiLog.logInfo('success');
}
else {
    print('fail\n' + ret[1]);
    NapiLog.logInfo('fail\n' + ret[1]);
}


module.exports = {
    getJsonCfg
}