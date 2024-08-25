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
const { analyzeFile } = require("./analyze");
const { generateAppCode } = require("./generate");
const { NapiLog } = require("./tools/NapiLog");
const re = require("./tools/re");
var fs = require('fs');

function doGenerate(ifname, destdir, jsonCfg) {
    // step1: analyze file
    let structOfTs = analyzeFile(ifname);
    let fn = re.getFileInPath(ifname);
    let tt = re.match('(@ohos\.)*([.a-z_A-Z0-9]+).d.ts', fn);
    if (structOfTs === undefined || structOfTs.declareNamespace.length == 0 || 
        structOfTs.declareNamespace[0].name === undefined) {
        NapiLog.logError('analyzeFile file fail and file name is: ' + fn);
        return;
    }
    
    // step2: generate code
    if (tt) {
        let moduleName = re.getReg(fn, tt.regs[2]);

        structOfTs.imports = [];
        generateAppCode(structOfTs, destdir, moduleName, jsonCfg);
    } else {
        NapiLog.logError('file name ' + fn + ' format invalid in function of doGenerate!');
    }
    return structOfTs.declareNamespace[0].name
}

module.exports = {
    doGenerate
}
