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
const { analyzeFileRaw } = require("./analyzeRaw");
const { generateAll } = require("./generate");
const { NapiLog } = require("./tools/NapiLog");
const re = require("./tools/re");
var fs = require('fs');

function doGenerate(ifname, destdir, imports, numberType, jsonCfg) {
    // step1: analyze file
    let structOfTs = analyzeFile(ifname);
    // to repace analyzeFile bythe below: let structOfTsRaw = analyzeFileRaw(ifname);
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
        let importsStr = '' + imports
        if (importsStr == 'true') {
            importsFun(structOfTs.imports, destdir, ifname);
        } else {
            structOfTs.imports = [];
        }
        generateAll(structOfTs, destdir, moduleName, numberType, jsonCfg);
    } else {
        NapiLog.logError('file name ' + fn + ' format invalid in function of doGenerate!');
    }
    return structOfTs.declareNamespace[0].name
}

function importsFun(imports, destDir, ifname) {
    for (let i = 0; i < imports.length; i++) {
        let importSearch = re.search("([.,/a-zA-Z {}']+from)", imports[i])
        let importPath = re.removeReg(imports[i], importSearch.regs[0])
        importPath = importPath.replace
        (/[`:~!#$%^&*() \+ =<>?"{}|,  ;' [ \] ·~！#￥%……&*（）—— \+ ={}|《》？：“”【】、；‘’，。、]/g,'')
        importPath = importPath.split('/')

        let ifnameSearch = re.search("(@[./a-zA-Z]+d.ts)", ifname)
        let ifnamePath = re.removeReg(ifname, ifnameSearch.regs[0])
        let filePath = ifnamePath+importPath[importPath.length-1]+'.d.ts'

        let ifnameFile = fs.readFileSync(ifname,'utf-8')
        let importFile 
        try {
            importFile = fs.readFileSync(ifnamePath+importPath[importPath.length-1]+'.d.ts','utf-8')
        } catch (err) {
            imports[i] = ''
            return
        }
        
        if (ifnameFile == importFile) {
            return
        } else {
            try {
                fs.accessSync(destDir+'/'+importPath[importPath.length-1], fs.constants.R_OK | fs.constants.W_OK);
            } catch (err) {
                fs.mkdirSync(destDir+'/'+importPath[importPath.length-1]);
            }
            imports[i] = '#include '+'"'+importPath[importPath.length-1]+'/'+
            doGenerate(filePath,destDir+'/'+importPath[importPath.length-1])+'.h"\n'
        }
    }
}

module.exports = {
    doGenerate
}
