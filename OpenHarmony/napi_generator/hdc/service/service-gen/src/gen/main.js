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
const path = require("path");
const stdio = require("stdio");
const fs = require('fs');
const re = require("../tools/re");

const { NapiLog } = require("../tools/NapiLog");
const { print } = require("../tools/tool");
const analyze = require("./analyze");
const gen =  require("./generate");
const { writeFile, createFolder } = require("../tools/FileRW");

let ops = stdio.getopt({
    'filename': { key: 'f', args: 1, description: ".h file", default: "" },
    'out': { key: 'o', args: 1, description: "output directory", default: "." },
    'loglevel': { key: 'l', args: 1, description: "Log Level: 0~3", default: "1" },
    'serviceId': { key: 's', args: 1, description: "service register id: 9000~16777214", default: "9000" }
});

NapiLog.init(ops.loglevel, path.join("" + ops.out, "napi_gen.log"));

let fileNames = ops.filename;
var pathDir = ops.directory;
if (fileNames == null && pathDir == null) {
    NapiLog.logInfo("fileNames and pathDir both cannot be empty at the same time");
} else if (pathDir && pathDir != '') {
    readDirFiles();
} else if (fileNames && fileNames != '') {
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

function readDirFiles() {
    fs.readdir(pathDir + '', function (err, files) {
        if (err) {
            NapiLog.logError('readdir file error' + err);
            return;
        }
        (function iterator(i) {
            if (i === files.length) {
                return;
            }
            fs.stat(path.join(pathDir + '', files[i]), function (err, data) {
                if (err) {
                    NapiLog.logError('read file error' + err);
                    return;
                }
                if (data.isFile()) {
                    let fileName = files[i];
                    checkGenerate(pathDir + '/' + fileName);
                }
                iterator(i + 1);
            });
        })(0);
    });
}

function wirte2Disk(fileInfo, destDir) {
    let filePath = re.pathJoin(destDir, fileInfo.name);
    writeFile(filePath, fileInfo.content);
}

function genServiceFile(fileName) {
    // 1. h文件解析保存为结构体
    let rootInfo = analyze.doAnalyze(fileName, ops);

    // 2. 根据结构体生成代码
    let fileContent = gen.doGenerate(rootInfo);

    // 3. 创建service工程目录
    let servicePath = re.pathJoin(ops.out, rootInfo.serviceName.toLowerCase() + "service");
    let etcPath = re.pathJoin(servicePath, "etc");
    let includePath = re.pathJoin(servicePath, "include");
    let interfacePath = re.pathJoin(servicePath, "interface");
    let profilePath = re.pathJoin(servicePath, "sa_profile");
    let srcPath = re.pathJoin(servicePath, "src");
    createFolder(servicePath);
    createFolder(etcPath);
    createFolder(includePath);
    createFolder(interfacePath);
    createFolder(profilePath);
    createFolder(srcPath);

    // 4. 生成代码保存为文件
    wirte2Disk(fileContent.serviceCfgFile, etcPath);
    wirte2Disk(fileContent.serviceCfgGnFile, etcPath);
    wirte2Disk(fileContent.proxyHFile, includePath);
    wirte2Disk(fileContent.stubHFile, includePath);
    wirte2Disk(fileContent.serviceHFile, includePath);
    wirte2Disk(fileContent.iServiceHFile, interfacePath);
    wirte2Disk(fileContent.profileGnFile, profilePath);
    wirte2Disk(fileContent.profileXmlFile, profilePath);
    wirte2Disk(fileContent.proxyCppFile, srcPath);
    wirte2Disk(fileContent.stubCppFile, srcPath);
    wirte2Disk(fileContent.serviceCppFile, srcPath);
    wirte2Disk(fileContent.clientCppFile, srcPath);
    wirte2Disk(fileContent.iServiceCppFile, srcPath);
    wirte2Disk(fileContent.buildGnFile, servicePath);
    wirte2Disk(fileContent.bundleJsonFile, servicePath);
}

function checkGenerate(fileName) {
    NapiLog.logInfo("check file []".format(fileName));
    let suffix = fileName.split('.').pop().toLowerCase();
    if (suffix === 'h') {
        NapiLog.logInfo("Generating service code from file " + fileName);
        genServiceFile(fileName);
    } else {
        NapiLog.logError('Only .h file is supported.');
    }
}

let ret = NapiLog.getResult();
if (ret[0]) {
    print('success');
    NapiLog.logInfo('success');
}
else {
    print('Finish with error: ' + ret[1]);
    NapiLog.logInfo('Finish with error: ' + ret[1]);
}
