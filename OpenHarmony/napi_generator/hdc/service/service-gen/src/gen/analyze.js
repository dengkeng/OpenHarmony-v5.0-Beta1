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
const { NapiLog } = require("../tools/NapiLog");
const fs = require("fs");
const os = require("os");
const { AllParseFileList } = require("../tools/common");
const path = require('path');

function parseFileAll(hFilePath) {
    let execSync = require("child_process").execSync;
    let cmd = "";
    if(fs.existsSync("./hdc/service/service-gen/src/gen/header_parser.py")) {
        // call python file (for debug test)
        cmd = "python ./hdc/service/service-gen/src/gen/header_parser.py " + hFilePath;
    } else {
        // call exe file (for real runtime)
        let sysInfo = os.platform();
        let execPath = path.dirname(process.execPath);
        let exeFile = sysInfo === 'win32' ? path.join(execPath, "header_parser.exe") : 
                                            path.join(execPath, "header_parser");
        cmd = exeFile + " " + hFilePath;
    }

    let parseResult = null;
    let stdout = execSync(cmd);
    parseResult = JSON.parse(stdout.toString()).result;
    parseResult.rawContent = fs.readFileSync(hFilePath, 'UTF-8');
    return parseResult;
}

function analyzeNameSpace(rootInfo, parseResult) {
    if (parseResult.namespaces.length == 0) {
        return;
    }
    let lastNameSpace = parseResult.namespaces[parseResult.namespaces.length - 1];
    rootInfo.nameSpace = lastNameSpace.split('::');
}

function createParam(parseParamInfo) {
    let param = {};
    param.name = parseParamInfo.name;
    param.type = parseParamInfo.reference ? parseParamInfo.type.replace("&", "").trim(): parseParamInfo.type
    param.rawType = parseParamInfo.raw_type;
    param.isPointer = (parseParamInfo.pointer == 1);
    param.isReference = (parseParamInfo.reference == 1);
    param.isArray = (parseParamInfo.array == 1);
    param.isConstant = (parseParamInfo.constant == 1);
    return param;
}

function createFuncInfo(parseFuncInfo) {
    let funcInfo = {
        "name": "", // 方法名
        "params": [], // 参数列表
        "retType": "", // 返回值
        "rawStr": "" // 方法原始代码
    }
    funcInfo.name = parseFuncInfo.name;

    let parseParams = parseFuncInfo.parameters;
    for(var i = 0; i < parseParams.length; ++i) {
        let param = createParam(parseParams[i]);
        funcInfo.params.push(param);
    }

    funcInfo.retType = parseFuncInfo.returns === '' ? parseFuncInfo.rtnType : parseFuncInfo.returns;
    funcInfo.rawStr = parseFuncInfo.debug;
    return funcInfo;
}

function createClassFunctions(parseFuncs) {
    let funcList = [];
    for(var i = 0; i < parseFuncs.length; ++i) {
        if (!(parseFuncs[i].constructor || parseFuncs[i].destructor)) { // 构造和析构方法不需要生成remote接口代码
            let funcInfo = createFuncInfo(parseFuncs[i]);
            funcList.push(funcInfo);
        }
    }
    return funcList;
}

function createClassInfo(parseClassInfo) {
    let classInfo = {
        "name": "",
        "namespace": [],
        "properties": [],
        "functions": [],
        "extends":[]
    }
    classInfo.name = parseClassInfo.name;
    classInfo.namespace = parseClassInfo.namespace.split('::');
    classInfo.functions = createClassFunctions(parseClassInfo.methods.public);

    return classInfo;
}

function analyzeClasses(rootInfo, parseClasses) {
    if (parseClasses.length == 0) {
        NapiLog.logError("Can not find any class.");
        return;
    }

    let firstClassName = null; // JSON集合中第一个class名称
    let serviceClassName = null;// JSON集合中带“@ServiceClass”注解的class名称
    let i = 0;
    for(var className in parseClasses) {
        if (++i == 1) {
            firstClassName = className;
        }

        let doxygen = parseClasses[className].doxygen;
        if (doxygen && doxygen.includes("@ServiceClass")) {
            serviceClassName = className;
            break;
        }
    }

    if (parseClasses.length == 1) {
        // h文件中只有唯一的一个类，基于该类的接口定义生成service
        rootInfo.serviceName = firstClassName;
        let classInfo = createClassInfo(parseClasses[firstClassName]);
        rootInfo.class.push(classInfo);
    } else {
        // h文件中有多个类，基于带@ServiceClass注解的类生成service
        if (serviceClassName == null) {
            NapiLog.logError("There must be one class that contains @ServiceClass annotations.");
            return;
        }
        rootInfo.serviceName = serviceClassName;
        let classInfo = createClassInfo(parseClasses[serviceClassName]);
        rootInfo.class.push(classInfo);
    }
}

function doAnalyze(hFilePath, cmdParam) {
    let parseResult = parseFileAll(hFilePath);
    parseResult.isInclude = false;
    AllParseFileList.push(parseResult);
    let rootInfo = {
        "serviceName": "",
        "nameSpace": [],
        "class": [],
        "includes": [],
        "using": [],
        "serviceId": cmdParam.serviceId == null ? "9002" : cmdParam.serviceId,
        "rawContent": parseResult.rawContent
    }

    analyzeNameSpace(rootInfo, parseResult);
    analyzeClasses(rootInfo, parseResult.classes);
    rootInfo.includes = parseResult.includes;
    rootInfo.using = parseResult.using;
    return rootInfo;
}

module.exports = {
    doAnalyze
}
