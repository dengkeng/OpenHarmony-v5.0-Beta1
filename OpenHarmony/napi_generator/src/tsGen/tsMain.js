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
const { NapiLog } = require("../gen/tools/NapiLog");
const { writeFile } = require("../gen/tools/FileRW");
const path = require('path')
const re = require("../gen/tools/re");
const fs = require("fs");
const os = require("os");

function parseFileAll(hFilePath) {
    let execSync = require("child_process").execSync
    let cmd = ""
    if(fs.existsSync("./src/tsGen/header_parser.py")) {
        // call python file (for debug test)
        cmd = "python ./src/tsGen/header_parser.py " + hFilePath
    } else {
        // call exe file (for real runtime)
        let sysInfo = os.platform()
        let execPath = path.dirname(process.execPath)
        let exeFile = sysInfo === 'win32' ? path.join(execPath, "header_parser.exe") : 
                                            path.join(execPath, "header_parser")
        cmd = exeFile + " " + hFilePath
    }

    let parseResult = null
    let stdout = execSync(cmd)
    parseResult = JSON.parse(stdout.toString()).result
    return parseResult
}

function createNameSpaceInfo(parseNameSpaceInfo) {
    let nameSpaceInfo = {
        "name": "",
        "classes": [],
        "functions": []
    }
    nameSpaceInfo.name = parseNameSpaceInfo
    return nameSpaceInfo
}

function analyzeNameSpace(rootInfo, parseResult) {
    let parseNameSpaces = parseResult.namespaces
    for(var i = 0; i < parseNameSpaces.length; ++i) {
        let nameSpaceInfo = createNameSpaceInfo(parseNameSpaces[i])
        rootInfo.namespaces.push(nameSpaceInfo)
    }
}

function isStringType(cType) {
    switch(cType) {
        case 'string':
        case 'std::string':
        case 'char':
        case 'wchar_t':
        case 'char16_t':
        case 'char32_t':
            return true
        default:
            return false
    }
}

function isBoolType(cType) {
    if (cType == 'bool') {
        return true
    }
    return false
}

function isNumberType(cType) {
    switch(cType) {
        case 'short':
        case 'int':
        case 'uint32_t':
        case 'size_t':
        case 'long':
        case 'long long':
        case 'float':
        case 'double':
        case 'long double':
        case 'int16_t':
        case 'uint16_t':
        case 'int32_t':
        case 'int64_t':
        case 'uint64_t':
        case 'double_t':
        case 'float_t':
            return true
        default:
            return false
    }
}

function basicC2js(cType) {
    let jsType = ""
    if (isStringType(cType)) {
        jsType = 'string'
    } else if (isBoolType(cType)) {
        jsType = 'boolean'
    } else if (isNumberType(cType)) {
        jsType = 'number'
    } else {
        jsType = cType
    }
    return jsType
}

function getJsTypeFromC(cType, typeInfo) {
    let basicCtype = cType
    let matchs = re.match("(std::)?vector<([\x21-\x7e ]+)>", basicCtype);
    if (matchs) {
        basicCtype = re.getReg(basicCtype, matchs.regs[2]).trim()
        typeInfo.array = 1
    }

    let unsignedIdx = basicCtype.indexOf('unsigned')
    if ( unsignedIdx >= 0) {
        // cut off the keywords 'unsigned'
        basicCtype = basicCtype.substring(unsignedIdx + 8, basicCtype.length).trim()
    }
    let jsType = basicC2js(basicCtype)
    if (typeInfo.array) {
        jsType = "Array<%s>".format(jsType)
    }
    return jsType
}

function createParam(parseParamInfo) {
    let param = {
        "name": "",
        "type": ""
    }
    param.name = parseParamInfo.name
    let rawType = getJsTypeFromC(parseParamInfo.raw_type, parseParamInfo)
    param.type = rawType

    return param
}

function createFuncInfo(parseFuncInfo, isClassFunc) {
    let funcInfo = {
        "name": "",
        "params": [],
        "namespace": "",
        "retType": "",
        "static":""
    }
    funcInfo.name = parseFuncInfo.name
    funcInfo.namespace = parseFuncInfo.namespace
    let tokenIndex = funcInfo.namespace.indexOf('::')
    if (tokenIndex >= 0) {
        // delete '::' in namespace, get the pure space name.
        funcInfo.namespace = funcInfo.namespace.substring(0, tokenIndex)
    }

    let parseParams = parseFuncInfo.parameters
    for(var i = 0; i < parseParams.length; ++i) {
        let param = createParam(parseParams[i])
        funcInfo.params.push(param)
    }

    funcInfo.isClassFunc = isClassFunc

    if (parseFuncInfo.static && isClassFunc) {
        funcInfo.static = "static "
    } 
    let retType = parseFuncInfo.returns === '' ? parseFuncInfo.rtnType : parseFuncInfo.returns
    funcInfo.retType = getJsTypeFromC(retType, parseFuncInfo)
    return funcInfo
}

function putFuncIntoNamespace(funcInfo, namespaces) {
    for (var i = 0; i < namespaces.length; ++i) {
        if (namespaces[i].name === funcInfo.namespace) {
            namespaces[i].functions.push(funcInfo)
            return
        }
    }
    NapiLog.logError('The namespace [%s] of function %s is not found.'.format(funcInfo.namespace, funcInfo.name));
}

function analyzeRootFunction(rootInfo, parseResult) {
    let parseFunctions = parseResult.functions
    for(var i = 0; i < parseFunctions.length; ++i) {
        let funcInfo = createFuncInfo(parseFunctions[i], false)
        if (parseFunctions[i].namespace != '') {
            // function in namespace
            putFuncIntoNamespace(funcInfo, rootInfo.namespaces)
        } else {
            // function without namespace, put on root
            rootInfo.functions.push(funcInfo)
        }
    }
}

function createProperties(parseProperties) {
    let propertyList = []
    for (var i = 0; i < parseProperties.length; ++i) {
        let property = {}
        property.name = parseProperties[i].name
        property.type = getJsTypeFromC(parseProperties[i].raw_type, parseProperties[i])
        propertyList.push(property)
    }
    return propertyList
}

function createClassFunctions(parseFuncs) {
    let funcList = []
    for(var i = 0; i < parseFuncs.length; ++i) {
        let funcInfo = createFuncInfo(parseFuncs[i], true)
        funcList.push(funcInfo)
    }
    return funcList
}

function createClassInfo(parseClassInfo) {
    let classInfo = {
        "name": "",
        "namespace": "",
        "properties": [],
        "functions": [],
        "extends":[]
    }
    classInfo.name = parseClassInfo.name
    classInfo.namespace = parseClassInfo.namespace
    classInfo.properties = createProperties(parseClassInfo.properties.public)
    classInfo.functions = createClassFunctions(parseClassInfo.methods.public)

    return classInfo
}

function putClassIntoNamespace(classInfo, namespaces) {
    for (var i = 0; i < namespaces.length; ++i) {
        if (namespaces[i].name === classInfo.namespace) {
            namespaces[i].classes.push(classInfo)
            return
        }
    }
    NapiLog.logError('The namespace [%s] of class %s is not found.'.format(classInfo.namespace, classInfo.name));
}

function analyzeClasses(rootInfo, parseResult) {
    let parseClasses = parseResult.classes;

    for(var className in parseClasses) {
        let classInfo = createClassInfo(parseClasses[className])
        if (classInfo.namespace != '') {
            // class in namespace
            putClassIntoNamespace(classInfo, rootInfo.namespaces)
        } else {
            // class without namespace, put on root
            rootInfo.classes.push(classInfo)
        }
    }
}

function getTab(tabLv) {
    let tab = ""
    for(var i = 0; i < tabLv; ++i) {
        tab += "    "
    }
    return tab
}

function genFunction(func, tabLv, needDeclare = false) {
    let tab = getTab(tabLv)
    let funcPrefix = func.isClassFunc ? "" : "function "
    let funcParams = ""
    for (var i = 0; i < func.params.length; ++i) {
        funcParams += i > 0 ? ", " : ""
        funcParams += func.params[i].name + ": " + func.params[i].type
    }
    let declareStr = needDeclare ? "declare " : ""
    return "%s%s%s%s%s(%s): %s;\n".format(tab, declareStr, funcPrefix, func.static, func.name, funcParams, func.retType)
}

function genClass(classInfo, tabLv, needDeclare = false) {
    let tab = getTab(tabLv)
    let declareStr = needDeclare ? "declare " : ""
    let tsClass = tab + declareStr + "class " + classInfo.name + " {\n"
    let tab1 = getTab(tabLv+1)
    for (var i = 0; i < classInfo.properties.length; ++i) {
        tsClass += "%s%s: %s;\n".format(tab1, classInfo.properties[i].name, classInfo.properties[i].type)
    }
    for (var i = 0; i < classInfo.functions.length; ++i) {
        tsClass += genFunction(classInfo.functions[i], tabLv+1)
    }
    tsClass += tab + "}\n"
    return tsClass
}

function genNamespace(namespace, tabLv) {
    let tab = getTab(tabLv)
    let tsNamespace = tab + "declare namespace %s {\n".format(namespace.name)
    for(var i = 0; i < namespace.functions.length; ++i) {
        tsNamespace += genFunction(namespace.functions[i], tabLv+1)
    }
    for(var i = 0; i < namespace.classes.length; ++i) {
        tsNamespace += genClass(namespace.classes[i], tabLv+1)
    }
    tsNamespace += tab + "}\n"
    return tsNamespace
}

function genTsContent(rootInfo) {
    let tsContent = rootInfo.needCallback ? "import { AsyncCallback, Callback } from './../basic';\n\n" : ""

    for(var i = 0; i < rootInfo.classes.length; ++i) {
        tsContent += genClass(rootInfo.classes[i], 0, true)
    }

    for(var i = 0; i < rootInfo.namespaces.length; ++i) {
        tsContent += genNamespace(rootInfo.namespaces[i], 0)
    }

    for(var i = 0; i < rootInfo.functions.length; ++i) {
        tsContent += genFunction(rootInfo.functions[i], 0, true)
    }

    if (rootInfo.namespaces.length > 0) {
        // export the first namespace as default
        tsContent += "\nexport default %s;".format(rootInfo.namespaces[0].name)
    }

    return tsContent
}

function doGenerate(hFilePath, destDir) {
    let parseResult = parseFileAll(hFilePath)
    let rootInfo = {
        "namespaces": [],
        "classes": [],
        "functions": [],
        "needCallback": false
    }
    analyzeNameSpace(rootInfo, parseResult)
    analyzeRootFunction(rootInfo, parseResult)
    analyzeClasses(rootInfo, parseResult)
    let hfileName = path.basename(hFilePath, ".h")
    let tsFilePath = re.pathJoin(destDir, "%s.d.ts".format(hfileName))
    let tsContent = genTsContent(rootInfo)
    writeFile(tsFilePath,tsContent)
}

module.exports = {
    doGenerate
}
