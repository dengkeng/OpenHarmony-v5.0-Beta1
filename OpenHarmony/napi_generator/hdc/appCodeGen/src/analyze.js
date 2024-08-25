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
const re = require("./tools/re");
const { removeExplains, removeEmptyLine, replaceTab, checkOutBody, getLicense } = require("./tools/tool");
const { NumberIncrease } = require("./tools/common");
const { readFile } = require("./tools/FileRW");

const { analyzeNamespace } = require("./analyze/namespace");
const { NapiLog } = require("./tools/NapiLog");

function analyzeFile(fn) {
    NumberIncrease.reset();
    let data = readFile(fn);
    let licenseData = getLicense(data)
    // 去除注释
    data = removeExplains(data)
    // 去除空行
    data = removeEmptyLine(data)
    // 去除Tab
    data = replaceTab(data)
    let result = {
        exportDefault: [],
        exports: [],
        imports:[],
        declareType: [],
        declareFunction: [],
        declareNamespace: [],
        declareInterface: [],
        declareLicense: [],
    }
    while (true) {
        // import
        let matchImport = re.search("import ([{}A-Za-z ,]+) from [\"']{1}([@_./a-zA-Z]+)[\"']{1};*", data);
        if (matchImport != null) {
            result.imports.push(re.getReg(data, matchImport.regs[0]))
            data = re.removeReg(data, matchImport.regs[0]);
        }
        else break;
    }

    if (null != licenseData) {
        result.declareLicense.push(licenseData)
    }
    return analyze(data, result)
}

function analyze(data, result) {
    while (true) {
        let oldData = data
        data = removeEmptyLine(data)
        let matchs = re.match(" *\n*", data)
        // 只剩下空格和回车时，解析完成
        if (matchs && matchs.regs[0][1] == data.length) break
        matchs = re.match("export default ([a-zA-Z0-9_]+);", data);
        if (matchs != null) {
            let exportName = re.getReg(data, matchs.regs[1])
            data = re.removeReg(data, matchs.regs[0]);
            result.exportDefault.push(exportName)
        }
        data = re.replaceAll(data, "\n{", "{");
        let matchType = analyzeMatchType(matchs, data, result)
        if (matchType != null) {
            data = matchType[0]
            if (matchType[1] != null) {
                result = matchType[1]
            }            
        }
        let namespace = analyzeMatchNamespace(matchs, data, result)
        if (namespace != null) {
            data = namespace[0]
            result = namespace[1]
        }
        let interface = analyzeMatchInterface(matchs, data, result)
        if (interface != null) {
            data = interface[0]
            result = interface[1]
        }
        let functionMatch = analyzeMatchFunction(matchs, data, result)
        if (functionMatch != null) {
            data = functionMatch[0]
            result = functionMatch[1]
        }
        if (oldData == data) {
            NapiLog.logError("\nvvv 解析文件失败 vvv");
            NapiLog.logError("[", data.substring(0, data.length > 64 ? 64 : data.length), "]");
            break;
        }
    }
    return result
}

function analyzeMatchNamespace(matchs, data, result) {
    matchs = re.match("declare namespace ([a-zA-Z_0-9]+) *({)", data);
    // 解析declare
    if (matchs != null) {
        let namespaceName = re.getReg(data, matchs.regs[1])
        let namespaceData = checkOutBody(data, matchs.regs[2][0], null, true)
        data = data.substring(matchs.regs[2][1] + namespaceData.length + 1, data.length)
        result.declareNamespace.push({
            name: namespaceName,
            body: analyzeNamespace(namespaceData)
        })
    }
    return [data, result]
}

function analyzeMatchInterface(matchs, data, result) {
    matchs = re.match("(export )*(declare )*interface ([A-Za-z_0-9<>= ]+) (extends [a-zA-Z]+ )*({)", data)
    if (matchs) {
        let interfaceName = re.getReg(data, matchs.regs[3])
        let interfaceData = checkOutBody(data, matchs.regs[5][0], null, true)
        data = data.substring(matchs.regs[5][1] + interfaceData.length + 1, data.length)
        result.declareInterface.push({
            name: interfaceName,
            body: {}
        })
    }
    return [data, result]
}

function analyzeMatchFunction(matchs, data, result) {
    matchs = re.match("declare function ([A-Za-z0-9_]+)\\(([\n a-zA-Z:;=,_0-9?<>{}|]*)\\) *:"
        + "*([A-Za-z0-9_<>{}:, .]+);*", data)
    if (matchs) {
        let functionName = re.getReg(data, matchs.regs[1])
        let functionBody = re.getReg(data, matchs.regs[2])
        data = re.removeReg(data, matchs.regs[0])
        result.declareFunction.push({
            name: functionName,
            body: functionBody
        })
    }
    return [data, result]
}

function analyzeMatchType(matchs, data, result) {
    matchs = re.match("(export )*type ([a-zA-Z]+) *= *([()a-zA-Z :=>,\"| ]+);", data)
    if (matchs) {
        let exportName = re.getReg(data, matchs.regs[2])
        let exportBody = re.getReg(data, matchs.regs[3])
        data = re.removeReg(data, matchs.regs[0]);
        result.declareType.push({
            name: exportName,
            body: exportBody
        })
        if (matchs.regs[1][0] != -1) {
            result.exports.push(exportName)
        }
    }

    matchs = re.match("(export )*type ([a-zA-Z]+) *= *(\n{)", data)
    if (matchs) {
        let exportName = re.getReg(data, matchs.regs[2])
        let exportBody = checkOutBody(data, matchs.regs[3][0], null, true)
        data = data.substring(matchs.regs[3][1] + exportBody.length + 2, data.length)
        result.declareType.push({
            name: exportName,
            body: exportBody
        })
        if (matchs.regs[1][0] != -1) {
            result.exports.push(exportName)
        }
    }
    return [data, result]
}

module.exports = {
    analyzeFile
}