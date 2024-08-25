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
const ts = require('typescript');
const fs = require('fs');
const re = require("./tools/re");
const { getLicense, checkOutBody } = require("./tools/tool");
const { analyzeNamespace } = require("./analyze/namespace");
const { NapiLog } = require("./tools/NapiLog");

// 读取和解析.d.ts文件
const filePath = '@ohos.test.d.ts';
// const sourceCode = fs.readFileSync(filePath, 'utf-8');
// const sourceFile = ts.createSourceFile(filePath, sourceCode, ts.ScriptTarget.Latest, true);
// let statements = sourceFile.statements

// 打印语法树
function stringifyWithoutCircular(obj) {
    const cache = new Set();
    return JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
        if (cache.has(value)) {
            return; // Skip circular references
        }
        cache.add(value);
        }
        return value;
    });
    }


function analyzeFileRaw(fn) {
    const sourceCode = fs.readFileSync(filePath, 'utf-8');
    const sourceFile = ts.createSourceFile(filePath, sourceCode, ts.ScriptTarget.Latest, true);
    let statements = sourceFile.statements

   // console.log(stringifyWithoutCircular(sourceFile));

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

    if (statements.length === 0 ) {
        return null;
    }    
    
    let imports = statements[0].getText();
    if (imports != null) {
        result.imports.push(imports);
    }

    let data = statements[0].getFullText();
    let licenseData = getLicense(data);
    if (null != licenseData) {
        result.declareLicense.push(licenseData)
    }

    // let impordts = statements[1].getText();

    // let ff = statements[1].getChildren();
    // let ffa = statements[1].getChildAt(1);
    // let ffb = statements[1].getChildCount();
    // let ffc = statements[1].getLastToken();
    // let xx = statements[1].getEnd();

    // let exportsInfo = statements[2].getText();

    // let ff = statements[2].end
    // let gg = statements[2].
    // let exportName = statements[2].expression.escapedText
    
    // result.exportDefault.push(exportName);

    return analyzeRaw(statements, result)
}

function analyzeRaw(statements, result) {
    while (true) {
        let exportsInfo = statements[2].getText();
        let matchs = re.match("export default ([a-zA-Z0-9_]+);", exportsInfo);
        if (matchs != null) {
            let exportName = re.getReg(exportsInfo, matchs.regs[1])
            // data = re.removeReg(data, matchs.regs[0]);
            result.exportDefault.push(exportName)
        }

        // data = re.replaceAll(data, "\n{", "{");
        // let matchType = analyzeMatchType(matchs, data, result)
        // if (matchType != null) {
        //     data = matchType[0]
        //     if (matchType[1] != null) {
        //         result = matchType[1]
        //     }            
        // }
        let data = statements[1].getText();
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
        
        // if (oldData == data) {
        //   NapiLog.logError("\nvvv 解析文件失败 vvv");
        //   NapiLog.logError("[", data.substring(0, data.length > 64 ? 64 : data.length), "]");
        //     break;
        // }
        return result;

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
    analyzeFileRaw
}