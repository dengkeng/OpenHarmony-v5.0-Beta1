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
const re = require("../tools/re");
const { removeEmptyLine, checkOutBody, addUniqFunc2List } = require("../tools/tool");
const { analyzeFunction } = require("./function");
const { analyzeInterface, parseNotes } = require("./interface");
const { analyzeEnum } = require("./enum");
const { NapiLog } = require("../tools/NapiLog");
const { analyzeType, analyzeType2, analyzeType2Result } = require("./type");
const { NumberIncrease, EnumValueType, getLogErrInfo } = require("../tools/common");

function preProcessData(data) {
    data = data.indexOf("//") < 0 ? data : parseNotes(data);   
    data = re.replaceAll(data, "\n{", "{");
    return data;
}

function getDataByResult(result) {
    let data = null
    if (result !== null) {
        data = result
    }
    return data
}

/**namespace解析 */
function analyzeNamespace(data) {
    let result = {
        exports: [],
        enum: [],
        const: [],
        type: [],
        function: [],
        interface: [],
        class: [],
        namespace: [],
        callFunction: [],
    }
    while (data !== '\n') {
        let oldData = data
        data = removeEmptyLine(data)
        let matchs = re.match(" *\n*", data)   
        data = preProcessData(data);
        // 只剩下空格和回车时，解析完成
        if (matchs && matchs.regs[0][1] === data.length) break
        let parseEnumResult = parseEnum(matchs, data, result)
        data = getDataByResult(parseEnumResult)
        
        result = parseEnumType(result);

        let parseInterResult = parseInterface(matchs, data, result)
        data = getDataByResult(parseInterResult)

        let parseFunctionResult = parseFunction(matchs, data, result)
        data = getDataByResult(parseFunctionResult)
        
        let parseTypeResult = parseType(matchs, data, result)
        data = getDataByResult(parseTypeResult)

        let parseClassResult = parseClass(matchs, data, result)
        data = getDataByResult(parseClassResult)

        let parseNamespaceResult = parseNamespace(matchs, data, result)
        data = getDataByResult(parseNamespaceResult)

        data = removeReg(matchs, data, result)
        if (oldData === data) {
            NapiLog.logError("解析Namespace失败");
            NapiLog.logError("[", data.substring(0, data.length > 128 ? 128 : data.length), "]");
            break;
        }
    }
    return result
}

function parseEnumType(result) {
    if (null === result) {
        return null;
    }

    for (let i in result.enum) {
        let enumm = result.enum[i]

        // interface 匹配           
        for (let i in result.interface) {
          let interf = result.interface[i]
          if(!isValidValue(interf)) {
            NapiLog.logError("parseEnumType interf is null!");
            return null;
          }

          // function 匹配
          for (let j in interf.body.function) {
            let func = interf.body.function[j];
            if(!isValidValue(func)) {
                NapiLog.logError("parseEnumType func is null!");
                return null;
            }
            
            // 参数匹配
            for (let k in func.value) {
                let v = func.value[k];
                if(!isValidValue(v)) {
                    NapiLog.logError("parseEnumType func.value is null!");
                    return null;
                }

                if (v.type ===  enumm.name) {
                    if (enumm.body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_NUMBER) {
                        v.type = "NUMBER_TYPE_" + NumberIncrease.getAndIncrease();
                    } else if (enumm.body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_STRING) {
                        v.type = "string";
                    } else {
                        NapiLog.logError("parseEnumType for interface function value is not support this type %s."
                            .format(enumm.body.enumValueType), getLogErrInfo());
                        return null;
                    }
                    result.interface[i].body.function[j].value[k].type = v.type;                    
                }                
            }
          }          
        }
    }
    return result
}

function parseNamespace(matchs, data, result) {
    matchs = re.match("(export )*namespace ([a-zA-Z0-9]+) ({)", data)
    if (matchs) {
        let namespaceName = re.getReg(data, matchs.regs[2])
        let namespaceBody = checkOutBody(data, matchs.regs[3][0], null, true)
        result.namespace.push({
            name: namespaceName,
            body: analyzeNamespace(namespaceBody)
        })
        data = data.substring(matchs.regs[3][0] + namespaceBody.length + 2, data.length)
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(namespaceName)
        }
    }
    return data
}

function parseClass(matchs, data, result) {
    matchs = re.match(
        "(export )*class ([A-Za-z_0-9]+)(<T>)* *(extends [a-zA-Z_0-9, ]+)* *(implements [a-zA-Z_0-9, ]+)* *({)"
        , data)
    if (matchs) {
        // class类型也解析成interface结构，该结构在后面生成C++代码时会按napi_define_class处理成C++的class
        return createInterfaceData(matchs, data, result)
    }
    return data
}

function parseEnum(matchs, data, result) {
    matchs = re.match("(export )*enum *([A-Za-z_0-9]+) *({)", data)
    if (matchs !== null) {
        let enumName = re.getReg(data, matchs.regs[2]);
        let enumBody = checkOutBody(data, matchs.regs[3][0], null, null)
        result.enum.push({
            name: enumName,
            body: analyzeEnum(enumBody.substring(1, enumBody.length - 1))
        })
        data = data.substring(matchs.regs[3][0] + enumBody.length)
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(enumName)
        }
    }
    matchs = re.match("(export )*const ([A-Za-z_0-9]+) *[:=]{1} ([A-Za-z_0-9]+);", data)
    if (matchs) {
        let constName = re.getReg(data, matchs.regs[1])
        result.const.push({
            name: constName,
            body: re.getReg(data, matchs.regs[2])
        })
        data = re.removeReg(data, matchs.regs[0])
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(constName)
        }
    }
    return data
}

function isValidValue(value) {
    if (value === null || value === undefined) {
      return false;
    }
    return true;
}

function getTypeInfo(result, typeName, typeType, isEnum) {
    if (!isValidValue(result) || !isValidValue(result.type)) {
        NapiLog.logError("getTypeInfo: result or result.type is invalid!");
    }
    result.type.push({
        name: typeName,
        body: typeType,
        isEnum: isEnum
    })
}

function parseType(matchs, data, result) {
    matchs = re.match("(export )*type ([a-zA-Z]+) *= *([\\(\\):=a-zA-Z<> |]+);", data)
    if (matchs) {
        let typeName = re.getReg(data, matchs.regs[2]);
        let typeType = re.getReg(data, matchs.regs[3]);
        let index = typeType.indexOf("number")
        if (index !== -1) {
          typeType = typeType.replace("number", "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
        }
        getTypeInfo(result, typeName, typeType, false);
        data = re.removeReg(data, matchs.regs[0])
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(typeName)
        }
    }

    matchs = re.match("(export )*type ([a-zA-Z]+) *= *([\\(\\):=a-zA-Z<> |\n']+);", data)
    if (matchs) {
        let typeName = re.getReg(data, matchs.regs[2]);
        let typeBody = re.getReg(data, matchs.regs[3]);

        getTypeInfo(result, typeName, analyzeType2(typeBody.substring(1, typeBody.length - 1)), true);
        data = re.removeReg(data, matchs.regs[0])
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(typeName)
        }
    }

    matchs = re.match("(export )*type ([a-zA-Z]+) *= *({)", data)
    if (matchs) {
        let typeName = re.getReg(data, matchs.regs[2]);
        let typeBody = checkOutBody(data, matchs.regs[3][0], null, true)
        if (typeBody === null) {
            NapiLog.logError("ParseType typeBody is null!");
        }
        let bodyObj = analyzeType(typeBody.substring(1, typeBody.length - 1), result.type)
        getTypeInfo(result, typeName, bodyObj, false);
        data = data.substring(matchs.regs[3][0] + typeBody.length + 2, data.length)
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(typeName)
        }
    }
    return data
}

function parseFunction(matchs, data, result) {
    matchs = re.match("(export )*function (\\$*[A-Za-z0-9_]+) *(\\()", data)
    if (null == matchs) {
        matchs = re.match("(export )*function (static )*(\\$*[A-Za-z0-9_]+) *(\\()", data)
    }
    if (null == matchs) {
        matchs = re.match("(export )*function (static )*(register\\$*[A-Za-z0-9_]+) *(\\()", data)
    }
    if (matchs) {
        let funcName = re.getReg(data,
            matchs.regs.length === 5 ? [matchs.regs[2][0], matchs.regs[3][1]] : matchs.regs[2])
        let funcValue = checkOutBody(data,
            matchs.regs.length === 5 ? matchs.regs[4][0] : matchs.regs[3][0], ["(", ")"], null)
        let funcRet = checkOutBody(data.substring(matchs.regs.length === 5 ?
            matchs.regs[4][0] : matchs.regs[3][0] + funcValue.length), 0, ["", "\n"], null)
        data = data.substring(matchs.regs.length === 5 ?
            matchs.regs[4][0] : matchs.regs[3][0] + funcValue.length + funcRet.length)
        let matchFunc = re.match(" *: *([A-Za-z0-9_<>{}\\[\\]:;, .=]+);*", funcRet)
        let matchFuncArray = re.match(" *: *([A-Za-z0-9]+)(\\[]);*", funcRet)
        if (matchFuncArray) {
            funcRet = re.getReg(funcRet, [matchFuncArray.regs[1][0], matchFuncArray.regs[2][1]])
        }
        else if (matchFunc) {
            funcRet = re.getReg(funcRet, matchFunc.regs[1])
        }
        else {
            funcRet = "void"
        }
        funcRet = re.replaceAll(re.replaceAll(funcRet, " ", ""), "\n", "")        

        if(funcRet[funcRet.length-1] === ";"){
            funcRet = funcRet.substring(0, funcRet.length-1)
        }
        let funcDetail = analyzeFunction(
            result, false, funcName, funcValue.substring(1, funcValue.length - 1), funcRet, result)
        if (funcDetail !== null) {
            // 完全一样的方法不重复添加 (如同名同参的AsyncCallback和Promise方法)
            addUniqFunc2List(funcDetail, result.function)
        }
        if (matchs.regs[1][0] !== -1) {
            result.exports.push(funcName)
        }
    }
    return data
}

/**
 * 提取当前类继承或实现的父类名称列表
 * @param firstKey 继承/实现关键字 (extends或implements)
 * @param secondKey 继承/实现关键字 (extends或implements)
 * @param parentStr 正则匹配到的继承语句 (如 extends xx1, xx2 implements yy1, yy2)
 * @returns 继承的名称列表 ([xx1, xx2, yy1, yy2])
 */
function getParentNameList(firstKey, secondKey, parentStr) {
    if (parentStr === '') {
        return []
    }

    let firstParents = ''
    let secondParents = ''
    if (parentStr.indexOf(secondKey) > 0) {
        // 同时出现extends和implements关键字的情况 (如 extends xx1, xx2 implements yy1, yy2)
        firstParents = parentStr.split(secondKey)[0].split(firstKey)[1]
        secondParents = parentStr.split(secondKey)[1].trim()
    } else {
        // 只有extends或implements一种关键字的情况 (如 extends xx1, xx2 或者 implements yy1, yy2)
        firstParents = parentStr.split(firstKey)[1]
    }

    let nameList = firstParents.split(",")
    if (secondParents !== '') {
        let secondList = secondParents.split(",")
        nameList.push(...secondList)
    }

    return nameList
}

/**
 * 创建interface数据结构
 * @param matchs 正则匹配对象
 * @param data 原始ts文件内容
 * @param result 解析后的ts数据结构
 * @returns data 原始ts文件内容中剩余未解析的部分
 */
function createInterfaceData (matchs, data, result) {
    let interfaceName = re.getReg(data, matchs.regs[2])
    let interfaceBody = checkOutBody(data, matchs.regs[6][0], null, null)
    let bodyObj = analyzeInterface(interfaceBody.substring(1, interfaceBody.length - 1), result.interface, 
      result, interfaceName)
    let extendsParent = re.getReg(data, matchs.regs[4])
    let implementParent = re.getReg(data, matchs.regs[5])
    bodyObj.parentNameList = []
    if(extendsParent !== '') {
        bodyObj.parentNameList = getParentNameList("extends", "implements", extendsParent)
    }
    if(implementParent !== '') {
        bodyObj.parentNameList = getParentNameList("implements", "extends", implementParent)
    }
    for (let i in bodyObj.parentNameList) {
        bodyObj.parentNameList[i] = bodyObj.parentNameList[i].trim()
        if (bodyObj.parentNameList[i] === interfaceName) {
            // 接口不能自己继承自己
            NapiLog.logError("The interface [%s] can not extends with itself.".format(interfaceName))
            return data
        }
    }

    bodyObj.parentList = [] // 该接口继承的父类型列表
    bodyObj.childList = [] // 继承自该接口的子类型列表
    
    result.interface.push({
        name: interfaceName,
        body: bodyObj
    })
    let rr = matchs.regs[6][0]
    rr = matchs.regs[6][0] + interfaceBody.length
    let tmp = data[rr]
    data = data.substring(matchs.regs[6][0] + interfaceBody.length, data.length)
    if (matchs.regs[1][0] !== -1) {
        result.exports.push(interfaceName)
    }
    return data
}

function parseInterface(matchs, data, result) {
    matchs = re.match(
        "(export )*interface ([A-Za-z_0-9]+)(<T>)* *(extends [a-zA-Z_0-9, ]+)* *(implements [a-zA-Z_0-9, ]+)* *({)"
        , data)
    if (matchs) {
        return createInterfaceData (matchs, data, result)
    }
    return data
}

function removeReg(matchs, data, result) {
    matchs = re.match("export { ([a-zA-Z]+) };", data)
    if (matchs) {
        let exportName = re.getReg(data, matchs.regs[1])
        result.exports.push(exportName)
        data = re.removeReg(data, matchs.regs[0])
    }
    matchs = re.match("export import [a-zA-Z]+ = [a-zA-Z\\.]+;", data)
    if (matchs) {
        data = re.removeReg(data, matchs.regs[0])
    }
    matchs = re.match("readonly [a-zA-Z]+: [a-z\\[\\]]+;*", data)
    if (matchs) {
        data = re.removeReg(data, matchs.regs[0])
    }
    return data
}
module.exports = {
    analyzeNamespace,
    parseNamespace,
    parseEnum,
    parseFunction,
    parseInterface,
    parseClass,
    parseType
}