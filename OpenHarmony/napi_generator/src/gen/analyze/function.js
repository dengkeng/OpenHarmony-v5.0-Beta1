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
const { FuncType, NumberIncrease, isEnum, EnumValueType, enumIndex, isType, typeIndex, isOnObjCallback, 
    getOnObjCallbackType, getLogErrInfo } = require("../tools/common"); 
const { analyzeParams } = require("./params");
const { analyzeReturn } = require("./return");
const { NapiLog } = require("../tools/NapiLog");
const { randomInt } = require("crypto");
const { print } = require("../tools/tool");

function analyzeSubInterface(data) {
    let body = re.replaceAll(data, "\n", "").split(";") //  # replace(" ", "").
    let result = {
        value: [],
        function: [],
        parentNameList: [],
        childList: [],
        parentList: []
    }
    for (let i in body) {
        let t = body[i]
        while (t.length > 0 && t[0] === ' ') // 去除前面的空格
            t = t.substring(1, t.length)
        while (t.length > 0 && t[-1] === ' ') // 去除后面的空格
            t = t.substring(0, t.length - 1)
        if (t === "") break // 如果t为空直接返回
        let tt = re.match(" *([a-zA-Z0-9_]+) *: *([a-zA-Z_0-9<>,:{}[\\] ]+)", t)
        if (tt) { // 变量

            let valueName = re.getReg(t, tt.regs[1])
            let valueType = re.getReg(t, tt.regs[2])
            let index = valueType.indexOf("number")
            while (index !== -1) {
                valueType = valueType.replace("number", "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
                index = valueType.indexOf("number")
            }
            result.value.push({
                name: valueName,
                type: valueType
            })
        }
    }
    return result
}

function getFuncParaType(v, interfaceName, data, results) {
    let arrayType = re.match("(Async)*Callback<(Array<([a-zA-Z_0-9]+)>)>", v["type"])
    let parameter = v["type"]
    if (arrayType) {
        parameter = re.getReg(v["type"], arrayType.regs[2])
    }
    if (isEnum(parameter, data)) {
        let index = enumIndex(parameter, data)
        if (data.enum[index].body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_NUMBER) {
            v["type"] = v["type"].replace(parameter, "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
        } else if (data.enum[index].body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_STRING) {
            v["type"] = v["type"].replace(parameter, "string")
        } else {
            NapiLog.logError("analyzeFunction getFuncParaType is not support this type %s."
                .format(data.enum[index].body.enumValueType), getLogErrInfo);
            return null
        }
    }
    // interface & class中的方法参数类型是enum的情况
     else if (isEnum(parameter, results)) {
        let index = enumIndex(parameter, results)
        if (results.enum[index].body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_NUMBER) {
          v["type"] = v["type"].replace(parameter, "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
          v["realType"] = v["type"]
        } else if (results.enum[index].body.enumValueType === EnumValueType.ENUM_VALUE_TYPE_STRING) {
          v["type"] = v["type"].replace(parameter, "string")
        } else {
          NapiLog.logError("analyzeFunction getFuncParaType is not support this type %s."
              .format(results.enum[index].body.enumValueType), getLogErrInfo());
          return null
      }
    }

    let interfaceType = re.match("{([A-Za-z0-9_]+:[A-Za-z0-9_,]+)([A-Za-z0-9_]+:[A-Za-z0-9_]+)}$", v["type"])
    if (interfaceType) {
        v["type"] = interfaceName
    }

    if (parameter.indexOf("number") >= 0) {
        v["type"] = v["type"].replace("number", "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
        v["realType"] = v["type"]
    }

    // type的处理
    if (isType(parameter, data)) {
      let index = typeIndex(parameter, data)
      if (data.type[index].isEnum) {
        v["type"] = v["type"].replace(parameter, "string")
      }
    }
    return v
}

function analyzeFuncNoNameInterface(data, values, results) {
    values = re.replaceAll(re.replaceAll(values, " ", ""), "\n", "")    
    let interfaceName = ""    
    let matchNoName = "([:{<}>,;a-zA-Z_0-9]*)\\?*(:[A-Za-z0-9_,;]*)?:((Async)*Callback<)?{(([A-Za-z0-9_]+:"+
    "[A-Za-z0-9_,;]+)*)([A-Za-z0-9_]+:[A-Za-z0-9_]+)}(}|,|;|>)?$"
    let matchs = re.match(matchNoName, values)
    if (matchs) {
        let st = values.lastIndexOf("{")        
        let end = values.indexOf("}")
        let number = NumberIncrease.getAndIncrease();
        interfaceName = "AUTO_INTERFACE_%s".format(number)
        let interfaceBody = values.substring(st+1, end)
        let typeInterface = "{%s}".format(interfaceBody)
        values = re.replaceAll(values, typeInterface, interfaceName)
        interfaceBody = re.replaceAll(interfaceBody, ",", ";")
        if (Object.prototype.hasOwnProperty.call(data, "interface")) {
            data.interface.push({
                name: interfaceName,
                body: analyzeSubInterface(interfaceBody)
            })
        } else if (Object.prototype.hasOwnProperty.call(results, "interface")) {
            results.interface.push({
                name: interfaceName,
                body: analyzeSubInterface(interfaceBody)
            })
        } 
    }

    matchs = re.match(matchNoName, values)    
    if(matchs) {
        let resNoNameInter = analyzeFuncNoNameInterface(data, values)
        values = resNoNameInter.values
    }

    let result = {
        interfaceName: interfaceName,
        values: values
    }
    return result
}

function analyseSubReturn(ret, data, results) {
    // 匿名interface返回值 function fun4(input: string): { read: number; written: number }; 
    let tt = null
    if (ret.indexOf(":") > 0) {
        ret = re.replaceAll(re.replaceAll(ret, " ", ""), "\n", "")
        ret = re.replaceAll(ret, ",", ";")
        ret = ret.substring(1, ret.length - 1)
        tt = ret.split(";")
    }
    if (tt) {
         let len = tt.length
         let res = ""
         let interfaceName = ""
         for (let i=0; i<len; i++) {
             let regs1 = tt[i] + ";"
             res += regs1       
         }  

        let number = NumberIncrease.getAndIncrease();
        interfaceName = "AUTO_INTERFACE_%s".format(number)
        let interfaceBody = res        
        ret = interfaceName

        interfaceBody = re.replaceAll(interfaceBody, ",", ";")
        if (Object.prototype.hasOwnProperty.call(data, "interface")) {
            data.interface.push({
                name: interfaceName,
                body: analyzeSubInterface(interfaceBody)
            })
        } else if (Object.prototype.hasOwnProperty.call(results,"interface")) {
            results.interface.push({
                name: interfaceName,
                body: analyzeSubInterface(interfaceBody)
            })
        }
    }
    if (ret.indexOf("number") >= 0) {
        ret = ret.replaceAll("number", "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
    }
    return ret
}

function getObjCallFunc(results, onObjCbType, values, ret) {
    if (results !== undefined) {
        results.callFunction.push({
            "name": onObjCbType,
            "body": values,
            "ret": ret
        })
    }
}
function getFuncResult(name, funcType, values, ret, isStatic) {
    let result = {
        name: name,
        type: funcType,
        value: values,
        ret: ret,
        isStatic: isStatic
    }
    return result
}

function getArrowCallFunc(tmp, results) {
    let callbackFunc = null 

    if (tmp[2][0] !== undefined) {
        callbackFunc = tmp[2][0] // 当方法的参数是回调方法，并且回调方法写法为=>函数
    }  
    if (results !== undefined && callbackFunc !== null) {
      results.callFunction.push(callbackFunc)
    }
}

/**函数解析 */
function analyzeFunction(data, isStatic, name, values, ret, results, interfaceName = '') {
    let res = analyzeFuncNoNameInterface(data, values, results)
    let tmp
    let funcType
    
    if (res) {
        tmp = analyzeParams(name, res.values)
        if (tmp !== null) {
            values = tmp[0]
            funcType = tmp[1]
            getArrowCallFunc(tmp, results)
        }
    }

    tmp = analyzeReturn(ret)
    ret = tmp[0]
    if (tmp[1]) { // 返回类型为 Promise, 解析成等价的AsyncCallback方法
        funcType = FuncType.ASYNC
        // 返回值是Promise的匿名interface
        let paramTypeVal = analyseSubReturn(ret.substring(8, ret.length - 1), data, results);
        // 将返回值Promise<type>改为AsyncCallback<type>，作为方法的入参
        let paramType = ret.replace("Promise", "AsyncCallback")
        if (paramTypeVal) {
          // 匿名interface处理
          let paramAsync = paramType.substring(14, paramType.length - 1)
          paramType = paramType.replace(paramAsync, paramTypeVal);
        }
        values.push({name: "promise", optional: false, type: paramType, realType: paramType})
        ret = "void" // 返回值由Promise改为void，与AsyncCallback接口保持一致
    }
    for (let j in values) {
        let v = values[j]
        v = getFuncParaType(v, res.interfaceName, data, results)
        if (v === null) {
            NapiLog.logError("analyzeFunction is not support this type %s.".format(v), getLogErrInfo());
        }
    }
    ret = analyseSubReturn(ret, data, results)
    let result = getFuncResult(name, funcType, values, ret, isStatic)
    if (isOnObjCallback(name)) {
        let onObjCbType = getOnObjCallbackType(name, interfaceName)
        getObjCallFunc(results, onObjCbType, values, ret)
    }    
    return result
}

module.exports = {
    analyzeFunction,
    analyzeSubInterface,
    getFuncParaType,
    analyzeFuncNoNameInterface,
    analyseSubReturn
}