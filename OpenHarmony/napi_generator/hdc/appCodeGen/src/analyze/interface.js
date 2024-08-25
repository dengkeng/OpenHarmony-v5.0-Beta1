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
const { NumberIncrease } = require("../tools/common");
const { addUniqFunc2List } = require("../tools/tool");
const { analyzeFunction } = require("./function");

/* 匿名interface */
function analyzeNoNameInterface(valueType, valueName, rsltInterface) {
    valueType = re.replaceAll(valueType, " ", "")
    let matchs = re.match("{(([A-Za-z0-9_]+:[A-Za-z0-9_,;]+)*)([A-Za-z0-9_]+:[A-Za-z0-9_]+)}$", valueType)
    if (matchs) {
        let number = NumberIncrease.getAndIncrease();
        let interfaceTypeName = 'AUTO_INTERFACE_%s_%s'.format(valueName, number)
        let interfaceBody = valueType.substring(1, valueType.length-1)
        interfaceBody = re.replaceAll(interfaceBody, ",", ";\n")                
        rsltInterface.push({
            name: interfaceTypeName,
            body: analyzeInterface(interfaceBody, rsltInterface)
        })                
        valueType = interfaceTypeName
    }
    return valueType
}

/* 去除单行注释// */
function parseNotes(data) {
    let notes = data.indexOf("//") >= 0 ? data.substring(data.indexOf("//"), data.length) : "";          
    while(notes != "") {
        notes = notes.substring(0, notes.indexOf("\n")); 
        data = data.replace(notes, "");
        notes = ""
        let st = data.indexOf("//");
        if(st >= 0) {
            notes = data.substring(st, data.length);
        }
    }
    return data
}

/**interface解析 */
function analyzeInterface(data, rsltInterface = null, results, interfaceName = '') { // same as class
    let body = data
    body = body.indexOf("//") < 0 ? body : parseNotes(body)
    let arr  =  [...body.matchAll(/;\s*\n+/g)]
    for (let i = 0; i < arr.length; i++) {
        let result = arr[i]
        body = re.replaceAll(body, result[0], ";\n")
    }
    body = body.split(";\n")
    let result = {
        value: [],
        function: []
    }
    for (let i in body) {
        let t = body[i]
        t = re.replaceAll(t, "\n", "")
        while (t.length > 0 && t[0] == ' ') t = t.substring(1, t.length) // 去除前面的空格
        while (t.length > 0 && t[-1] == ' ') t = t.substring(0, t.length - 1) // 去除后面的空格   
        if (t == "") break // 如果t为空直接返回
        let tt = re.match(" *([a-zA-Z0-9_]+)(\\?*)*: *([a-zA-Z_0-9<>,:{}[\\]| ]+)", t)
        if (tt && t.indexOf("=>") < 0) { // 接口成员变量, 但不包括带'=>'的成员，带'=>'的接口成员需要按函数处理
            let valueName = re.getReg(t, tt.regs[1])
            let valueType = re.getReg(t, tt.regs[3])
            let index = valueType.indexOf("number")
            let optionalFlag = re.getReg(t, tt.regs[2]) == '?' ? true : false;
            while (index !== -1) {
                valueType = valueType.replace("number", "NUMBER_TYPE_" + NumberIncrease.getAndIncrease())
                index = valueType.indexOf("number")
            } 
            valueType = analyzeNoNameInterface(valueType, valueName, rsltInterface)
            result.value.push({
                name: valueName,
                type: valueType,
                optional: optionalFlag
            })
        }
        tt = re.match("(static )* *(\\$*[A-Za-z0-9_]+) *[:]? *\\(([\n 'a-zA-Z\'\'\"\":;=,_0-9?<>{}()=>|[\\]]*)\\)"
            + " *(:|=>)? *([A-Za-z0-9_<>{}:;, .[\\]]+)?", t)
        if (tt) { // 接口函数成员
            let ret = re.getReg(t, tt.regs[5]) == ''? 'void': re.getReg(t, tt.regs[5])
            let funcDetail = analyzeFunction(data, re.getReg(t, tt.regs[1]) != '', re.getReg(t, tt.regs[2]),
                re.getReg(t, tt.regs[3]), ret, results, interfaceName)
            if (funcDetail != null) {
                // 完全一样的方法不重复添加 (如同名同参的AsyncCallback和Promise方法)
                addUniqFunc2List(funcDetail, result.function)
            }
        }
    }
    return result
}

module.exports = {
    analyzeInterface,
    parseNotes
}