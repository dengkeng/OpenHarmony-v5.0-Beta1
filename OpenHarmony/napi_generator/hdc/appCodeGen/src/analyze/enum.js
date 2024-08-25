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
const { NumberIncrease } = require("../tools/common");
const re = require("../tools/re");

/** Enum解析 */
function analyzeEnum(data) {
    let body = re.replaceAll(data, "\n", "").split(",")
    let result = {
        element: [],
        function: [],
        enumValueType: 0 // 0代表数字，1代表字符串
    }
    for (let i in body) {
        let bodyContent = body[i]
        while (bodyContent.length > 0 && bodyContent[0] == ' ') {
            bodyContent = bodyContent.substring(1, bodyContent.length)
        }
        while (bodyContent.length > 0 && bodyContent[-1] == ' ') {
            bodyContent = bodyContent.substring(0, bodyContent.length - 1)
        }
        if (bodyContent == "") {
            break
        }
        analyzeEnumResult(result, bodyContent, i)
    }
    return result
}

function analyzeEnumResult(result, bodyContent, index) {
    let regString       = re.match(" *([a-zA-Z0-9_]+) * = *\"([\x21-\x7e]+)*\"", bodyContent)
    let regSingleQuotes = re.match(" *([a-zA-Z0-9_]+) * = *'([\x21-\x7e]+)*'", bodyContent)
    let regNumber = re.match(" *([a-zA-Z0-9_]+) * = *([a-zA-Z_0-9<>-]+)", bodyContent)
    let reg = re.match(" *([a-zA-Z0-9_]+) *", bodyContent)
    if (regString) {
        let elementName = re.getReg(bodyContent, regString.regs[1])
        let elementValue = re.getReg(bodyContent, regString.regs[2])
        result.element.push({
            name: elementName,
            value: elementValue,
            type: 'string'
        })
        result.enumValueType = 1
    } else if (regSingleQuotes) {
        let elementName = re.getReg(bodyContent, regSingleQuotes.regs[1])
        let elementValue = re.getReg(bodyContent, regSingleQuotes.regs[2])
        result.element.push({
            name: elementName,
            value: elementValue,
            type: 'string'
        })
        result.enumValueType = 1
    } else if (regNumber) {
        let elementName = re.getReg(bodyContent, regNumber.regs[1])
        let elementValue = re.getReg(bodyContent, regNumber.regs[2])
        typeof (elementValue)
        result.element.push({
            name: elementName,
            value: elementValue,
            type: "NUMBER_TYPE_" + NumberIncrease.getAndIncrease()
        })
        result.enumValueType = 0
    } else if (reg) {
        let elementName = re.getReg(bodyContent, reg.regs[1])
        let elementValue = index
        result.element.push({
            name: elementName,
            value: elementValue,
            type: "NUMBER_TYPE_" + NumberIncrease.getAndIncrease()
        })
        result.enumValueType = 0
    }
    return result
}

module.exports = {
    analyzeEnum,
    analyzeEnumResult
}