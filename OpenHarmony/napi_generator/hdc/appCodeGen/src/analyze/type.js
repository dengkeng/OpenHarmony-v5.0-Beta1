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

/**type解析 */
function analyzeType(data, rsltInterface = null) { // same as class
    let body = data
    body = body.indexOf("//") < 0 ? body : parseNotes(body)
    body = re.replaceAll(body, "\n", "").split(";")
    let result = {
        value: [],
        // function: []
    }
    for (let i in body) {
        let t = body[i]
        while (t.length > 0 && t[0] == ' ') // 去除前面的空格
            t = t.substring(1, t.length)
        while (t.length > 0 && t[-1] == ' ') // 去除后面的空格
            t = t.substring(0, t.length - 1)
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
              result.value.push({
                name: valueName,
                type: valueType,
                optional: optionalFlag
              })
        }
    }
    return result
}

function analyzeType2(data) {
  let body = re.replaceAll(data, " ", "").split("'|'")
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
        analyzeType2Result(result, bodyContent, i)
    }
    return result
}

function analyzeType2Result(result, bodyContent, index) {
  let regString       = re.match(" *([a-zA-Z0-9_]+) *", bodyContent)
  if (regString) {
      let elementName = re.getReg(bodyContent, regString.regs[1])
      elementName = 'NAME_' + elementName.toUpperCase()
      let elementValue = re.getReg(bodyContent, regString.regs[1])
      result.element.push({
          name: elementName,
          value: elementValue,
          type: 'string'
      })
      result.enumValueType = 1
  } 
  return result
}

module.exports = {
    analyzeType,
    analyzeType2,
    analyzeType2Result,
    parseNotes
}