/*
* Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
const util = require('util');
const { generateRandomInteger } = require("../tools/tool");
const { InterfaceList, TypeList } = require('../tools/common')
const path = require('path')
const fs = require("fs");
const LENGTH = 10;
const TWO_DECIMAL = 2;
const MODTWO = 2;

// 随机生成浮点数值
function generateRandomArbitrary(min, max, fixed) {
    let random = (Math.random() * (max - min) + min).toFixed(fixed);
    return parseFloat(random);
}

// 随机生成布尔值
function generateRandomBoolValue() {
    let randomBool = false;
    if (generateRandomInteger(0, LENGTH) % MODTWO === 0) {
        randomBool = true;
    }
    return randomBool;
}

// 随机生成字符串
function generateRandomString(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;

    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

function generateFuncTestCase(params, funcIndex, tsFuncName, abilityTestTemplete, hFileName) {
    let funcInfo = {
        "name": "",
        "params": [],
        "retType": "",
    }
    funcInfo.name = params.functions[funcIndex].name
    let parseParams =  params.functions[funcIndex].parameters
    for(let i = 0; i < parseParams.length; ++i) {
        let param = createParam(parseParams[i])
        funcInfo.params.push(param)
    }
    funcInfo.retType = params.functions[funcIndex].rtnType
    let funcParamDefine = ''
    let funcParamUse = ''
    let funcInfoParams = ''
    let funcInfoParamTemp = '[paramName]: [paramType]; '
    // 判断函数有几个参数，依次给参数赋值
    for(let i = 0; i < funcInfo.params.length; i++) {
        let funcInfoParamReplace = replaceAll(funcInfoParamTemp, '[paramName]', funcInfo.params[i].name)
        funcInfoParamReplace = replaceAll(funcInfoParamReplace, '[paramType]', funcInfo.params[i].type)
        funcInfoParams += funcInfoParamReplace
        let testType = getTestType(funcInfo.params[i].type);
        if (testType === 'int') {
            funcParamDefine += util.format('let %s = %s\n    ', funcInfo.params[i].name, generateRandomInteger(0, LENGTH))
            funcParamUse += funcInfo.params[i].name + ', '
        } else if (testType === 'float') {
            funcParamDefine += util.format('let %s = %s\n    ', funcInfo.params[i].name, generateRandomArbitrary(0, LENGTH, TWO_DECIMAL))
            funcParamUse += funcInfo.params[i].name + ', '
        } else if (testType === 'bool') {
            funcParamDefine += util.format('let %s = %s\n    ', funcInfo.params[i].name, generateRandomBoolValue())
            funcParamUse += funcInfo.params[i].name + ', '
        } else if (testType === 'string') {
            funcParamDefine += util.format('let %s = "%s"\n    ', funcInfo.params[i].name, generateRandomString(LENGTH))
            funcParamUse += funcInfo.params[i].name + ', '
        } else if (TypeList.getValue(testType)) {
            let typeDefineRes = getTypeDefine(testType, funcParamDefine, funcInfo, i, funcParamUse);
            funcParamDefine = typeDefineRes[0]
            funcParamUse = typeDefineRes[1]
        } else if (InterfaceList.getBody(testType)) {
            let interfaceDefineRes =  getInterfaceDefine(testType, funcParamDefine, funcInfo, i, funcParamUse);
            funcParamDefine = interfaceDefineRes[0]
            funcParamUse = interfaceDefineRes[1]
        }
    }
    // 去除调用参数的最后一个','
    let index = funcParamUse.lastIndexOf(', ');
    funcParamUse = funcParamUse.substring(0, index);
    let callFunc = ''
    let hilogContent = ''
    // 调用函数
    if (getJsType(funcInfo.retType) !== 'void') {
      callFunc = util.format('let result: %s = testNapi.%s(%s)\n    ', getJsType(funcInfo.retType), tsFuncName, funcParamUse)
      // 加 hilog 打印
      hilogContent = util.format('hilog.info(0x0000, "testTag", "Test NAPI %s: ", JSON.stringify(result));\n    ', tsFuncName)
      hilogContent += util.format('console.info("testTag", "Test NAPI %s: ", JSON.stringify(result));\n    ', tsFuncName)
    } else {
      callFunc = util.format('testNapi.%s(%s)\n    ', tsFuncName, funcParamUse)
    }
    let func_test_replace = funcParamDefine + callFunc + hilogContent
    // 替换test_case_name
    let funcTestContent =  replaceAll(abilityTestTemplete,'[func_direct_testCase]', func_test_replace)
    funcTestContent = replaceAll(funcTestContent, '[test_case_name]', tsFuncName)
    funcTestContent = replaceAll(funcTestContent, '[file_introduce_replace]', hFileName)
    funcTestContent = replaceAll(funcTestContent, '[func_introduce_replace]', funcInfo.name)
    funcTestContent = replaceAll(funcTestContent, '[input_introduce_replace]', funcInfoParams === ''? 'void': funcInfoParams)
    funcTestContent = replaceAll(funcTestContent, '[output_introduce_replace]', funcInfo.retType)

    return funcTestContent
}

function getTypeDefine(testType, funcParamDefine, funcInfo, i, funcParamUse) {
  let typeDefType = TypeList.getValue(testType);
  // genType
  if (typeDefType === 'number') {
    funcParamDefine += util.format('let %s = %s\n    ', funcInfo.params[i].name, generateRandomInteger(0, LENGTH));
    funcParamUse += funcInfo.params[i].name + ', ';
  } else if (typeDefType === 'string') {
    funcParamDefine += util.format('let %s = "%s"\n    ', funcInfo.params[i].name, generateRandomString(LENGTH));
    funcParamUse += funcInfo.params[i].name + ', ';
  } else if (typeDefType === 'boolean') {
    funcParamDefine += util.format('let %s = %s\n    ', funcInfo.params[i].name, generateRandomBoolValue());
    funcParamUse += funcInfo.params[i].name + ', ';
  }
  return [funcParamDefine, funcParamUse];
}

function getInterfaceDefine(testType, funcParamDefine, funcInfo, i, funcParamUse) {
  let objValue = InterfaceList.getBody(testType);
  let objTestData = 'let %s:testNapi.%s = { ';
  for (let j = 0; j < objValue.length; j++) {
    if (objValue[j].type === 'number') {
      objTestData += util.format('%s: %s, ', objValue[j].name, generateRandomInteger(0, LENGTH));
    } else if (objValue[j].type === 'string') {
      objTestData += util.format('%s: "%s", ', objValue[j].name, generateRandomString(LENGTH));
    } else if (objValue[j].type === 'boolean') {
      objTestData += util.format('%s: %s, ', objValue[j].name, generateRandomBoolValue());
    } else if (InterfaceList.getBody(objValue[j].type)) {
      objTestData += util.format('%s: null, ', objValue[j].name);
    } else if (objValue[j].type.indexOf('=>') >= 0) { // 成员方法
      let interfaceFunc = objValue[j].type;
      let indexFunc = interfaceFunc.indexOf('=>');
      let interfaceFuncRet = interfaceFunc.substring(indexFunc + 2, interfaceFunc.length);
      if (interfaceFuncRet.trim() === 'void') {
        let interfaceFuncRetDefine = interfaceFunc.substring(0, indexFunc + 2) + '{}';
        objTestData += util.format('%s, ', interfaceFuncRetDefine);
      } else if (interfaceFuncRet.trim() === 'string') {
        let interfaceFuncRetDefine = interfaceFunc.substring(0, indexFunc + 2) + '{return ""}';
        objTestData += util.format('%s, ', interfaceFuncRetDefine);
      } else if (interfaceFuncRet.trim() === 'boolean') {
        let interfaceFuncRetDefine = interfaceFunc.substring(0, indexFunc + 2) + '{ return true }';
        objTestData += util.format('%s, ', interfaceFuncRetDefine);
      } else if (interfaceFuncRet.trim() === 'number') {
        let interfaceFuncRetDefine = interfaceFunc.substring(0, indexFunc + 2) + '{ return 0 }';
        objTestData += util.format('%s, ', interfaceFuncRetDefine);
      }
    }
  }

  // 去除调用参数的最后一个','
  let index = objTestData.lastIndexOf(', ');
  if (index !== -1) {
    objTestData = objTestData.substring(0, index) + ' }\n    ';
  } else {
    objTestData = 'let %s:testNapi.%s = null;\n    ';
  }
  funcParamDefine += util.format(objTestData, funcInfo.params[i].name, testType);
  funcParamUse += funcInfo.params[i].name + ', ';
  return [funcParamDefine, funcParamUse];
}

function replaceAll(s, sfrom, sto) {
    while (s.indexOf(sfrom) >= 0) {
        s = s.replace(sfrom, sto)
    }
    return s;
}

function getTestType(type) {
    // 去掉const 和 *
    type = type.replaceAll('const', '').replaceAll('*', '').trim()
    if (type === 'uint32_t' || type === 'int32_t' || type === 'int16_t' ||
        type === 'int64_t' || type === 'int' || type === 'size_t') {
        return 'int'
    } else if (type === 'double_t' || type === 'double' || type === 'float') {
        return 'float'
    } else if (type === 'bool') {
        return 'bool'
    } else if (type === 'std::string' || type.indexOf('char') >= 0) {
        return 'string'
    }
    return type
}

function getJsType(type) {
    // 去掉const 和 *
    type = type.replaceAll('const', '').replaceAll('*', '').trim()
    if (type === 'uint32_t' || type === 'int32_t' || type === 'int16_t' || type === 'int64_t' ||
        type === 'int' || type === 'double_t' || type === 'double' || type === 'float' || type === 'size_t') {
        return 'number'
    } else if (type.indexOf('char') >= 0 || type === 'std::string') {
        return 'string'
    } else if (type === 'bool') {
        return 'boolean'
    } else if (type === 'void') {
        return type
    } else {
        // 对象，在ts中定义为interface
        return 'testNapi.' + type.replace('*', '').trim()
    }
}

function createParam(parseParamInfo) {
    let param = {
        "name": "",
        "type": ""
    }
    param.name = parseParamInfo.name
    param.type = parseParamInfo.type
    return param
}

module.exports = {
    generateFuncTestCase
}