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
const path = require('path');
const fs = require("fs");
const { writeFile, readFile } = require("../tools/tool");
const re = require("../tools/re");
const LENGTH = 10;
const TWO_DECIMAL = 2;

function analyzeRetIsObject(retType, objectInfo) {
    // 去除 * 和 空格
    retType = retType.replace('*', '').replace('struct', '').trim()
    let objKeys = Object.keys(objectInfo)
    for (let i = 0; i < objKeys.length; i++) {
        if (retType == objKeys[i]) {
            return true;
        }
    }
    return false;
}


function analyzeRetIsTypeDef(type, info) {
  let typedefKeys = Object.keys(info)
  for (let i = 0; i < typedefKeys.length; i++) {
    if (type === typedefKeys[i]) {
      return info[type];
    }
  }
  return null;
}

//tsFuncName
function generateDirectFunction(params, index, tsFuncName, directFuncPath, hFileName) {
    let funcInfo = {
        "name": "",
        "params": [],
        "retType": "",
    }
  
    let funcName_replace = tsFuncName

    // 方法的注册
    let funcInitPath = path.join(__dirname, directFuncPath.initTempleteDetails.funcInitTemplete);
    let funcInitTemplete = readFile(funcInitPath)
    let init_replace = replaceAll(funcInitTemplete, '[func_name_replace]', funcName_replace)

    // 分析方法  分析第index个方法
    funcInfo.name = params.functions[index].name
    funcInfo.retType = params.functions[index].rtnType
    let parseParams = params.functions[index].parameters
    for (let i = 0; i < parseParams.length; ++i) {
        let param = createParam(parseParams[i])
        funcInfo.params.push(param)
    }

    // 生成
    let relativeParamGenPath = directFuncPath.cppTempleteDetails.funcBody.funcParamIn.paramGenTemplete
    let paramGenTempletePath = path.join(__dirname, relativeParamGenPath);
    let paramGenTemplete = readFile(paramGenTempletePath)
    let funcParamTypePath = directFuncPath.cppTempleteDetails.funcBody.funcParamIn.funcParamType
    let paramGenResult = ''
    // napi 获取参数
    for (let i = 0; i < funcInfo.params.length; i++) {
        paramGenResult = getParamJs2C(funcInfo, i, paramGenTemplete, funcParamTypePath, paramGenResult, params);
    }

    // 返回值处理  对于对象要使用循环处理
    let retGenResult = ''
    let retObjInfo = {
        "objName": '',
        "flag": false
    }
 
    let funcRetOutPath = directFuncPath.cppTempleteDetails.funcBody.funcReturnOut
    retGenResult = returnTypeC2Js(funcRetOutPath, funcInfo, params, retGenResult, retObjInfo);

    let funcBodyTempletePath = path.join(__dirname, directFuncPath.cppTempleteDetails.funcBody.funcBodyTemplete);
    let bodyTemplete = readFile(funcBodyTempletePath);
   
    let body_replace = replaceAll(bodyTemplete, '[funcName]', funcName_replace)
    body_replace = replaceAll(body_replace, '[get_error_msg_tag]', funcName_replace)
    body_replace = replaceAll(body_replace, '[file_introduce_replace]', hFileName)
    body_replace = replaceAll(body_replace, '[func_introduce_replace]', funcInfo.name)

    let funcInfoParams = ''
    let funcInfoParamTemp = '[paramName]: [paramType]; '
    for (let i = 0; i < funcInfo.params.length; i++) {
      let funcInfoParamReplace = replaceAll(funcInfoParamTemp, '[paramName]', funcInfo.params[i].name)
      funcInfoParamReplace = replaceAll(funcInfoParamReplace, '[paramType]', funcInfo.params[i].type)
      funcInfoParams += funcInfoParamReplace
    }
    body_replace = replaceAll(body_replace, '[input_introduce_replace]', funcInfoParams === ''? 'void': funcInfoParams)
    body_replace = replaceAll(body_replace, '[output_introduce_replace]', funcInfo.retType)
    
    let funcGetParamTempletePath = path.join(__dirname,
      directFuncPath.cppTempleteDetails.funcBody.funcParamIn.funcGetParamTemplete);
    let funcGetParamTemplete = readFile(funcGetParamTempletePath)
    let genParam_replace = replaceAll(funcGetParamTemplete, '[param_length]', "PARAMS" + funcInfo.params.length)
    genParam_replace = replaceAll(genParam_replace, '[funcName]', funcName_replace)
    genParam_replace = replaceAll(genParam_replace, '[getParam_replace]', paramGenResult)
    if (funcInfo.params.length !== 0) {
        body_replace = replaceAll(body_replace, '[func_getParam_replace]', genParam_replace)
    } else {
        body_replace = replaceAll(body_replace, '[func_getParam_replace]', '')
    }
    if (funcInfo.retType.replace('*', '').trim() !== 'void') {
        let returnType = funcInfo.retType === 'std::string' ? 'const char *' : funcInfo.retType
        returnType = returnType === 'size_t' ? 'int64_t' : returnType
        let funcReturnTempletePath = path.join(__dirname, funcRetOutPath.funcReturnTemplete);
        let funcReturnTemplete = readFile(funcReturnTempletePath);
        let = func_return_replace = replaceAll(funcReturnTemplete, '[return_name]', retObjInfo.objName)
        func_return_replace = replaceAll(func_return_replace, '[funcName]', funcName_replace)
        func_return_replace = replaceAll(func_return_replace, '[return_replace]', retGenResult)
        body_replace = replaceAll(body_replace, '[func_return_replace]', func_return_replace)
    } else {
        body_replace = replaceAll(body_replace, '[func_return_replace]', '    return NULL;\n')
    }
    body_replace = replaceAll(body_replace, '[return_replace]', retGenResult)

    let funcHDeclarePath = path.join(__dirname, directFuncPath.cppTempleteDetails.funcHDeclare.funcHDeclare);
    let funcHDeclare = readFile(funcHDeclarePath)
    funcHDeclare = replaceAll(funcHDeclare, '[funcName]', funcName_replace)

    funcHDeclare = replaceAll(funcHDeclare, '[file_introduce_replace]', hFileName)
    funcHDeclare = replaceAll(funcHDeclare, '[func_introduce_replace]', funcInfo.name)
    funcHDeclare = replaceAll(funcHDeclare, '[input_introduce_replace]', funcInfoParams === ''? 'void': funcInfoParams)
    funcHDeclare = replaceAll(funcHDeclare, '[output_introduce_replace]', funcInfo.retType)
   
    return [funcHDeclare, init_replace, body_replace]
}

function getParamJs2C(funcInfo, i, paramGenTemplete, funcParamTypePath, paramGenResult, params) {
  let paramType = funcInfo.params[i].type === 'size_t' ? 'int64_t' : funcInfo.params[i].type;
  // 去除const 和 *
  paramType = paramType.replace('const', '').replace('*', '').trim()
  let paramName = funcInfo.params[i].name;
  let paramGen = replaceAll(paramGenTemplete, '[param_index_replace]', "PARAMS" + i);
  paramGen = replaceAll(paramGen, '[param_name_replace]', paramName);
  if (paramType === 'double') {
    let getParamPath = path.join(__dirname, funcParamTypePath.double)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
    paramGenResult += paramGen;
  } else if (paramType === 'uint32_t') {
    let getParamPath = path.join(__dirname, funcParamTypePath.uint32_t)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
  
    paramGenResult += paramGen;
  } else if (paramType === 'int32_t' || paramType === 'int') {
    let getParamPath = path.join(__dirname, funcParamTypePath.int32_t)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
    paramGenResult += paramGen;
  } else if (paramType === 'int64_t' || paramType === 'size_t') {
    let getParamPath = path.join(__dirname, funcParamTypePath.int64_t)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
    paramGenResult += paramGen;
  } else if (paramType === 'bool') {
    let getParamPath = path.join(__dirname, funcParamTypePath.bool)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
    paramGenResult += paramGen;
  } else if (paramType === 'std::string' || paramType.indexOf('char') >= 0) {
    let getParamPath = path.join(__dirname, funcParamTypePath.string)
    paramGen = getParamGenCon(getParamPath, i, paramName, paramGen);
    paramGenResult += paramGen;
  } else if (analyzeRetIsTypeDef(paramType, params.typedefs)) { // typedefs
    funcInfo.params[i].type = analyzeRetIsTypeDef(paramType, params.typedefs);
    paramGenResult = getParamJs2C(funcInfo, i, paramGenTemplete, funcParamTypePath, paramGenResult, params);
  } 
  // 其他情况，处理成对象 napi_get_cb_info之后不做任何处理
  return paramGenResult;
}

function getParamGenCon(getParamPath, i, paramName, paramGen) {
  let getParam = readFile(getParamPath);
  getParam = replaceAll(getParam, '[param_index_replace]', "PARAMS" + i);
  getParam = replaceAll(getParam, '[param_name_replace]', paramName);
  paramGen = replaceAll(paramGen, '[getParam_replace]', getParam);
  return paramGen;
}

function returnTypeC2Js(funcRetOutPath, funcInfo, params, retGenResult, retObjInfo) {
    let setRetPropertyPath = path.join(__dirname, funcRetOutPath.funcReturnType.returnObj.funcReturnObjectToSet)
    let setRetProperty = readFile(setRetPropertyPath)
    let returnName = funcInfo.name;
    if (!retObjInfo.flag) {
        retObjInfo.objName = returnName
    }
    if (funcInfo.retType === 'uint32_t') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.uint32_t)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (funcInfo.retType === 'double') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.double)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (funcInfo.retType === 'int32_t' || funcInfo.retType === 'int') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.int32_t)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (funcInfo.retType === 'int64_t' || funcInfo.retType === 'size_t') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.int64_t)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (funcInfo.retType === 'bool') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.bool)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (funcInfo.retType === 'std::string' || funcInfo.retType.substring(0, 10) === 'const char'
        || funcInfo.retType === 'char *') {
        let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.string)
        retGenResult = getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty);
    } else if (analyzeRetIsObject(funcInfo.retType, params.classes)) { // 返回值是对象
        if (!retObjInfo.flag) {
            retGenResult = getObjRetContent(funcRetOutPath, retGenResult, returnName);
            retObjInfo.flag = true
            let retType = funcInfo.retType.replace('*', '').trim();
            let objectName = '';
            let objectProperty = [];

            let myObject = params.classes[retType]
            objectName = myObject.bare_name;
            let myObjectProperty = myObject.properties.public;
            for (let j = 0; j < myObjectProperty.length; j++) {
                let propertyObj = {
                    "name": '',
                    "retType": ''
                }
                propertyObj.name = myObjectProperty[j].name;
                propertyObj.retType = myObjectProperty[j].type;

                objectProperty.push(propertyObj);
            }
            // 遍历属性
            for (let i = 0; i < objectProperty.length; i++) {
                let testRes = returnTypeC2Js(funcRetOutPath, objectProperty[i], params, retGenResult, retObjInfo)
                retGenResult = testRes;
            }
        } else {
            if (retObjInfo.objName !== '') {
                retGenResult = getObjRetContent(funcRetOutPath, retGenResult, returnName);
                let setRetPropertyObj = readFile(setRetPropertyPath)
                setRetPropertyObj = replaceAll(setRetPropertyObj, '[set_objname_replace]', retObjInfo.objName);
                setRetPropertyObj = replaceAll(setRetPropertyObj, '[set_propname_replace]', returnName);
                setRetPropertyObj = replaceAll(setRetPropertyObj, '[set_propvalue_replace]', returnName);
                retGenResult += setRetPropertyObj;
            }
        }
    } else if (analyzeRetIsTypeDef(funcInfo.retType, params.typedefs)) { // typedefs
      funcInfo.retType = analyzeRetIsTypeDef(funcInfo.retType, params.typedefs);
      retGenResult = returnTypeC2Js(funcRetOutPath, funcInfo, params, retGenResult, retObjInfo);
    }
    return retGenResult;
}

function getObjRetContent(funcRetOutPath, retGenResult, returnName) {
  let funcReturnTypePath = path.join(__dirname, funcRetOutPath.funcReturnType.returnObj.object)
  let funcReturnType = readFile(funcReturnTypePath);
  retGenResult += replaceAll(funcReturnType, '[return_name_replace]', returnName);
  return retGenResult;
}

function getRetTypeContent(funcReturnTypePath, returnName, retGenResult, retObjInfo, setRetProperty) {
  let funcReturnType = readFile(funcReturnTypePath);
  funcReturnType = replaceAll(funcReturnType, '[return_name_replace]', returnName);
  retGenResult += funcReturnType;
  if (retObjInfo.flag) {
    setRetProperty = replaceAll(setRetProperty, '[set_objname_replace]', retObjInfo.objName);
    setRetProperty = replaceAll(setRetProperty, '[set_propname_replace]', returnName);
    setRetProperty = replaceAll(setRetProperty, '[set_propvalue_replace]', returnName);
    retGenResult += setRetProperty;
  }
  return retGenResult;
}

function replaceAll(s, sfrom, sto) {
    while (s.indexOf(sfrom) >= 0) {
        s = s.replace(sfrom, sto)
    }
    return s;
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
    generateDirectFunction
}