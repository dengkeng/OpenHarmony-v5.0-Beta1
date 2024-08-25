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
const { generateFunctionDirect } = require("./function_direct");
const { generateFunctionSync } = require("./function_sync");
const { generateFunctionAsync } = require("./function_async");
const { generateInterface } = require("./interface");
const { generateClass } = require("./class");
const { generateType } = require("./type");
const { FuncType, InterfaceList, EnumList, TypeList, CallFunctionList, isOnOffRegisterFunc, isCreateThreadsafeFunc } = 
require("../tools/common");
const { generateEnum } = require("./enum");
const { generateFunctionOnOff } = require("./function_onoff");
const { generateThreadsafeFunc } = require("./function_threadsafe");

const { NapiLog } = require("../tools/NapiLog");
const { addUniqFunc2List, addUniqObj2List } = require("../tools/tool");

function findParentByName(parentName, data) {
    for (let i in data.interface) {
        if (parentName === data.interface[i].name) {
            return data.interface[i]
        }
    }

    for (let i in data.class) {
        if (parentName === data.class[i].name) {
            return data.class[i]
        }
    }
    return null
}

/**
 * 生成父类的成员变量和方法
 * @param currentObj 当前类
 * @param data 全局数据上下文
 * @param parentBody 输出参数，保存父类的成员变量和方法
 * @returns void
 */
function genParentPropties(currentObj, data, parentBody) {
    for (let i in currentObj.body.parentNameList) {
        let parentName = currentObj.body.parentNameList[i]
        let parentObj = findParentByName(parentName, data)
        if (!parentObj) {
            NapiLog.logError("Failed to find %s's parent by name [%s]".format(currentObj.body.name, parentName))
            return
        }
    
        // 为父类添加子类的对象信息
        addUniqObj2List(currentObj, parentObj.body.childList)
    
        // 为当前类添加父类对象信息
        addUniqObj2List(parentObj, currentObj.body.parentList)
    
        for (let i in parentObj.body.value) {
            // 添加父类的所有成员属性到parentBody
            addUniqObj2List(parentObj.body.value[i], parentBody.value)
        }
        for (let i in parentObj.body.function) {
            // 添加父类的所有成员方法到parentBody
            addUniqFunc2List(parentObj.body.function[i], parentBody.function)
        }
        if (parentObj.body.parentNameList.length > 0) {
            // 递归查找父类的父类
            genParentPropties(parentObj, data, parentBody)
        }
    }
} 

// 为有继承关系的interface和class类型建立父子类关系信息
function genExtendsRelation(data) {
    for (let i in data.interface) {
        let ifObj = data.interface[i]
        if (ifObj && ifObj.body.parentNameList && ifObj.body.parentNameList.length > 0) {
            ifObj.body.parentBody = {value:[], function:[]}
            genParentPropties(ifObj, data, ifObj.body.parentBody)
        }
    }

    for (let i in data.class) {
        let classObj = data.class[i]
        if (classObj.body.parentName) {
            classObj.body.parentBody = {value:[], function:[]}
            genParentPropties(classObj, data, classObj.body.parentBody)
        }
    }
}

//生成module_middle.cpp、module.h、module.cpp
function generateNamespace(name, data, inNamespace = "") {
    let namespaceResult = { implH: "", implCpp: "", middleFunc: "", middleInit: "", declarationH: "", middleH: "", middleInitEnumDef: "" }
    namespaceResult.middleInit += formatMiddleInit(inNamespace, name)
    genExtendsRelation(data)
    InterfaceList.push(data.interface)
    TypeList.push(data.type)
    EnumList.push(data.enum)
    CallFunctionList.push(data.callFunction)
    let toolNamespace = getToolNamespaceFunc(inNamespace, name);  
    enumNamespaceFunction(data, namespaceResult, inNamespace, name, toolNamespace); 
    for (let i in data.type) {
      let ii = data.type[i]
      let result = generateType(ii.name, ii.body, inNamespace + name + "::",inNamespace, name, toolNamespace)
      namespaceResult = getNamespaceResult(result, namespaceResult)   
    }
    for (let i in data.interface) {
        let ii = data.interface[i]
        let result = generateInterface(ii.name, ii.body, inNamespace + name + "::")
        namespaceResult = getNamespaceResult(result, namespaceResult)   
    }
    for (let i in data.class) {
        let ii = data.class[i]
        let result = generateClass(ii.name, ii.body, inNamespace + name + "::", ii.functiontType)
        namespaceResult = getNamespaceResult(result, namespaceResult)
    }
    namespaceResult.implH = namespaceResult.declarationH + namespaceResult.implH 
    for (let i in data.function) {
        genNamespaceFunc(data, i, namespaceResult, inNamespace, name);
    }
    let flag = true;
    if (data.namespace.length !== 0) {
      flag = false;
    }
    for (let i in data.namespace) {
        let ns = data.namespace[i]
        let result = generateNamespace(ns.name, ns.body, inNamespace + name + "::")
        namespaceResult = getNamespaceResult(result, namespaceResult)
    }
    InterfaceList.pop();
    TypeList.pop();
    EnumList.pop();
    CallFunctionList.pop();
    if (inNamespace.length > 0) {
        namespaceResult.middleInit += "}"
        flag = true;
    }
    return generateResult(name, namespaceResult.implH, namespaceResult.implCpp, namespaceResult.middleFunc,
        namespaceResult.middleInit, namespaceResult.middleH, namespaceResult.middleInitEnumDef, flag)
}

function genNamespaceFunc(data, i, namespaceResult, inNamespace, name) {
    let func = data.function[i];
    let tmp = generateFunction(func, data, namespaceResult.implH);
    namespaceResult.middleFunc += tmp[0];
    namespaceResult.implH += tmp[1];
    namespaceResult.implCpp += tmp[2];
    namespaceResult.middleH += tmp[3];
    let toolNamespace = getToolNamespaceFunc(inNamespace, name);
    let middleTmp = '    pxt->DefineFunction("%s", %s%s::%s%s_middle%s);\n'
      .format(func.name, inNamespace, name, toolNamespace, func.name, inNamespace.length > 0 ? ", " + name : "");
    if (namespaceResult.middleInit.indexOf(middleTmp) < 0) { // on方法不需要重复定义
      namespaceResult.middleInit += middleTmp;
    }
}

function getToolNamespaceFunc(inNamespace, name) {
    let toolNamespace;
    if (inNamespace != '') {
        let index = inNamespace.lastIndexOf('::');
        let bodyTmp = inNamespace.substring(0, index);
        let index2 = bodyTmp.lastIndexOf('::');
        if (index2 > 0 && index2 < index) {
            toolNamespace = inNamespace.substring(index2 + 2, index) + '_interface::';
        } else {
            toolNamespace = name + '_interface::';
        }
    } else {
        toolNamespace = name + '_interface::';
    }
    return toolNamespace;
}

function enumNamespaceFunction(data, namespaceResult, inNamespace, nameSpaceName, toolNamespace) {
  let result = generateEnumResult(data, inNamespace, nameSpaceName, toolNamespace);
  namespaceResult.implH += result.implH;
  namespaceResult.implCpp += result.implCpp;
  namespaceResult.middleInit += result.middleInit;
  namespaceResult.middleInitEnumDef += result.midInitEnumDefine
}

function getNamespaceResult(subResult, returnResult) {    
    returnResult.middleFunc += subResult.middleBody
    returnResult.implH += subResult.implH
    returnResult.implCpp += subResult.implCpp
    returnResult.middleInit += subResult.middleInit
    returnResult.declarationH += subResult.declarationH
    returnResult.middleH += subResult.middleH

    if (subResult.midInitEnumDefine !== undefined) {
      returnResult.middleInitEnumDef += subResult.midInitEnumDefine
    }
  
    return returnResult
}

  function generateEnumResult(data, inNamespace, nameSpaceName, toolNamespace) {
    let resultEnum = {
        implH: "",
        implCpp: "",
        middleInit: "",
        midInitEnumDefine: ""
    }

    for (let i in data.enum) {
        let enumm = data.enum[i]
        let result = generateEnum(enumm.name, enumm.body, inNamespace, nameSpaceName, toolNamespace)
        resultEnum.implH += result.implH
        resultEnum.implCpp += result.implCpp
        resultEnum.middleInit += result.midInitEnum
        resultEnum.midInitEnumDefine += result.midInitEnumDefine
    }
    return resultEnum
}

function generateResult(name, implH, implCpp, middleFunc, middleInit, middleH, middleInitEnumDef, flag) {
  let result
  let middleEnumDefine = middleInitEnumDef.indexOf('undefined') >= 0? '' : middleInitEnumDef
  if (flag) {
    result = {
      implH: `\nnamespace %s {\nnamespace %s_interface {%s\n}\n}`.format(name, name, implH),
      implCpp: `\nnamespace %s {\nnamespace %s_interface {%s\n}\n}`.format(name, name, implCpp),
      middleBody: `\nnamespace %s {\nnamespace %s_interface {\n%s%s\n}\n}`.format(name, name, middleEnumDefine, middleFunc),
      middleInit: middleInit,
      middleH: `\nnamespace %s {\nnamespace %s_interface {%s\n}\n}`.format(name, name, middleH)
    }
  } else {
        result = {
        implH: `\nnamespace %s {%s\n}`.format(name, implH),
        implCpp: `\nnamespace %s {%s}`.format(name, implCpp),
        middleBody: `\nnamespace %s {\n%s%s}`.format(name, middleEnumDefine, middleFunc),
        middleInit: middleInit,
        middleH: `\nnamespace %s {%s\n}`.format(name, middleH)
    }
  }
  return result;
}

function generateFunction(func, data, implH = null) {
    let tmp;
    let className;
    if (isOnOffRegisterFunc(func.name)) {
        return generateFunctionOnOff(func, data)
    } else if (isCreateThreadsafeFunc(func.name)) {
        return generateThreadsafeFunc(func, data)
    }
    switch (func.type) {
        case FuncType.DIRECT:
            tmp = generateFunctionDirect(func, data)
            break;
        case FuncType.SYNC:
            tmp = generateFunctionSync(func, data)
            break
        case FuncType.ASYNC:
        case FuncType.PROMISE:
            tmp = generateFunctionAsync(func, data, className, implH)
            break
        default:
            return
    }
    return tmp
}

function formatMiddleInit(inNamespace, name) {
    let middleInit = ""
    if (inNamespace.length > 0) {
        let nsl = inNamespace.split("::")
        nsl.pop()
        let parentNs = nsl[nsl.length - 1]
        middleInit = `{\nnapi_value %s = pxt->CreateSubObject(%s, "%s");\n`
            .format(name, nsl.length === 1 ? "exports" : parentNs, name)
    }
    return middleInit
}

module.exports = {
    generateNamespace,
    getNamespaceResult,
    generateEnumResult,
    generateResult,
    generateFunction,
    formatMiddleInit
}