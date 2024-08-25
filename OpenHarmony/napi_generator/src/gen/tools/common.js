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
const re = require("./re");
const tsc = require("../../node_modules/typescript");

function checkFileError(ifname) {
    let program = tsc.createProgram([ifname], {target: tsc.ScriptTarget.Latest,})
    let emitResult = program.emit();
    let allDiagnostics = tsc.getPreEmitDiagnostics(program).concat(emitResult.diagnostics);

    let errorMsg = ''
    allDiagnostics.forEach(diagnostic => {
        if (diagnostic.file) {
            let { line, character } = tsc.getLineAndCharacterOfPosition(diagnostic.file, diagnostic.start);
            let message = tsc.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
            errorMsg += `${diagnostic.file.fileName} (${line + 1},${character + 1}): ${message}\n`;
        } else {
            errorMsg += tsc.flattenDiagnosticMessageText(diagnostic.messageText, "\n") + "\n";
        }
    });

    if (allDiagnostics.length > 0) {
        return [false, errorMsg];
    }
    return [true, ""];
}

class FuncType { }
FuncType.DIRECT = 1
FuncType.SYNC = 2
FuncType.ASYNC = 4
FuncType.PROMISE = 8
FuncType.ToString = function (type) {
    if (type === FuncType.DIRECT) return "DIRECT";
    else if (type === FuncType.SYNC) return "SYNC";
    else if (type === FuncType.ASYNC) return "ASYNC";
    else if (type === FuncType.PROMISE) return "PROMISE";
    return "UNKNOW";
}

class NumberIncrease { }
NumberIncrease.num = 1
NumberIncrease.getAndIncrease = function () {
    return NumberIncrease.num++;
}
NumberIncrease.get = function () {
    return NumberIncrease.num;
}
NumberIncrease.reset = function () {
    NumberIncrease.num = 1
}

class InterfaceList { }
InterfaceList.interfacess_ = [];
InterfaceList.push = function (ifs) {
    InterfaceList.interfacess_.push(ifs)
}
InterfaceList.pop = function () {
    InterfaceList.interfacess_.pop()
}
InterfaceList.getValue = function (name) {
    let ifs = InterfaceList.interfacess_[InterfaceList.interfacess_.length - 1]
    for (let i in ifs) {
        let vv = ifs[i];
        if (ifs[i].name === name) {
            var hasProperty = Object.prototype.hasOwnProperty.call(ifs[i].body, "allProperties")
            if (hasProperty) {
                return ifs[i].body.allProperties.values;
            } else {
                return ifs[i].body.value;
            }
        }
    }
    return null;
}

InterfaceList.getBody = function (name) {
    let ifs = InterfaceList.interfacess_[InterfaceList.interfacess_.length - 1]
    for (let i in ifs) {
        if (ifs[i].name === name) {
            return ifs[i].body;
        }
    }
    return null;
}

class CallFunctionList { }
CallFunctionList.callFuncs = [];
CallFunctionList.push = function (ifs) {
    CallFunctionList.callFuncs.push(ifs)
}
CallFunctionList.pop = function () {
    CallFunctionList.callFuncs.pop()
}
CallFunctionList.getValue = function (name) {
    if (CallFunctionList.callFuncs.length === 0) {
        return null
    }

    let cfs = CallFunctionList.callFuncs[CallFunctionList.callFuncs.length - 1]
    if (cfs === undefined) {
        return null
    }

    for (let i = 0; i < cfs.length; i++) {
        if (cfs[i].name === name) {
            return [cfs[i].body, cfs[i].ret]
        } 
    }
    return null
}

CallFunctionList.getObjOnFuncName = function (interfaceName) {
    let cfs = CallFunctionList.callFuncs[CallFunctionList.callFuncs.length - 1]
    let funNames = []
    for (let i = 0; i < cfs.length; i++) {
        if (cfs[i].name.indexOf(interfaceName) === 0) {
            let funName = cfs[i].name.substring(interfaceName.length+1, cfs[i].name.length)
            funNames.push(funName)
        } 
    }
    return funNames
}

class TypeList { }
TypeList.types = [];
TypeList.push = function (ifs) {
  TypeList.types.push(ifs)
}
TypeList.pop = function () {
  TypeList.types.pop()
}
TypeList.getValue = function (name) {
    let ifs = TypeList.types[TypeList.types.length - 1]
    for (let i in ifs) {
        if (ifs[i].name === name) {
            var hasProperty = Object.prototype.hasOwnProperty.call(ifs[i].body, "allProperties")
            if (hasProperty) {
                return ifs[i].body.allProperties.values;
            } else {
                return ifs[i].body;
            }
        }
    }
    return null;
}

class EnumList { }
EnumList.enum_ = [];
EnumList.push = function (ifs) {
    EnumList.enum_.push(ifs)
}
EnumList.pop = function () {
    EnumList.enum_.pop()
}
EnumList.getValue = function (name) {
    let ifs = EnumList.enum_[EnumList.enum_.length - 1]
    for (let i in ifs) {
        if (ifs[i].name === name) {
            return ifs[i].body.element;
        }
    }
    return null;
}

function getArrayType(type) {
    let tt = re.match("Array<([a-zA-Z_0-9]+)>", type)
    if (tt != null) {
        return re.getReg(type, tt.regs[1])
    } 
    
    tt = re.match("Array<{([[a-z:]+)([a-z:]]+)([a-zA-Z_1-9:]+)", type)
    if (tt != null) {
        let res = ''
        let len = tt.regs.length
        for (let i=1; i<len; i++) {
            let regs1 = re.getReg(type, tt.regs[i])
            res += regs1
        }          
        return res
    }
    
    tt = re.match("Array<map<string", type)
    if (tt != null) {
        let preStr = 'Array<'
        let preStrLen = preStr.length        
        let res = type.substring(preStrLen, type.length-1)              
        return res
    }

    tt = re.match("Array<Map<string", type)
    if (tt != null) {
        let preStr = 'Array<'
        let preStrLen = preStr.length        
        let res = type.substring(preStrLen, type.length-1)              
        return res
    } 
    return null
}

function getArrayTypeTwo(type) {
    let tt = re.match("([a-zA-Z_0-9]+)", type)
    return re.getReg(type, tt.regs[1])
}

function jsType2CType(jsTypeName) {
    if (jsTypeName === "string") {
        return "std::string"
    } else if (jsTypeName === "boolean") {
        return "bool"
    } else {
        return jsTypeName
    }
}

class EnumValueType { }
EnumValueType.ENUM_VALUE_TYPE_NUMBER = 0
EnumValueType.ENUM_VALUE_TYPE_STRING = 1

function isEnum(type, data) {
    let isEnum = false
    if (null == data) {
        return isEnum
    }
    for (let i in data.enum) {
        let enumm = data.enum[i]
        if (type === enumm.name) {
            isEnum = true
        }
    }
    return isEnum
}

function enumIndex(type, data) {
    let index;
    if (null === data) {
        return index
    }
    for (let i in data.enum) {
        let enumm = data.enum[i]
        if (type === enumm.name) {
            index = i
        }
    }
    return index
}

function isType(type, data) {
  let isType = false
  if (null === data) {
    return isType
  }
  for (let i in data.type) {
    let typee = data.type[i]
    if (type === typee.name) {
      isType = true
    }
  }
  return isType
}

function typeIndex(type, data) {
  let index;
  if (null === data) {
      return index
  }
  for (let i in data.type) {
      let typee = data.type[i]
      if (type === typee.name) {
          index = i
      }
  }
  return index
}

function getMapType(type) {
    type = type.replace(/\s*/g,"")
    let ttKey = re.search("Map<([a-zA-Z_0-9]+),", type)
    let ttValue = re.search(",([a-zA-Z_0-9<>]+)>", type)
    let ttMap = re.search(",([a-zA-Z_0-9]+)>>", type)
    let ttArray = re.search("Array<([a-zA-Z_0-9]+)>", type)

    if(ttArray === null) {
        ttArray = re.search("([a-zA-Z_0-9]+)\\[\\]>", type)
    }
    
    let valueType
    let valueMapType
    let valueArrayType
    if (ttKey === null && ttValue === null && ttMap === null) {
        ttKey = re.search("key:([a-zA-Z_0-9]+)", type)
        ttValue = re.search(":([a-zA-Z_0-9]+)}", type)
        ttMap = re.search(":([a-zA-Z_0-9]+)}}", type)
        ttArray = re.search("Array<([a-zA-Z_0-9]+)>", type)
        if (ttArray === null) {
            ttArray = re.search(":([a-zA-Z_0-9]+)\\[\\]}", type)
        }        
    }
    
    if (ttValue != null) {
        valueType = re.getReg(type, ttValue.regs[1])
        if (valueType.indexOf("Array<") === 0) {
            valueArrayType = re.getReg(valueType, ttArray.regs[1])
            valueType = undefined
        } else if (ttMap != undefined) {
            valueMapType = re.getReg(type, ttMap.regs[1])
            valueType = undefined
        }
    }
    if (ttMap != null) {
        valueMapType = re.getReg(type, ttMap.regs[1])
    }
    if (ttArray != null) {
        valueArrayType = re.getReg(type, ttArray.regs[1])
    }
    return [re.getReg(type, ttKey.regs[1]), valueType, valueMapType, valueArrayType]
}

function getUnionType(type) {
    type = type.replace(/\s*/g,"")
    var typeArr = new Array()
    typeArr = type.split("|")
    return typeArr
}

function isFuncType(type) {
    let isFunction = false; 
    if (type === null || type === undefined) {
        return isFunction;
    }
    
    if (type === 'function' || type === 'Function') {
        isFunction = true;
        return isFunction;
    }
}

function isRegisterFunc(name) {
    let regIndex = name.indexOf('register');
    let isRegister = false
    if (regIndex === 0) {
        isRegister = true
    }
    return isRegister
}

function isUnRegisterFunc(name) {
    let unRegIndex = name.indexOf('unRegister');
    let isRegister = false
    if (unRegIndex === 0) {
        isRegister = true
    }
    return isRegister
}

function isOnObjCallback(name) {
    let regIndex = name.indexOf('on');
    let flag = false
    let onLen = 2;
    if (regIndex === 0 && name.length > onLen) {
        flag = true
    }
    return flag
}

// 箭头函数，如funTest(cb: (wid: boolean) => void): string;
function isArrowFunc(type) {
    let arrowFunc = false;
    if (type.indexOf('AUTO_CALLFUNCTION') >= 0 || type.indexOf('=>') > 0) {
        arrowFunc = true;
    }
    return arrowFunc;
}

function isOnOffRegisterFunc(name) {
    let flag = false;
    if (name === 'on' || name === 'off' || isRegisterFunc(name) || isUnRegisterFunc(name) ||
      isOnObjCallback(name)) {
        flag = true;
    }
    return flag;
}

function isCreateThreadsafeFunc(name) {
    let index = name.indexOf('createThreadSafeFunc');
    let isTdSafeFunc = false
    if (index === 0) {
        isTdSafeFunc = true
    }
    return isTdSafeFunc
}

function getOnObjCallbackType(funcName, interName) {
    let onObjCbType = ''
    if (interName != '') {
        onObjCbType = interName + '_' + funcName
    } else {
        onObjCbType = funcName
    }
    return 'AUTO_CALLFUNCTION_' + onObjCbType
}

function getOnCallbackFunAndInterName(CallbackType) {
    CallbackType = CallbackType.replaceAll('AUTO_CALLFUNCTION_', '')
    let CallbackTypes = CallbackType.split('_')
    let funcName = CallbackTypes[1];
    let interName = CallbackTypes[0];
    return [interName, funcName]
}

class jsonCfgList { }
jsonCfgList.jsonCfg = [];
jsonCfgList.push = function (ifs) {
  jsonCfgList.jsonCfg.push(ifs)
}
jsonCfgList.pop = function () {
  jsonCfgList.jsonCfg.pop()
}
jsonCfgList.getValue = function (className, inter) {
    let ifs = jsonCfgList.jsonCfg[jsonCfgList.jsonCfg.length - 1]
    for (let i in ifs) {
        if (ifs[i].interfaceName.className === className && ifs[i].interfaceName.funcName === inter) {
            return ifs[i].serviceCode
        }
    }
    return null;
}

function getLogErrInfo() {
  let errInfo = " Please refer to for support capacity:"
      + "https://gitee.com/openharmony/napi_generator/tree/master/release-notes"
  return errInfo
}

module.exports = {
    FuncType,
    EnumValueType,
    NumberIncrease,
    InterfaceList,
    TypeList,
    CallFunctionList,
    isType,
    typeIndex,
    getArrayType,
    getArrayTypeTwo,
    checkFileError,
    isEnum,
    enumIndex,
    getMapType,
    EnumList,
    jsType2CType,
    getUnionType,
    isFuncType,
    isArrowFunc,
    jsonCfgList,
    isRegisterFunc,
    isUnRegisterFunc,
    isOnObjCallback,
    isOnOffRegisterFunc,
    getOnObjCallbackType,
    getLogErrInfo,
    isCreateThreadsafeFunc
}