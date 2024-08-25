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
const { replaceAll, getPrefix, getConstNum } = require("../tools/tool");
const { paramGenerate } = require("./param_generate");
const { returnGenerate } = require("./return_generate");
const { NapiLog } = require("../tools/NapiLog");
const { NumberIncrease, jsonCfgList, getLogErrInfo }= require("../tools/common");

/**
 * 结果通过同步回调(CallBack)返回
 */
let funcSyncMiddleHTemplete = `
struct [funcName]_value_struct {[valueIn][valueOut]
};

[static_define]napi_value [funcName]_middle(napi_env env, napi_callback_info info);
`

let funcSyncTemplete = `
napi_value [middleClassName][funcName]_middle(napi_env env, napi_callback_info info)
{
    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();
    if (pxt->IsFailed()) {
        napi_value err = pxt->GetError();
        delete pxt;
        return err;
    }
    [unwarp_instance]
    struct [funcName]_value_struct *vio = new [funcName]_value_struct();
    [valueCheckout][optionalCallbackInit]
    [callFunc]
    napi_value result = nullptr;
    napi_value retVal = nullptr;
    if (pxt->GetArgc() > [callback_param_offset]) {
        static const int ARGS_SIZE = [agrs_size];
        napi_value args[ARGS_SIZE];
        [valuePackage]  
        {
            // 回调为Callback<XX>，参数个数为1，其转换结果保存在result中
            // 回调为箭头函数，支持参数个数大于1，参数转换结果保存在args[i]
            if (ARGS_SIZE ==  XNapiTool::ONE && result !=  nullptr) {
                args[0] = result;
            }            
            retVal = pxt->SyncCallBack(pxt->GetArgv([callback_param_offset]),  ARGS_SIZE, args);
        }
    }

    if (retVal != nullptr) {
        [cbRetValJs2C]        
        [funcRetC2Js]
    }

    [optionalParamDestory]
    delete vio;
    delete pxt; // release
    return result;
}`

let cppTemplate = `
bool %s%s(%s)
{
    %s
    return true;
}
`
let cppFuncReturnTemplate = `
bool %s%sReturn(%s)
{
    return true;
}
`

function removeEndlineEnter(value) {
    for (var i = value.length; i > 0; i--) {
        let len = value.length
        if (value.substring(len - 1, len) == "\n" || value.substring(len - 1, len) == ' ') {
            value = value.substring(0, len - 1)
        } else {
            value = '    ' + value + "\n"
            break
        }
    }
    return value
}

function getOptionalCallbackInit(param) {
    if (!param.callback.optional) {
        return ""
    }
    let cType = param.valueOut.substr(0, param.valueOut.indexOf("*"))
    return "if (pxt->GetArgc() > %s) {\n        vio->out = new %s;\n    }"
        .format(getConstNum(param.callback.offset), cType)
}

function callBackReturnValJs2C(className, funcName, callbackRetType, funcRetType) {
    let cbRetJs2CTrans = ''
    let retOutFill = ''
    if (funcRetType !== 'void') {
        retOutFill = ', vio->retOut'
    }

    if (callbackRetType === 'void') {
        cbRetJs2CTrans = '';
    } else if (callbackRetType === 'string') {
        cbRetJs2CTrans = 'pxt->SwapJs2CUtf8(retVal, vio->cbOut);\n' + 
        '%s%sReturn(vio->cbOut%s);\n'.format(className == null ? "" : "pInstance->", funcName, retOutFill);
    } else if (callbackRetType === 'boolean') {
        cbRetJs2CTrans = 'vio->cbOut = pxt->SwapJs2CBool(retVal);\n' + 
        '%s%sReturn(vio->cbOut%s);\n'.format(className == null ? "" : "pInstance->", funcName, retOutFill);
    } else if (callbackRetType.substring(0, 12) == "NUMBER_TYPE_") {
        let lt = NumberIncrease.getAndIncrease()
        cbRetJs2CTrans = 'NUMBER_JS_2_C(retVal, NUMBER_TYPE_%d, vio->cbOut);\n'.format(lt) + 
        '%s%sReturn(vio->cbOut%s);\n'.format(className == null ? "" : "pInstance->", funcName, retOutFill); 
    } else if (callbackRetType === 'number') {       
        cbRetJs2CTrans = 'NUMBER_JS_2_C(retVal, NUMBER_TYPE_1, vio->cbOut);\n' + 
        '%s%sReturn(vio->cbOut%s);\n'.format(className == null ? "" : "pInstance->", funcName, retOutFill);
    } else {
        NapiLog.logError("callBackReturnValJs2C not surpport callbackRetType:%s."
            .format(callbackRetType), getLogErrInfo());
    }
    return cbRetJs2CTrans;
}

function returnProcRetC2Js(funRetType) {
    let retC2JsCode = '';
    if (funRetType === 'void') {
        NapiLog.logInfo("returnProcRetC2Js void type do nothing!");
    } else if (funRetType === 'string') {
        retC2JsCode = 'result = pxt->SwapC2JsUtf8(vio->retOut.c_str());'
    } else if (funRetType === 'boolean') {
        retC2JsCode = 'result = pxt->SwapC2JsBool(vio->retOut);'
    } else if (funRetType.substring(0, 12) == "NUMBER_TYPE_") {
        retC2JsCode = 'result = NUMBER_C_2_JS(pxt, vio->retOut);'
    } else {
        NapiLog.logError("returnProcRetC2Js not surpport funRetType:%s".format(funRetType));
    }
    return retC2JsCode;
}

function fillCbRetValueStruct(type, param, outName) {
    if (type === null || param === null || param.valueOut === null || param.valueDefine === null) {
        NapiLog.logError("[fillCbRetValueStruct] param in is null!");
        return;
    }

    if (type === 'void') {
       NapiLog.logInfo("The current void type don't need generate");
    } else if (type === 'string') {       
        param.cbRetvalueDefine += "%sstd::string& %s".format(param.cbRetvalueDefine.length > 0 ? ", " : "", outName)
    } else if (type === 'boolean') {
        param.cbRetvalueDefine += "%sbool& %s".format(param.cbRetvalueDefine.length > 0 ? ", " : "", outName)
    } else if (type.substring(0, 12) == "NUMBER_TYPE_") {
        param.cbRetvalueDefine += "%s%s& %s".format(param.cbRetvalueDefine.length > 0 ? ", " : "", type, outName)
    } else if ( type === 'number') {
        param.cbRetvalueDefine += "%sNUMBER_TYPE_1& %s".format(param.cbRetvalueDefine.length > 0 ? ", " : "",
        type, outName)
    }
    else {
        NapiLog.logError("[fillCbRetValueStruct] The current type:%s don't support."
            .format(type), getLogErrInfo());
    }
}

function fillValueStruct(type, param, outName) {
    if (type === null || param === null || param.valueOut === null || param.valueDefine === null) {
        NapiLog.logError("[fillValueStruct] Param in is null!");
        return;
    }

    if (type === 'void') {
        NapiLog.logInfo("The current void type don't need generate");
    } else if (type === 'string') {
        param.valueOut += 'std::string %s;\n'.format(outName)
        if (param.callback.returnType === 'void') {
            param.valueDefine += "%sstd::string& %s".format(param.valueDefine.length > 0 ? ", " : "", outName)
        }        
    } else if (type === 'boolean') {
        param.valueOut += 'bool %s;\n'.format(outName)
        if (param.callback.returnType === 'void') {
            param.valueDefine += "%sbool& %s".format(param.valueDefine.length > 0 ? ", " : "", outName)
        }  
    } else if (type.substring(0, 12) === "NUMBER_TYPE_") {
        param.valueOut += '%s %s;\n'.format(type, outName)
        if (param.callback.returnType === 'void') {
            param.valueDefine += "%s%s& %s".format(param.valueDefine.length > 0 ? ", " : "", type, outName)
        }  
    } else if (type === 'number') {
        param.valueOut += 'NUMBER_TYPE_1 %s;\n'.format(outName)
        if (param.callback.returnType === 'void') {
            param.valueDefine += "%sNUMBER_TYPE_1& %s".format(param.valueDefine.length > 0 ? ", " : "", outName)
        } 
    }
    else {
        NapiLog.logError("[fillValueStruct] The current type:%s don't support."
            .format(type), getLogErrInfo());
    }
}

function callbackReturnProc(param, func) {    
    fillValueStruct(param.callback.returnType, param, 'cbOut')
    fillValueStruct(func.ret, param, 'retOut')

    // 回调返回值非空，业务代码分两部分，一部分填写JS回调需要的参数(对应funcname函数)，一部分根据回调返回值进行后续业务处理(对应funcnameReturn函数)，
    // 回调返回值为空，则业务代码处理是一个整体，对应funcname函数，统一处理填写参数、函数返回值赋值处理。
    if (param.callback.returnType === 'void') {
        if (func.ret == "string" || func.ret == "boolean" || func.ret.substring(0, 12) == "NUMBER_TYPE_") {
            param.valueFill += param.valueFill.length > 0 ? ", vio->retOut" : "vio->retOut"
        } else if (func.ret == "void") {
            NapiLog.logInfo("The current void type don't need generate");
        } else{
            NapiLog.logError("not support returnType:%s!".format(param.callback.returnType),
                getLogErrInfo())
        }
    } else {
        // param.cbRetvalueDefine赋值，传递给funcnameReturn函数
        fillCbRetValueStruct(param.callback.returnType, param, 'in')
        fillCbRetValueStruct(func.ret, param, 'out')  
    }
}

function replaceValueOut(param, middleH) {
    if (param.valueOut == "") {
        middleH = replaceAll(middleH, "[valueOut]", param.valueOut) // # 输出参数定义
    } else {
        middleH = replaceAll(middleH, "[valueOut]", "\n    " + param.valueOut) // # 输出参数定义
    }
    return middleH
}

function replaceValueCheckout(param, middleFunc) {
    if (param.valueCheckout == "") {
        middleFunc = replaceAll(middleFunc, "[valueCheckout]", param.valueCheckout) // # 输入参数解析
    } else {
        param.valueCheckout = removeEndlineEnter(param.valueCheckout)
        middleFunc = replaceAll(middleFunc, "[valueCheckout]", param.valueCheckout) // # 输入参数解析
    }
    return middleFunc
}

function generateFunctionSync(func, data, className) {
    let middleFunc = replaceAll(funcSyncTemplete, "[funcName]", func.name)
    let middleH = ""
    if (func.name != "constructor") {
      middleH = replaceAll(funcSyncMiddleHTemplete, "[funcName]", func.name)
    }
    let isClassresult = isClassFunc(className, middleH, middleFunc);
    middleH = isClassresult[0]
    middleFunc = isClassresult[1]
    
    // 定义输入,定义输出,解析,填充到函数内,输出参数打包,impl参数定义,可选参数内存释放
    let param = { valueIn: "", valueOut: "", valueCheckout: "", valueFill: "",
        valuePackage: "", valueDefine: "", optionalParamDestory: "", cbRetvalueDefine: "", paramSize: 1}

    for (let i in func.value) {
        paramGenerate(i, func.value[i], param, data)
    }
    returnGenerate(param.callback, param)
    callbackReturnProc(param, func);

    middleH = replaceAll(middleH, "[valueIn]", param.valueIn) // # 输入参数定义
    middleH = replaceValueOut(param, middleH)
    middleFunc = replaceValueCheckout(param, middleFunc)

    let callFunc = "%s%s(%s);".format(className == null ? "" : "pInstance->", func.name, param.valueFill)
    middleFunc = replaceAll(middleFunc, "[callFunc]", callFunc) // 执行
    let optionalCallback = getOptionalCallbackInit(param)
    middleFunc = replaceAll(middleFunc, "[optionalCallbackInit]", optionalCallback) // 可选callback参数初始化
    middleFunc = replaceAll(middleFunc, "[valuePackage]", param.valuePackage) // 输出参数打包
    middleFunc = replaceAll(middleFunc, "[optionalParamDestory]", param.optionalParamDestory) // 可选参数内存释放
    middleFunc = replaceAll(middleFunc, "[agrs_size]", param.paramSize)
    
    middleFunc = middleFunc.replaceAll("[callback_param_offset]", param.callback.offset); // 呼叫回调
    
    // callback返回值处理，回调成功后根据js返回值，业务进行后续处理
    let callBackReturnProc = callBackReturnValJs2C(className, func.name, param.callback.returnType, func.ret)
    middleFunc = middleFunc.replaceAll("[cbRetValJs2C]", callBackReturnProc);

    // 同步函数返回值处理
    let retTrans = returnProcRetC2Js(func.ret)
    middleFunc = middleFunc.replaceAll("[funcRetC2Js]", retTrans);

    let prefixArr = getPrefix(data, func)
    let implH = ""
    let implCpp = ""

    if (!func.isParentMember) {
        // 只有类/接口自己的成员方法需要在.h.cpp中生成，父类/父接口不需要
        implH = "\n%s%s%sbool %s(%s)%s;".format(
            prefixArr[0], prefixArr[1], prefixArr[2], func.name, param.valueDefine, prefixArr[3])
        let callStatement = jsonCfgList.getValue(className == null? "": className, func.name);
        implCpp = cppTemplate.format(className == null ? "" : className + "::", func.name, param.valueDefine,
            callStatement == null? "": callStatement)

        if (param.callback.returnType != 'void' && param.callback.returnType != undefined) {
            implH += "\n%s%s%sbool %sReturn(%s)%s;".format(
                prefixArr[0], prefixArr[1], prefixArr[2], func.name, param.cbRetvalueDefine, prefixArr[3])
            implCpp += cppFuncReturnTemplate.format(className == null ? "" : className + "::", 
            func.name, param.cbRetvalueDefine)
        }
    }
    return [middleFunc, implH, implCpp, middleH]
}

function isClassFunc(className, middleH, middleFunc) {
    if (className == null) {
        middleH = middleH.replaceAll("[static_define]", "");
        middleFunc = middleFunc.replaceAll("[unwarp_instance]", "");
        middleFunc = middleFunc.replaceAll("[middleClassName]", "");
    }
    else {
        middleH = middleH.replaceAll("[static_define]", "static ");
        middleFunc = middleFunc.replaceAll("[unwarp_instance]",
          `void *instPtr = pxt->UnWarpInstance();
        %s *pInstance = static_cast<%s *>(instPtr);`.format(className, className));
        middleFunc = middleFunc.replaceAll("[middleClassName]", className + "_middle" + "::");
    }
    return [middleH, middleFunc];
}

module.exports = {
    generateFunctionSync
}