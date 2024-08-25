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
const { replaceAll } = require("../tools/tool");
const re = require("../tools/re");
const { eventParamGenerate } = require("./param_generate");
const { returnGenerate } = require("./return_generate");
const { cToJs } = require("./return_generate");
const { jsonCfgList, isRegisterFunc, isUnRegisterFunc, getOnObjCallbackType, isOnObjCallback } = 
require("../tools/common");

let middleHOnOffTemplate = `
struct [funcName]_value_struct {
    std::string eventName;
};

[static_define]napi_value [funcName]_middle(napi_env env, napi_callback_info info);
`
let middleHCallbackTemplate = `
  void [eventName]CallbackMiddle(std::string &eventName, [callback_param_type]);
  void [eventName]AsyncOrSyncCallbackMiddle(const std::string &eventName, [callback_param_type]);
`

/**
 * on和off接口生成模板
 */
let funcOnOffTemplete = `
napi_value [middleClassName][funcName]_middle(napi_env env, napi_callback_info info)
{
    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();
    if (pxt->IsFailed()) {
        napi_value err = pxt->GetError();
        delete pxt;
        return err;
    }
    struct [funcName]_value_struct *vio = new [funcName]_value_struct();
    [getEventName]
    [handleRegist]

    napi_value result = pxt->UndefinedValue();
    delete vio;
    delete pxt; // release
    return result;
}
`

let middleAsyncCallbackTemplate = `
void [middleClassName][eventNames]AsyncOrSyncCallbackMiddle(const std::string &eventName, [callback_param_type])
{
  printf("onSayHelloStartAsyncOrSyncCallbackMiddle callFuncs_.count %u  ",
  (unsigned int)XNapiTool::callFuncs_.count(eventName));
	if(XNapiTool::callFuncs_.count(eventName) <= 0) {
        return;
    }
  CallFunc *pAsyncFuncs = &XNapiTool::callFuncs_[eventName];
	napi_value exports = nullptr;
	XNapiTool *pxt = std::make_unique<XNapiTool>(pAsyncFuncs->env_, exports).release();
    napi_value result = nullptr;
    napi_status status = napi_create_array(pAsyncFuncs->env_, &result);
    if (status != napi_ok) {
      return;  // napi数组创建失败
    }
    [cb_params_define]
    [cb_params]
    [value_set_array]
  XNapiTool::[call_function_name](pAsyncFuncs, result);
	delete pxt;
}
`

let fixedTypeMiddleTemplate = 
`if (eventName != "[eventName]") { // on方法注册字段为固定值时,判断ts文件中注册的字段与使用字段是否一样
        printf("eventName Err !");
        return;
    }`

let middleEventCallbakTemplate = `
void [middleClassName][eventName]CallbackMiddle(std::string &eventName, [callback_param_type]) {
    [replace_onTypeMiddle]
    [middleClassName][eventName]AsyncOrSyncCallbackMiddle(eventName, [callback_param_name]);
}
`

let implHEventCallbakTemplate = `
//供业务调用的回调接口
void [eventName]Callback([callback_eventName][callback_param_type]);
`

let implCppEventCallbakTemplate = `
//供业务调用的回调接口
void [className][eventName]Callback([callback_eventName][callback_param_type])
{
  [eventName_is_string]
  [use_callback_func]
}
`

function isOnTypeExist(onTypeList, newType) {
    if (!onTypeList) {
        return false
    }

    for (var i in onTypeList) {
        if (onTypeList[i] === newType) {
            return true
        }
    }
    return false
}

function addOnTypeToList(data, newType) {
    if (!data.onTypeList) {
        data.onTypeList = []
    }

    data.onTypeList.push(newType)
}

function isOnOffFuncExist(data, funcName) {
    return data.onOffList && data.onOffList.indexOf(funcName) > -1
}

function addOnOffFunc(data, funcName) {
    if (!data.onOffList) {
        data.onOffList = []
    }
    data.onOffList.push(funcName)
}

function getregistLine(name) {
    let registLine = ''
    if (isRegisterFunc(name)) {
        registLine = "pxt->RegistOnOffFunc(vio->eventName, pxt->GetArgv(XNapiTool::ZERO));"
    } else if (name === 'on') {
        registLine = "pxt->RegistOnOffFunc(vio->eventName, pxt->GetArgv(XNapiTool::ONE));"    
    } else if (isOnObjCallback(name)) {
        // registLine = "pxt->RegistOnOffFunc(vio->eventName, cbFunc);"
    }else { // off/unRegister处理
        registLine = "pxt->UnregistOnOffFunc(vio->eventName);"
    }
    return registLine
}

function getPrefix(isRegister) {
    let prefix = ''
    if (isRegister) {
        prefix = "register"
    } else {
        prefix = "unRegister" 
    }
    return prefix;
}

function gennerateOnOffContext(codeContext, func, data, className, param) {
    let isRegister = isRegisterFunc(func.name);
    let isUnRegister = isUnRegisterFunc(func.name)
    let getEventName = ''
    let registLine = getregistLine(func.name)
    let onObjFlag = isOnObjCallback(func.name)

    if (isRegister || isUnRegister) {
        let prefix = getPrefix(isRegister)
        param.eventName = func.name.replaceAll(prefix, "") // 去掉注册、注销关键字前缀       
        getEventName = 'vio->eventName = "%s";\n'.format(param.eventName) 
    } else if (onObjFlag) {
        param.eventName = className + '_' +func.name      
        getEventName = 'vio->eventName = "%s";\n'.format(param.eventName)
    } else {
        getEventName = 'pxt->SwapJs2CUtf8(pxt->GetArgv(XNapiTool::ZERO), vio->eventName);\n'
    }
    codeContext.middleFunc = replaceAll(funcOnOffTemplete, "[funcName]", func.name)

    if (func.name != "constructor") {
      codeContext.middleH = replaceAll(middleHOnOffTemplate, "[funcName]", func.name)
    }
    codeContext.middleFunc = codeContext.middleFunc.replaceAll("[getEventName]", getEventName)
    let middleClassName = ""
    if (className == null) {
        codeContext.middleH = codeContext.middleH.replaceAll("[static_define]", "")
        codeContext.middleFunc = codeContext.middleFunc.replaceAll("[middleClassName]", "")
    }
    else {
        middleClassName = className + "_middle"
        codeContext.middleH = codeContext.middleH.replaceAll("[static_define]", "static ")
        codeContext.middleFunc = codeContext.middleFunc.replaceAll("[middleClassName]", middleClassName + "::")
    }
    let instancePtr = "%s".format(className == null ? "" : "pInstance->")
    codeContext.middleFunc = replaceAll(codeContext.middleFunc, "[instance]", instancePtr) //执行
    
    codeContext.middleFunc = replaceAll(codeContext.middleFunc, "[handleRegist]", registLine) //注册/去注册event
   
    if (isRegister) {
        codeContext.middleFunc = replaceAll(codeContext.middleFunc, "(vio->eventName)", "()")
    }

    addOnOffFunc(data, func.name)
}

function gennerateEventCallback(codeContext, data, param, className = null, isOnFuncFlag = false) {
    let paramIsAsync = false
    let middleClassName = ""

    param.resultDefine = ''
    param.cbParams = ''
    param.valueSetArray = '' 
    param.useParams = ''
    param.params = ''

    returnGenerate(param.callback, param, data, isOnFuncFlag)
    if (param.params === '') {
        let paramType = param.valueOut.substring(0, param.valueOut.lastIndexOf(' ') + 1)
        if (paramType != null && paramType != undefined && paramType != '') {
            param.params = paramType + '&valueIn'  
        }        
    }
    if (param.useParams === '' && param.params != '') {
        param.useParams = 'valueIn'
    }
     
    if (className != null) {
        middleClassName = className + "_middle"
    }
    
    let callFunctionName = paramIsAsync? "CallAsyncFunc" : "CallSyncFunc"
    let callbackFunc = middleAsyncCallbackTemplate
    callbackFunc = replaceAll(middleAsyncCallbackTemplate, "[eventNames]", param.eventName)
    callbackFunc = replaceAll(callbackFunc, "[callback_param_type]", param.params)
    if (param.params === '') {
        callbackFunc = replaceAll(callbackFunc, "&eventName, ", "&eventName")
    }

    // 回调是箭头函数
    if (param.callback != null && param.callback.isArrowFuncFlag != undefined && param.callback.isArrowFuncFlag) {
        callbackFunc = getArrowCallbackC2JsParam(callbackFunc, param);
    } else { // 回调是普通callback
        callbackFunc = getCallbackC2JsParam(callbackFunc, param);
    }
    callbackFunc = replaceAll(callbackFunc, "[call_function_name]", callFunctionName)
    if (className != null) {
        callbackFunc = replaceAll(callbackFunc, "[middleClassName]", middleClassName + "::")
    } else {
        callbackFunc = replaceAll(callbackFunc, "[middleClassName]", "")
    }
    codeContext.middleFunc += callbackFunc

     // 为每个on的event事件生成回调方法
    genCallbackMiddleMethod(param, className, middleClassName, codeContext);

    // 为每个on的event事件生成回调接口供用户侧使用
    genCallbackMethodH(param, codeContext);

    // 为每个on的event事件生成回调接口在工具代码中声明
    let middleHCallback = replaceAll(middleHCallbackTemplate, "[eventName]", param.eventName)
    middleHCallback = replaceAll(middleHCallback, "[callback_param_type]", param.params)
    if (param.params === '') {
        middleHCallback = replaceAll(middleHCallback, "&eventName,", "&eventName")
    }
    codeContext.middleH += middleHCallback

    // 为每个on的event事件生成回调接口的实现供用户侧使用
    genCallbackMethod(param, className, middleClassName, codeContext);
}

function getArrowCallbackC2JsParam(callbackFunc, param) {
    callbackFunc = replaceAll(callbackFunc, "[cb_params_define]", param.resultDefine);
    callbackFunc = replaceAll(callbackFunc, "[cb_params]", param.cbParams + '\n');
    callbackFunc = replaceAll(callbackFunc, "[value_set_array]", param.valueSetArray);
    return callbackFunc;
}

function getCallbackC2JsParam(callbackFunc, param) {
    callbackFunc = replaceAll(callbackFunc, "[cb_params_define]", `napi_value resultTmp = nullptr; `);
    callbackFunc = replaceAll(callbackFunc, "[cb_params]", param.valuePackage);
    callbackFunc = replaceAll(callbackFunc, "[value_set_array]",
      `napi_set_element(pAsyncFuncs->env_, result, 0, resultTmp);`);
    return callbackFunc;
}

function genCallbackMiddleMethod(param, className, middleClassName, codeContext) {
    let middleEventCallBack = replaceAll(middleEventCallbakTemplate, "[eventName]", param.eventName);
    middleEventCallBack = replaceAll(middleEventCallBack, "[callback_param_type]", param.params);
    middleEventCallBack = replaceAll(middleEventCallBack, "[callback_param_name]", param.useParams);
    if (className != null) {
        middleEventCallBack = replaceAll(middleEventCallBack, "[middleClassName]", middleClassName + "::");
    } else {
        middleEventCallBack = replaceAll(middleEventCallBack, "[middleClassName]", "");
    }
    let middleEventTypeTemplate = replaceAll(fixedTypeMiddleTemplate, "[eventName]", param.eventName);
    if (param.eventNameIsStr) {
        middleEventCallBack = replaceAll(middleEventCallBack, "[replace_onTypeMiddle]", "");
    } else {
        middleEventCallBack = replaceAll(middleEventCallBack, "[replace_onTypeMiddle]", middleEventTypeTemplate);
    }
    if (param.params === '') {
        middleEventCallBack = replaceAll(middleEventCallBack, "eventName, ", "eventName")
    }
    codeContext.middleFunc += middleEventCallBack;
}

function genCallbackMethodH(param, codeContext) {
    let eventNameDefine = param.eventNameIsStr ? "std::string &eventName, " : "";
    if (param.params === '' && eventNameDefine != '') {
        eventNameDefine = "std::string &eventName"
    }
    let implHCallBack = replaceAll(implHEventCallbakTemplate, "[eventName]", param.eventName);
    implHCallBack = replaceAll(implHCallBack, "[callback_param_type]", param.params);
    implHCallBack = replaceAll(implHCallBack, "[callback_eventName]", eventNameDefine);
    codeContext.implH += implHCallBack;
}

function genCallbackMethod(param, className, middleClassName, codeContext) {
    let isStrType = param.eventNameIsStr ? "" : `std::string eventName = "[fixed_eventName]";`;
    isStrType = replaceAll(isStrType, "[fixed_eventName]", param.eventName);
    let implCppCallBack = replaceAll(implCppEventCallbakTemplate, "[eventName]", param.eventName);
    implCppCallBack = replaceAll(implCppCallBack, "[callback_param_type]", param.params);
    implCppCallBack = replaceAll(implCppCallBack, "[eventName_is_string]", isStrType);
    let eventNameDefine = param.eventNameIsStr ? "std::string &eventName, " : "";
    if (param.params === '' && eventNameDefine != "") {
        eventNameDefine = replaceAll(eventNameDefine, "&eventName,", "&eventName")
    }

    implCppCallBack = replaceAll(implCppCallBack, "[callback_eventName]", eventNameDefine);

    let callbackNoClass = `[eventName]CallbackMiddle(eventName, [callback_param_name]);`;
    let callbackClass = `  [middleClassName] *ptr = new [middleClassName]();
        ptr->[eventName]CallbackMiddle(eventName, [callback_param_name]);
        delete ptr;`;

    if (className === null) {
      let callbackNoClassRes = replaceAll(callbackNoClass, "[eventName]", param.eventName);
      callbackNoClassRes = replaceAll(callbackNoClassRes, "[callback_param_name]", param.useParams);
      if (param.useParams === '') {
        callbackNoClassRes = replaceAll(callbackNoClassRes, "eventName, ", "eventName")
      }
      implCppCallBack = replaceAll(implCppCallBack, "[use_callback_func]", callbackNoClassRes);
      implCppCallBack = replaceAll(implCppCallBack, "[className]", "");
    } else {
      let callbackClassRes = replaceAll(callbackClass, "[eventName]", param.eventName);
      callbackClassRes = replaceAll(callbackClassRes, "[callback_param_name]", param.useParams);
      callbackClassRes = replaceAll(callbackClassRes, "[middleClassName]", middleClassName);
      if (param.useParams === '') {
        callbackClassRes = replaceAll(callbackClassRes, "eventName, ", "eventName")
      }
      implCppCallBack = replaceAll(implCppCallBack, "[use_callback_func]", callbackClassRes);
      implCppCallBack = replaceAll(implCppCallBack, "[className]", className + "::");
    }

    codeContext.implCpp += implCppCallBack;
}

function generateFunctionOnOff(func, data, className) {
    let param = {
        valueIn: "", // 定义输入
        valueOut: "", // 定义输出
        valueCheckout: "", // 解析
        valueFill: "", // 填充到函数内
        valuePackage: "", // 输出参数打包
        valueDefine: "", // impl参数定义
        eventName:"", // 注册/去注册事件名称
        eventNameIsStr:false, // 注册/去注册事件名称是否在ts中为string类型
        optionalParamDestory: "" // 可选参数内存释放
    }

    let isRegister = isRegisterFunc(func.name)
    let onObjFlag = isOnObjCallback(func.name)
    if (onObjFlag) {
        let cbType = getOnObjCallbackType(func.name, className)
        let funcValue = {
            type: cbType,
            optional: false
        }
        eventParamGenerate(0, funcValue, param, data)

    } else {
        for (let i in func.value) {
            eventParamGenerate(i, func.value[i], param, data)
        }    
    }

    let codeContext = {
        middleFunc: "",
        implH: "",
        implCpp: "",
        middleH: ""
    }
    if (!isOnOffFuncExist(data, func.name)) {
        // 同一个ts文件中所有的on和off 接口只需要生成一份公共的native方法
        gennerateOnOffContext(codeContext, func, data, className, param)
    }

    if (func.name === 'on' || isRegister || onObjFlag) {
        // 为每个on接口同步生成eventCallback方法供用户回调使用
        let isOnFuncFlag = true;
        gennerateEventCallback(codeContext, data, param, className, isOnFuncFlag)
    }

    return [codeContext.middleFunc, codeContext.implH, codeContext.implCpp, codeContext.middleH]
}

module.exports = {
    generateFunctionOnOff
}