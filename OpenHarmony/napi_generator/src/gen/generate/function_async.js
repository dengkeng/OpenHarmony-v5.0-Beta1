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
const { jsonCfgList, InterfaceList }= require("../tools/common");

/**
 * 结果异步返回Async|Promise
 */
let funcAsyncMiddleHTemplete = `
struct [funcName]_value_struct {[valueIn]
    uint32_t outErrCode = 0;[valueOut]
};

[static_define]void [funcName]_execute(XNapiTool *pxt, DataPtr data);
[static_define]void [funcName]_complete(XNapiTool *pxt, DataPtr data);
[static_define]napi_value [funcName]_middle(napi_env env, napi_callback_info info);
`

let funcAsyncTemplete = `
void [middleClassName][funcName]_execute(XNapiTool *pxt, DataPtr data)
{
    void *data_ptr = data;
    [funcName]_value_struct *vio = static_cast<[funcName]_value_struct *>(data_ptr);
    [checkout_async_instance]
    [callFunc]
}

void [middleClassName][funcName]_complete(XNapiTool *pxt, DataPtr data)
{
    void *data_ptr = data;
    [funcName]_value_struct *vio = static_cast<[funcName]_value_struct *>(data_ptr);
    napi_value result = nullptr;
    [valuePackage]
    napi_value errCodeResult = nullptr;
    napi_value napiErrCode = nullptr;
    napiErrCode = NUMBER_C_2_JS(pxt, vio->outErrCode);
    pxt->SetValueProperty(errCodeResult, "code", napiErrCode);
    {
        napi_value args[XNapiTool::TWO] = {errCodeResult, result};
        pxt->FinishAsync(XNapiTool::TWO, args);
    }
    [optionalParamDestory]
    delete vio;
}

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
    [valueCheckout][optionalCallbackInit][start_async]
    return result;
}`

let cppTemplate = `
bool %s%s(%s)
{
    %s[replace_valueOut]
    return true;
}
`

let cppCbResultTemplate = `
[replace_outDefine]
void %s%sSetCbValue(%s)
{
  %s
  return;
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
    return "vio->out = new %s;".format(cType)
}

function replaceBasicInfo(middleFunc, middleH, className) {
    if (className == null) {
        middleH = middleH.replaceAll("[static_define]", "")
        middleFunc = middleFunc.replaceAll("[unwarp_instance]", "")
        middleFunc = middleFunc.replaceAll("[checkout_async_instance]", "")
        middleFunc = middleFunc.replaceAll("[middleClassName]", "")
    }
    else {
        middleH = middleH.replaceAll("[static_define]", "static ")
        middleFunc = middleFunc.replaceAll("[unwarp_instance]",
            `pxt->SetAsyncInstance(pxt->UnWarpInstance());`)
        middleFunc = middleFunc.replaceAll("[checkout_async_instance]",
            "%s *pInstance = (%s *)pxt->GetAsyncInstance();".format(className, className))
        middleFunc = middleFunc.replaceAll("[middleClassName]", className + "_middle" + "::")
    }
    return [middleFunc, middleH]
}
function generateFunctionAsync(func, data, className, implHCbVariable) {
    let middleFunc = replaceAll(funcAsyncTemplete, "[funcName]", func.name)
    let middleH = ""
    if (func.name != "constructor") {
      middleH = replaceAll(funcAsyncMiddleHTemplete, "[funcName]", func.name)
    }
    let basicInfoRes = replaceBasicInfo(middleFunc, middleH, className)
    middleFunc = basicInfoRes[0]
    middleH = basicInfoRes[1]

    // 定义输入,定义输出,解析,填充到函数内,输出参数打包,impl参数定义,可选参数内存释放
    let param = { valueIn: "", valueOut: "", valueCheckout: "", valueFill: "",
        valuePackage: "", valueDefine: "", optionalParamDestory: "" }

    for (let i in func.value) {
        paramGenerate(i, func.value[i], param, data)
    }
    returnGenerate(param.callback, param, data)
    middleH = replaceValueOut(middleH, param);

    if (param.valueCheckout == "") {
        middleFunc = replaceAll(middleFunc, "[valueCheckout]", param.valueCheckout) // # 输入参数解析
    } else {
        param.valueCheckout = removeEndlineEnter(param.valueCheckout)
        middleFunc = replaceAll(middleFunc, "[valueCheckout]", param.valueCheckout) // # 输入参数解析
    }
    let optionalCallback = getOptionalCallbackInit(param)
    if (optionalCallback == "") {
        middleFunc = replaceAll(middleFunc, "[optionalCallbackInit]", optionalCallback) // 可选callback参数初始化
    } else {
        middleFunc = replaceAll(middleFunc, "[optionalCallbackInit]", optionalCallback + "\n    ") // 可选callback参数初始化
    }
    middleFunc = replaceAll(middleFunc, "[start_async]", `
    napi_value result = pxt->StartAsync(%s_execute, reinterpret_cast<DataPtr>(vio), %s_complete,
    pxt->GetArgc() == %s? pxt->GetArgv(%d) : nullptr);`
        .format(func.name, func.name, getConstNum(parseInt(param.callback.offset) + 1),
        getConstNum(param.callback.offset))) // 注册异步调用
    let callFunc = "%s%s(%s);".format(className == null ? "" : "pInstance->", func.name, param.valueFill)
    middleFunc = replaceAll(middleFunc, "[callFunc]", callFunc) // 执行
    middleFunc = replaceAll(middleFunc, "[valuePackage]", param.valuePackage) // 输出参数打包
    middleFunc = replaceAll(middleFunc, "[optionalParamDestory]", param.optionalParamDestory) // 可选参数内存释放

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

        let outResult = generateCbInterfaceOutFunc(param, className, prefixArr, implHCbVariable, implCpp, implH)
        implCpp = outResult[0]
        implH = outResult[1]
    }
    return [middleFunc, implH, implCpp, middleH]
}

function generateCbInterfaceOutFunc(param, className, prefixArr, implHCbVariable, implCpp, implH) {
    let cbInterfaceRes = "";
    let outInterfaceDefine = param.valueDefine.substring(param.valueDefine.lastIndexOf(",") + 1,
        param.valueDefine.length);
    outInterfaceDefine = replaceAll(outInterfaceDefine, ' ', '');
    let index = outInterfaceDefine.indexOf('&');
    let outInterfaceName = outInterfaceDefine.substring(0, index);
    if (InterfaceList.getValue(outInterfaceName)) {
        let defineParams = '';
        let useParams = '';
        let interBody = InterfaceList.getValue(outInterfaceName);
        for (let i = 0; i < interBody.length; i++) {
            let realType = interBody[i].type == "string" ? "std::string" : interBody[i].type;
            realType = interBody[i].type == "boolean" ? "bool" : realType;
            defineParams += "%s %s, ".format(realType, interBody[i].name);
            useParams += "%s%sOutRes.%s = %s;\n".format(className == null ? "" : className + "::",
                outInterfaceName.toLocaleLowerCase(), interBody[i].name, interBody[i].name);
        }
        defineParams = defineParams.substring(0, defineParams.length - 2);
        let cbOutDefine = "\n%s %s%sOutRes = {};".format(outInterfaceName, className == null ? "" : className + "::",
        outInterfaceName.toLocaleLowerCase())
        cbInterfaceRes = cppCbResultTemplate.format(className == null ? "" : className + "::", outInterfaceName.toLocaleLowerCase(),
            defineParams, useParams);
        if (className != null) {
            cbInterfaceRes = replaceAll(cbInterfaceRes, '[replace_outDefine]', cbOutDefine)
        } else {
            cbInterfaceRes = replaceAll(cbInterfaceRes, '[replace_outDefine]', '')
        }
       
        // 多次使用interface(非匿名)作为Promise回调只需生成一次cbResult接口
        let outResDefine = "\n%s%s%sstatic %s %sOutRes;".format(
            prefixArr[0], prefixArr[1], prefixArr[2], outInterfaceName, outInterfaceName.toLocaleLowerCase());
        let replaceOut = "\n    out = %s%sOutRes;".format(className == null ? "" : className + "::",
            outInterfaceName.toLocaleLowerCase());
        implCpp = replaceAll(implCpp, "[replace_valueOut]", replaceOut);
        if (implHCbVariable.indexOf(outResDefine) < 0) {
            implH += outResDefine;
            implH += "\n%s%s%svoid %sSetCbValue(%s);".format(
                prefixArr[0], prefixArr[1], prefixArr[2], outInterfaceName.toLocaleLowerCase(), defineParams);
            implCpp += cbInterfaceRes;
        }
    } else {
        implCpp = replaceAll(implCpp, "[replace_valueOut]", '');
    }
    return [implCpp, implH];
}

function replaceValueOut(middleH, param) {
    middleH = replaceAll(middleH, "[valueIn]", param.valueIn); // # 输入参数定义
    if (param.valueOut == "") {
        middleH = replaceAll(middleH, "[valueOut]", param.valueOut); // # 输出参数定义
    } else {
        middleH = replaceAll(middleH, "[valueOut]", "\n    " + param.valueOut); // # 输出参数定义
    }
    return middleH;
}

module.exports = {
    generateFunctionAsync
}