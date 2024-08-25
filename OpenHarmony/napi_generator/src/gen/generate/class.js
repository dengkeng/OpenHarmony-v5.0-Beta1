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
const { FuncType, InterfaceList, getArrayType } = require("../tools/common");
const { jsToC } = require("./param_generate");
const { cToJs } = require("./return_generate");
const re = require("../tools/re");
const { NapiLog } = require("../tools/NapiLog");

let middleBodyTmplete = `
class [className]_middle {
public:
    static napi_value constructor(napi_env env, napi_callback_info info)
    {
        XNapiTool *pxt = new XNapiTool(env, info);
        [className] *p = new [className]();
        napi_value thisvar = pxt->WrapInstance(reinterpret_cast<DataPtr>(p), release);
        return thisvar;
    }
    static void release(DataPtr p)
    {
        void *dataPtr = p;
        [className] *p2 = static_cast<[className] *>(dataPtr);
        delete p2;
    }
    [static_funcs]
};`

function generateVariable(name, type, variable, className) {
    if (type == "string") variable.hDefine += "\n    std::string %s;".format(name)
    else if (type.substring(0, 12) == "NUMBER_TYPE_") variable.hDefine += "\n    %s %s;".format(type, name)
    else if (InterfaceList.getValue(type)) variable.hDefine += "\n    %s %s;".format(type, name)
    else if (type.indexOf("Array<") == 0) {
        let type2 = getArrayType(type)
        if (type2 == "string") type2 = "std::string"
        if (type2 == "boolean") type2 = "bool"
        variable.hDefine += "\n    std::vector<%s> %s;".format(type2, name)
    } else if (type == "boolean") {
        variable.hDefine += "\n    bool %s;".format(name)
    } else if (type.indexOf("[]") == 0) {
        variable.hDefine += "\n    std::vector<%s> %s;".format(type, name)
    }
    else
        NapiLog.logError(`
        ---- generateVariable fail %s,%s ----
        `.format(name, type));
    variable.middleValue += `
    static napi_value getvalue_%s(napi_env env, napi_callback_info info)
    {
        XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();
        void *instPtr = pxt->UnWarpInstance();
        %s *p = static_cast<%s *>(instPtr);
        napi_value result = nullptr;
        `.format(name, className, className) + cToJs("p->" + name, type, "result") + `
        delete pxt;
        return result;
    }
    static napi_value setvalue_%s(napi_env env, napi_callback_info info)
    {
        std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);
        void *instPtr = pxt->UnWarpInstance();
        %s *p = static_cast<%s *>(instPtr);
        `.format(name, className, className) + jsToC("p->" + name, "pxt->GetArgv(XNapiTool::ZERO)", type) + `
        return nullptr;
    }
`
}

function generateClass(name, data, inNamespace, functiontType) {
    let resultConnect = connectResult(data, inNamespace, name)
    let middleFunc = resultConnect[0]
    let implH = functiontType == "static" ? "\n" + "static " +
        resultConnect[1].substring(1, resultConnect[1].length) : resultConnect[1]
    let implCpp = resultConnect[2]
    let middleInit = resultConnect[3]
    let middleH = resultConnect[4]
    let selfNs = ""
    if (inNamespace.length > 0) {
        let nsl = inNamespace.split("::")
        nsl.pop()
        if (nsl.length >= 2) {
            selfNs = ", " + nsl[nsl.length - 1]
        }
    }
    let toolNamespace =  getToolNamespace(inNamespace)
    middleInit += `\n    pxt->DefineClass("%s", %s%s%s_middle::constructor, valueList, funcList%s);\n}\n`
        .format(name, inNamespace, toolNamespace, name, selfNs)
    let result = {
        implH: `
class %s {
public:%s
};`.format(name, implH),
        implCpp: implCpp,
        middleBody: middleBodyTmplete.replaceAll("[className]", name).replaceAll("[static_funcs]", middleFunc),
        middleInit: middleInit,
        declarationH: `
class %s;\r`.format(name), 
        middleH: middleH   
    }
    return result
}

function connectResult(data, inNamespace, name) {
    let implH = ""
    let implCpp = ""
    let middleFunc = ""
    let middleInit = ""
    let middleH = ""
    let variable = {
        hDefine: "",
        middleValue: "",
    }
    let toolNamespace =  getToolNamespace(inNamespace)
    middleInit = `{\n    std::map<const char *, std::map<const char *, napi_callback>> valueList;`
    for (let i in data.value) {
        let v = data.value[i]
        generateVariable(v.name, v.type, variable, name)
        middleInit += `
    valueList["%s"]["getvalue"] = %s%s%s_middle::getvalue_%s;
    valueList["%s"]["setvalue"] = %s%s%s_middle::setvalue_%s;`
            .format(v.name, inNamespace, toolNamespace, name, v.name, v.name, inNamespace, toolNamespace, name, v.name)
    }
    implH += variable.hDefine
    middleFunc += variable.middleValue
    middleInit += `\n    std::map<const char *, napi_callback> funcList;`
    for (let i in data.function) {
        let func = data.function[i]
        let tmp;
        switch (func.type) {
            case FuncType.DIRECT:
                tmp = generateFunctionDirect(func, '', name)
                break;
            case FuncType.SYNC:
                tmp = generateFunctionSync(func, '', name)
                break
            case FuncType.ASYNC:
            case FuncType.PROMISE:
                tmp = generateFunctionAsync(func, '', name)
                break
            default:
                return
        }
        middleFunc += tmp[0]
        implH += tmp[1]
        implCpp += tmp[2]
        middleH += tmp[3]
        middleInit += `\n    funcList["%s"] = %s%s%s_middle::%s_middle;`
          .format(func.name, inNamespace, toolNamespace, name, func.name)
    }
    return [middleFunc, implH, implCpp, middleInit, middleH]
}

function getToolNamespace(inNamespace) {
    let index = inNamespace.lastIndexOf("::");
    let toolNamespace;
    if (index > 0) {
        let bodyTmp = inNamespace.substring(0, index)
        let index2 = bodyTmp.lastIndexOf('::')
        if (index2 > 0 && index2 < index) {
            toolNamespace =  inNamespace.substring(index2 + 2, index) + '_interface::'
        } else {
          toolNamespace = bodyTmp + "_interface::";
        }
    } else {
        toolNamespace = inNamespace + "_interface::";
    }
    return toolNamespace;
}

module.exports = {
    generateClass
}