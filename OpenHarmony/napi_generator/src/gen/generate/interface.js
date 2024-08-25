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
const { generateFunctionOnOff } = require("./function_onoff");
const { generateThreadsafeFunc } = require("./function_threadsafe");
const { FuncType, InterfaceList, getArrayType, getArrayTypeTwo, getMapType, EnumList, jsType2CType, 
    isOnOffRegisterFunc, isCreateThreadsafeFunc } = require("../tools/common");
const { jsToC, getCType, paramGenerate } = require("./param_generate");
const { cToJs } = require("./return_generate");
const re = require("../tools/re");
const { NapiLog } = require("../tools/NapiLog");
const { addUniqFunc2List, addUniqObj2List, setOverrideFunc } = require("../tools/tool");

let middleHTmplete = `
class [className]_middle {
public:
    struct constructor_value_struct {[contructorValueIn]
    };
    static napi_value constructor(napi_env env, napi_callback_info info);
    static void release(DataPtr p);
    [static_funcs]
};
`

let middleBodyTmplete = `
    napi_value [className]_middle::constructor(napi_env env, napi_callback_info info)
    {
        XNapiTool *pxt = new XNapiTool(env, info);
        napi_status status;
        size_t argc;
        status = napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr);
        if (argc > 0) {
            napi_value args[argc];
            status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
            if (status != napi_ok) {
                return nullptr;
            }
            struct constructor_value_struct *vio = new constructor_value_struct();
            [getConstructorParam]
            [className] *p = new [className]([constructorParam]);
            napi_value thisvar = pxt->WrapInstance(reinterpret_cast<DataPtr>(p), [className]_middle::release);
            delete vio;
            return thisvar;
        } else {
            [className] *p = new [className]();
            napi_value thisvar = pxt->WrapInstance(reinterpret_cast<DataPtr>(p), [className]_middle::release);
            return thisvar;
        }  
    }
    void [className]_middle::release(DataPtr p)
    {
        void *dataPtr = p;
        [className] *p2 = static_cast<[className] *>(dataPtr);
        delete p2;
    }
    [static_funcs]
`

function getHDefineOfVariable(name, type, variable, optional) {
    if (type.indexOf("|") >= 0) {
        unionTypeString(name, type, variable, optional)
    } else if (type == "string") {
        if (optional) {
            variable.hDefine += "\n    std::optional<std::string> %s;".format(name)
        } else {
            variable.hDefine += "\n    std::string %s;".format(name)
        }
    } else if (InterfaceList.getValue(type)) {
        if (optional) {
            variable.hDefine += "\n    std::optional<%s> %s;".format(type, name)
        } else {
            variable.hDefine += "\n    %s %s;".format(type, name)
        }
    } else if (EnumList.getValue(type)) {
      // 如果是枚举string类型，需要将其转换为std::string类型
      let enumBasicType = EnumList.getValue(type)[0].type
      if (enumBasicType === 'string') {
        variable.hDefine += "\n    %s %s;".format('std::string', name)
      } else {
        variable.hDefine += "\n    %s %s;".format(type, name)
      }
    } else if (type.indexOf("Array<") == 0) {
        typeArrFunctionOne(type, variable, name, optional);
    } else if (type == "boolean") {
        if (optional) {
            variable.hDefine += "\n    std::optional<bool> %s;".format(name)
        } else {
            variable.hDefine += "\n    bool %s;".format(name)
        }
    } else if (type.substring(type.length - 2) == "[]") {
        typeArrFunctionTwo(type, variable, name, optional);
    } else if (type.substring(0, 4) == "Map<" || type.indexOf("{[key:") == 0) {  // 支持可选参数？
        variable.hDefine += mapTypeString(type, name, optional)
    } else if (type == "any") {
        variable.hDefine += anyTypeString(type, name)
    } else if (type.substring(0, 12) == "NUMBER_TYPE_") {
        if (optional) {
            variable.hDefine += "\n    std::optional<%s> %s;".format(type, name)
        } else {
            variable.hDefine += "\n    %s %s;".format(type, name)
        }
    } else if (type == "Object" || type == "object") {
        variable.hDefine += "\n    std::map<std::string, std::any> %s;".format(name)
    }
    else {
        NapiLog.logError(`
        ---- generateVariable fail %s,%s ----
        `.format(name, type));
    }
}

function typeArrFunctionTwo(type, variable, name, optional) {
    let arrayType = getArrayTypeTwo(type);
    if (arrayType == "any") {
        variable.hDefine += "\n    std::string %s_type;\n    std::any %s;".format(name, name);
    } else {
        let cType = jsType2CType(arrayType);
        if (optional) {
            variable.hDefine += "\n    std::optional<std::vector<%s>> %s;".format(cType, name);
        } else {
            variable.hDefine += "\n    std::vector<%s> %s;".format(cType, name);
        }
    }
}

function typeArrFunctionOne(type, variable, name, optional) {
    let arrayType = getArrayType(type);
    if (arrayType == "any") {
        variable.hDefine += "\n    std::string %s_type; \n    std::any %s;".format(name, name);
    } else {
        let cType = jsType2CType(arrayType);
        if (optional) {
            variable.hDefine += "\n    std::optional<std::vector<%s>> %s;".format(cType, name);
        } else {
            variable.hDefine += "\n    std::vector<%s> %s;".format(cType, name);
        }
    }
}

function generateVariable(value, variable, className) {
    let name = value.name
    let type = value.type
    let optional = value.optional
    if (!value.isParentMember) {
        // 只有类/接口自己的成员属性需要在.h中定义， 父类/父接口不需要
        getHDefineOfVariable(name, type, variable, optional)
    }
    if (optional && type.indexOf("|") < 0) {
        optionalParamGetSet(type, variable, name, className);
    } else {
          variable.middleH += `
          static napi_value getvalue_%s(napi_env env, napi_callback_info info);
          static napi_value setvalue_%s(napi_env env, napi_callback_info info);\n`.format(name, name)
        variable.middleValue += `
          napi_value %s::getvalue_%s(napi_env env, napi_callback_info info)
        {
            XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();
            void *instPtr = pxt->UnWarpInstance();
            %s *p = static_cast<%s *>(instPtr);
            napi_value result = nullptr;
              `.format(className + "_middle", name, className, className) +
              cToJs("p->" + name, type, "result", 1, optional) + `
            delete pxt;
            return result;
        }
          napi_value %s::setvalue_%s(napi_env env, napi_callback_info info)
        {
            std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);
            void *instPtr = pxt->UnWarpInstance();
            %s *p = static_cast<%s *>(instPtr);
              `.format(className + "_middle", name, className, className) +
              jsToC("p->" + name, "pxt->GetArgv(XNapiTool::ZERO)",
            type, 0, optional) + `
            return nullptr;
        }`
    }
}

function optionalParamGetSet(type, variable, name, className) {
    let optType = getCType(type);
    variable.middleH += `
        static napi_value getvalue_%s(napi_env env, napi_callback_info info);
        static napi_value setvalue_%s(napi_env env, napi_callback_info info);\n`.format(name, name)
    variable.middleValue += `
        napi_value %s::getvalue_%s(napi_env env, napi_callback_info info)
        {
            XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();
            void *instPtr = pxt->UnWarpInstance();
            %s *p = static_cast<%s *>(instPtr);
            napi_value result = nullptr;
            if(p->%s.has_value()) {
                `.format(className + "_middle", name, className, className, name) +
                cToJs("p->%s.value()".format(name), type, "result") + `
            }
            delete pxt;
            return result;
        }
        napi_value %s::setvalue_%s(napi_env env, napi_callback_info info)
        {
            std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);
            void *instPtr = pxt->UnWarpInstance();
            %s *p = static_cast<%s *>(instPtr);
            if (pxt->GetProperty(pxt->GetArgv(XNapiTool::ZERO), "%s")) {
                %s %s_tmp;
                `.format(className + "_middle", name, className, className, name, optType, name) +
                jsToC("%s_tmp".format(name), "pxt->GetArgv(XNapiTool::ZERO)", type) + `
                p->%s.emplace(%s_tmp);`.format(name, name) + `
            }
            return nullptr;
        }`;
}

function unionTypeString(name, type, variable, optional) {
    if (optional) {
        variable.hDefine += `\n    std::optional<std::string> %s_type;
        std::optional<std::any> %s;`.format(name, name)
    } else {
        variable.hDefine += `\n    std::string %s_type;
        std::any %s;`.format(name, name)
    }
}

function mapTypeString(type, name, optional) {
    let mapType = getMapType(type)
    let mapTypeString
    if (mapType[1] != undefined && mapType[2] == undefined) {
        if (mapType[1] == "string") mapTypeString = "std::string, std::string"
        else if (mapType[1] == "boolean") mapTypeString = "std::string, bool"
        else if (mapType[1].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, %s".format(mapType[1])
        }
        else if (mapType[1].substring(0, 12) == "any") {
            mapTypeString = `std::string, std::any`.format(mapType[1])
            return `\n    std::map<%s> %s;
            std::string %s_type;`.format(mapTypeString, name, name)
        }
        else if (InterfaceList.getValue(mapType[1])) mapTypeString = "std::string, %s".format(mapType[1])
    }
    if (mapType[2] != undefined) {
        if (mapType[2] == "string") mapTypeString = "std::string, std::map<std::string, std::string>"
        else if (mapType[2] == "boolean") mapTypeString = "std::string, std::map<std::string, bool>"
        else if (mapType[2].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, std::map<std::string, %s>".format(mapType[2])
        }
    }
    if (mapType[3] != undefined) {
        if (mapType[3] == "string") mapTypeString = "std::string, std::vector<std::string>"
        else if (mapType[3] == "boolean") mapTypeString = "std::string, std::vector<bool>"
        else if (mapType[3].substring(0, 12) == "NUMBER_TYPE_") {
            mapTypeString = "std::string, std::vector<%s>".format(mapType[3])
        }
    }
    if (optional) {
        return "\n    std::optional<std::map<%s>> %s;".format(mapTypeString, name);
    } else {
        return "\n    std::map<%s> %s;".format(mapTypeString, name);
    }
}

function anyTypeString (type, name) {
    let anyType = `\n    std::string %s_type;
    std::any %s;`
    return anyType.format(name, name)
}

function generateInterface(name, data, inNamespace) {
    let param = { valueIn: "", valueOut: "", valueCheckout: "", valueFill: "",
    valuePackage: "", valueDefine: "", optionalParamDestory: "" }
    let getConParam = getConstructorFunc(data, param);
    let resultConnect = connectResult(data, inNamespace, name)
    let middleFunc = resultConnect[0]
    let implH = resultConnect[1]
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
    let toolNamespace = getToolNamespace(inNamespace);
    middleInit += `\n    pxt->DefineClass("%s", %s%s%s_middle::constructor,
        valueList, funcList%s);\n}\n`
        .format(name, inNamespace, toolNamespace, name, selfNs)
    let extendsStr = (data.parentNameList && data.parentNameList.length > 0) ?
        " : public %s".format(data.parentNameList.join(", public ")) : ""
    let result = {
        implH: `
class %s%s {
public:%s\n
};\n`.format(name, extendsStr, implH),
        implCpp: implCpp,
        middleBody: middleBodyTmplete.replaceAll("[className]", name).replaceAll("[static_funcs]", middleFunc)
        .replaceAll("[getConstructorParam]", getConParam)
        .replaceAll("[constructorParam]", param.valueFill),
        middleInit: middleInit,
        declarationH: `
class %s;\r`.format(name),
        middleH: middleHTmplete.replaceAll("[className]", name).replaceAll("[static_funcs]", middleH)
        .replaceAll("[contructorValueIn]", param.valueIn)
    }
    return result
}

function getConstructorFunc(data, param) {
    let funcValues = null;
    if (data.function != null) {
        for (let i = 0; i < data.function.length; i++) {
            if (data.function[i].name == "constructor") {
                funcValues = data.function[i].value;
            }
        }
    }
    for (let j in funcValues) {
        paramGenerate(j, funcValues[j], param, data);
    }
    let tmpBody = param.valueCheckout.split(';\n');
    let getConParam = "";
    for (let i in tmpBody) {
        let flag = tmpBody[i].replaceAll('\n', '').replaceAll(' ', '')
        if (flag != '') {
            let indexBegin = tmpBody[i].indexOf("pxt->GetArgv(");
            if (indexBegin > 0 && tmpBody[i].indexOf("\n") < 0) {
              tmpBody[i] = tmpBody[i].replaceAll("pxt->GetArgv(", "args[");
              let index = tmpBody[i].indexOf(")");
              tmpBody[i] = tmpBody[i].substring(0, index) + "]" + tmpBody[i].substring(index + 1, tmpBody[i].length);  
            } else if (indexBegin > 0 && tmpBody[i].indexOf("\n") >= 0) {
              tmpBody[i] = tmpBody[i].replaceAll("pxt->GetArgv(", "args[");
              let index = tmpBody[i].indexOf("),");
              tmpBody[i] = tmpBody[i].substring(0, index) + "]" + tmpBody[i].substring(index + 1, tmpBody[i].length); 
            }
           getConParam += tmpBody[i] + ";\n";
        }
    }
    let index = getConParam.lastIndexOf(';\n')
    if (getConParam.substring(index-1, index) === ' ') {
      getConParam = getConParam.substring(0, index -1)
    }
    return getConParam;
}

// 递归获取接口及接口父类的所有成员属性和方法
function getAllPropties(interfaceBody, properties, isParentClass) {
    for (let i in interfaceBody.value) {
        interfaceBody.value[i].isParentMember = isParentClass
        addUniqObj2List(interfaceBody.value[i], properties.values)
    }
    for (let i in interfaceBody.function) {
        interfaceBody.function[i].isParentMember = isParentClass
        if(!addUniqFunc2List(interfaceBody.function[i], properties.functions)) {
            if (isParentClass) {
                // 没添加到列表，说明子类方法properties.functions重写了父类方法interfaceBody.function[i]
                // 找到该子类方法并将其设置为override (生成的重写函数如果没有override关键字会触发门禁告警)
                setOverrideFunc(interfaceBody.function[i], properties.functions)
            }
        }
    }
    if (!isParentClass && interfaceBody.parentNameList && interfaceBody.parentNameList.length > 0) {
        getAllPropties(interfaceBody.parentBody, properties, true)
    }
} 

function addVirtualKeywords(data, implH, name) {
    if (data.childList && data.childList.length > 0) {
        // 如果该类是其它类的父类，增加虚析构函数使其具备泛型特征 (基类必须有虚函数才能正确使用dynamic_cast和typeinfo等方法)
        // 如果该类自己也有父类，虚析构函数需要加上override关键字(否则C++门禁会有告警)
        let ovrrideStr = (data.parentList && data.parentList.length > 0) ? " override" : "";
        // 如果虚析构函数已经有override关键字，就不需要再加virtual关键字了(否则C++门禁会有告警)
        let virtualStr = (data.parentList && data.parentList.length > 0) ? "" : "virtual ";
        implH += "\n    %s~%s()%s {};".format(virtualStr, name, ovrrideStr);
    }
    return implH;
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
        middleH: ""
    }
    middleInit = getMiddleInitFunc(middleInit, data, variable, name, inNamespace);
    implH += variable.hDefine
    middleFunc += variable.middleValue
    middleInit += `\n    std::map<const char *, napi_callback> funcList;`
    middleH += variable.middleH
    for (let i in data.allProperties.functions) {
        let func = data.allProperties.functions[i]
        let tmp;
        if (isOnOffRegisterFunc(func.name)) {
            tmp = generateFunctionOnOff(func, data, name)
        } else if (isCreateThreadsafeFunc(func.name)) {
            tmp = generateThreadsafeFunc(func, data, name)
        }
        if (!tmp) {
            switch (func.type) {
                case FuncType.DIRECT:
                    tmp = generateFunctionDirect(func, data, name, implH)
                    break;
                case FuncType.SYNC:
                    tmp = generateFunctionSync(func, data, name)
                    break
                case FuncType.ASYNC:
                case FuncType.PROMISE:
                    tmp = generateFunctionAsync(func, data, name, implH)
                    break
                default:
                    return
            }
        }
        middleFunc += tmp[0]
        implH += tmp[1]
        implCpp += tmp[2]
        middleH += tmp[3]
        middleInit = generateMiddleInitFunc(func, inNamespace, middleInit, name);
    }
    implH = addVirtualKeywords(data, implH, name);
    return [middleFunc, implH, implCpp, middleInit, middleH]
}

function generateMiddleInitFunc(func, inNamespace, middleInit, name) {
    if (func.name != "constructor") {
        let toolNamespace = getToolNamespace(inNamespace);
        middleInit += `\n    funcList["%s"] = %s%s%s_middle::%s_middle;`.format(func.name,
            inNamespace, toolNamespace, name, func.name);
    }
    return middleInit;
}

function getMiddleInitFunc(middleInit, data, variable, name, inNamespace) {
    middleInit = `{\n    std::map<const char *, std::map<const char *, napi_callback>> valueList;`;
    data.allProperties = { values: [], functions: [] };
    getAllPropties(data, data.allProperties, false);
    let toolNamespace = getToolNamespace(inNamespace);
    for (let i in data.allProperties.values) {
        let v = data.allProperties.values[i];
        generateVariable(v, variable, name);
        middleInit += `
        valueList["%s"]["getvalue"] = %s%s%s_middle::getvalue_%s;
        valueList["%s"]["setvalue"] = %s%s%s_middle::setvalue_%s;`
        .format(v.name, inNamespace, toolNamespace, name, v.name, v.name, inNamespace, toolNamespace, name, v.name);
    }
    return middleInit;
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
    generateInterface,
    connectResult,
    generateVariable,
    mapTypeString,
    anyTypeString,
    getHDefineOfVariable
}
