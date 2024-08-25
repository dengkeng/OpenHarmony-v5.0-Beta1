
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
const { NapiLog } = require("../tools/NapiLog");
const { replaceAll, getTab } = require("../tools/tool");
const re = require("../tools/re");
const { iServiceHTemplate, proxyHTemplate, stubHTemplate, serviceHTemplate, proxyCppTemplate,
    proxyFuncTemplate, stubCppTemplate, stubInnerFuncTemplate, serviceCppTemplate, serviceFuncImplTemplate,
    clientCppTemplate, buildGnTemplate, bundleJsonTemplate, profileGnTemplate, profileXmlTemplate, serviceCfgTemplate,
    serviceCfgGnTemplate, iServiceCppTemplate } = require("./fileTemplate");
const { DATA_W_MAP, DATA_R_MAP, VECTOR_W_MAP, VECTOR_R_MAP, getParcelType, AllParseFileList, MarshallInfo, 
    ProcessingClassList} = require("../tools/common");

let rootHFileSrc = ""; // .h文件的源码
let dependSrcList = []; //在.h文件中定义并被接口使用到的class/struct类定义源码集合(接口没用到的class定义就不需要了)
let marshallFuncList = []; // class类的消息序列化方法代码集合

let fileContent = {
    "iServiceHFile": {},
    "proxyHFile": {},
    "stubHFile": {},
    "serviceHFile": {},
    "proxyCppFile": {},
    "stubCppFile": {},
    "serviceCppFile": {},
    "clientCppFile": {},
    "buildGnFile": {},
    "bundleJsonFile": {},
    "profileGnFile": {},
    "profileXmlFile": {},
    "serviceCfgFile": {},
    "serviceCfgGnFile": {},
    "iServiceCppFile": {},
};

function getIncludeStr(includeList) {
    let includeStr = "";
    for (let i = 0; i < includeList.length; ++i) {
        includeStr += "#include " + includeList[i] + "\n";
    }
    return includeStr;
}

function getUsingStr(usingList) {
    let usingStr = "";
    for (usingName in usingList) {
        usingStr += "\nusing " + usingList[usingName].raw_type + ";";
    }
    return usingStr;
}

function getFuncParamStr(params) {
    let paramStr = "";
    for (let i = 0; i < params.length; ++i) {
        paramStr += (i == 0) ? "" : ", ";
        paramStr += params[i].type + " " + params[i].name;
    }
    return paramStr;
}

/**
 * 获取class类型在原始.h文件中的定义源码段
 * @param className 待查找的class名称(可以是struct)
 * @param rawContent .h文件源码
 * @returns class类型在原始.h文件中的定义源码段
 */
 function getClassSrc(className, rawContent) {
    let beginPos = rawContent.indexOf(className);
    if( beginPos < 0) {
        NapiLog.logError("Warning: Can not find definition of " + className);
        return null;
    }

    let firstBracesPos = rawContent.indexOf("{", beginPos); // class后面第一个{的位置
    let firstSemiPos = rawContent.indexOf(";", beginPos); // class后面第一个分号的位置
    if ( (firstBracesPos < 0) || (firstSemiPos < firstBracesPos)) {
        // class定义后面找不到{}，或先找到了结束符分号，视为该class没有相关的实现代码
        NapiLog.logError("Warning: Can not find implementation of " + className);
        return null;
    }

    let endPos = firstBracesPos + 1;
    let bracesCount = 1;
    for (; (endPos < rawContent.length) && (bracesCount != 0); ++endPos) {
        if (rawContent.charAt(endPos) == "{") {
            ++bracesCount;
        }
        if (rawContent.charAt(endPos) == "}") {
            --bracesCount;
        }
    }

    if (bracesCount != 0) {
        // 左右括号不匹配
        NapiLog.logError("Warning: The braces of %s do not match.".format(className));
        return null;
    }
    
    let classSrc = rawContent.substring(beginPos, endPos);
    return classSrc;
}

/**
 * 查看变量类型是否为class/struct类型，是否已生成指定的打包函数
 * @param vType 变量类型
 * @returns [class对应的打包函数(没有为null), class结构信息(没找到为null)]
 */
function findClassGenInfo(vType) {
    let marshallInfo = null;
    for (let i = 0; i < marshallFuncList.length; ++i) {
        if (marshallFuncList[i].className == vType) {
            marshallInfo = marshallFuncList[i].marshallFuncs;
        }
    }

    if (marshallInfo) {
        // 该class已经有生成好的包装代码，就不用再到原始代码结构体AllParseFileList中去查找了。
        return [marshallInfo, null];
    }
    let classInfo = AllParseFileList.findClassByName(vType);
    return [null, classInfo];
}

function findGetSet(propName, classInfo) {
    let upperName = propName.replace(propName[0], propName[0].toUpperCase());
    let getName = "get" + upperName;
    let setName = "set" + upperName;
    let findGet = false;
    let findSet = false;
    let result = null;
    for (let i = 0; i < classInfo.methods.public.length; ++i) {
        if (getName == classInfo.methods.public[i].name) {
            findGet = true;
        }
        if (setName == classInfo.methods.public[i].name) {
            findSet = true;
        }
    }
    if (findGet && findSet) {
        // get和set方法必须同时具备，成员对象属性才能序列化/反序列化，缺一不可。
        result = {"name": propName, "getName": getName, "setName": setName};
    } 
    return result;
}

function privatePropMashall(parcelName, objName, classInfo, marshallInfo) {
    let properties = classInfo.properties.protected.concat(classInfo.properties.private);
    let propFuncs = []; // 保存成员属性对应的get/set方法
    for (let i = 0; i < properties.length; ++i) {
        let getSetInfo = findGetSet(properties[i].name, classInfo);
        if (getSetInfo != null) {
            getSetInfo.type = properties[i].type;
            propFuncs.push(getSetInfo);
        } else {
            NapiLog.logError(
                "Warning: Can not find get/set method of %s.%s, the property will be ignored in remote request."
                .format(classInfo.name, properties[i].name));
        }
    }
    let writePropStr = "";
    let readPropStr = "";
    let tab = getTab(1);
    for (let i = 0; i < propFuncs.length; ++i) {
        writePropStr += "\n" + tab;
        writePropStr += genWrite(objName + "." + propFuncs[i].getName + "()", parcelName,  propFuncs[i].type);

        readPropStr += "\n" + tab;
        let destObj = {
            "name": objName + "." + propFuncs[i].name,
            "setFunc": objName + "." + propFuncs[i].setName,
            "type": propFuncs[i].type
        };
        readPropStr += genRead(parcelName, destObj);
    }
    marshallInfo.marshallFuncH = marshallInfo.marshallFuncH.replace("[privateMarshall]", writePropStr);
    marshallInfo.unmarshallFuncH = marshallInfo.unmarshallFuncH.replace("[privateUnmarshall]", readPropStr);
}

function publicPropMashall(parcelName, objName, classInfo, marshallInfo) {
    let properties = classInfo.properties.public;
    let writePropStr = "";
    let readPropStr = "";
    let tab = getTab(1);
    for (let i = 0; i < properties.length; ++i) {
        writePropStr += "\n" + tab;
        writePropStr += genWrite(objName + "." + properties[i].name, parcelName,  properties[i].type);

        readPropStr += "\n" + tab;
        let destObj = {
            "name": objName + "." + properties[i].name,
            "setFunc": null,
            "type": properties[i].type
        };
        readPropStr += genRead(parcelName, destObj);
    }
    marshallInfo.marshallFuncH = marshallInfo.marshallFuncH.replace("[publicMarshall]", writePropStr);
    marshallInfo.unmarshallFuncH = marshallInfo.unmarshallFuncH.replace("[publicUnmarshall]", readPropStr);
}

/**
 * 保存远程接口用到的相关class/struct定义代码，以便后面写入到生成的iservice.h接口文件中
 * @param classInfo 接口使用到的class信息
 */
function saveClassSrc(classInfo) {
    if (classInfo.isInclude) {
        // 只有service class所在的主.h文件中定义的class/struct需要保存其源码
        // 定义在其它include文件中的类，不需要保存定义源码。
        return;
    }
    for (let i = 0; i < dependSrcList.length; ++i) {
        if (dependSrcList[i].name == classInfo.name){
            // 该class的定义源码已经保存过了。
            return;
        }
    }

    let srcObj = {};
    srcObj.name = classInfo.name;
    let className = classInfo.declaration_method + " " + classInfo.name;

    // 从.h源码中获取该class定义的源码段
    srcObj.srcCode = getClassSrc(className, rootHFileSrc);
    if (srcObj.srcCode != null) {
        dependSrcList.push(srcObj);
    }
}

/**
 * 创建class对象序列化/反序列化代码数据结构
 * @param classInfo class类信息
 */
function createMarshallInfo(classInfo) {
    saveClassSrc(classInfo);
    let newMarshall = new MarshallInfo(classInfo.name);
    let objName = classInfo.name.toLowerCase();
    newMarshall.marshallFuncName = "marshalling" + classInfo.name;
    newMarshall.unmarshallFuncName = "unmarshalling" + classInfo.name;
    // 为了marshall方法的入参能同时支持左值引用marshall(xx.obj)和右值引用marshall(xx.getObj())，这里采用万能引用模板来实现
    newMarshall.marshallFuncH = replaceAll(
        "\ntemplate<typename T> // T should be [className]& or [className]&&", "[className]", classInfo.name);
    newMarshall.marshallFuncH += 
        "\n%s bool %s(MessageParcel& data, T&& %s) {[publicMarshall][privateMarshall]\n    return true;\n}\n"
        .format("__attribute__((unused)) static", newMarshall.marshallFuncName, objName);
    newMarshall.unmarshallFuncH = 
        "\n%s bool %s(MessageParcel& data, %s& %s) {[publicUnmarshall][privateUnmarshall]\n    return true;\n}\n"
        .format("__attribute__((unused)) static", newMarshall.unmarshallFuncName, classInfo.name, objName);

    let marshallInfo = {
        "className": classInfo.name,
        "marshallFuncs": newMarshall
    }
    // 这里必须先将class放入处理列表中，以免后续的属性代码生成过程中再次遇到该class类型造成无限循环嵌套。
    ProcessingClassList.push(marshallInfo); 

    // 继续生成属性代码
    publicPropMashall("data", objName, classInfo, newMarshall);
    privatePropMashall("data", objName, classInfo, newMarshall);

    marshallFuncList.push(marshallInfo); 
    return newMarshall;
}

/**
 * 生成class对象转换remote消息buffer(parcel data)的代码段
 * @param objName 待写入的class对象名
 * @param parcelName 写入目标(parcel data)变量的名称
 * @param marshallInfo class对应的打包函数(没有为null)
 * @param classInfo class结构信息
 */
function genClassWriteString(objName, parcelName, marshallInfo, classInfo) {
    let marshall = marshallInfo;
    if (!marshall) {
        // class的序列化代码还未生成，查看是否已在待处理列表中
        let ProcessingClass = ProcessingClassList.findByName(classInfo.name);
        if (ProcessingClass == null) {
            // 待处理列表中没有，则创建该class的读写代码数据。
            marshall = createMarshallInfo(classInfo);
        } else {
            // 待处理列表中存在(说明该class已经在递归生成代码的执行路径中)，直接使用即将生成的marshalling方法名
            marshall = ProcessingClass.marshallFuncs;
        }
    }
    return "%s(%s, %s);".format(marshall.marshallFuncName, parcelName, objName);
}

/**
 * 生成从remote消息buffer(parcel data)中读取class对象的代码段
 * @param destObj 待读取的class对象信息
 * @param parcelName 待读取的(parcel data)变量的名称
 * @param marshallInfo class对应的打包函数(没有为null)
 * @param classInfo class结构信息
 */
 function genClassReadString(destObj, parcelName, marshallInfo, classInfo) {
    let marshall = marshallInfo;
    if (!marshall) {
        marshall = createMarshallInfo(classInfo);
    }
    let readStr = "";
    if (destObj.setFunc) { // 有set方法的是私有成员，需要生成set代码
        let className = destObj.type;
        readStr = "%s tmp%s;\n    %s(%s, tmp%s);\n    %s(tmp%s);".format(className, className,
            marshall.unmarshallFuncName, parcelName, className, destObj.setFunc, className);
    } else {
        readStr = "%s(%s, %s);".format(marshall.unmarshallFuncName, parcelName, destObj.name);
    }
    return readStr;
}

/**
 * 生成vector集合写入remote消息buffer(parcel data)的代码段
 *
 * @param vectorName 待写入的vector变量名
 * @param parcelName 写入目标(parcel data)变量的名称
 * @param vecType vector变量类型
 * @param matchs vector类型的正则匹配结果
 * @returns 生成的vector变量序列化打包代码段
 */
 function genVectorWrite(vectorName, parcelName, vecType, matchs) {
    let rawType = re.getReg(vecType, matchs.regs[2]);
    let parcelType = getParcelType(rawType);
    let wFunc = VECTOR_W_MAP.get(parcelType);
    if (!wFunc) {
        NapiLog.logError("Unsupport writing with type: " + vecType);
        return "";
    }
    return "%s.%s(%s);".format(parcelName, wFunc, vectorName);
}

/**
 * 生成c参数写入remote消息buffer(parcel data)的代码段
 * @param srcName 待写入的c变量名
 * @param parcelName 写入目标(parcel data)变量的名称
 * @param vType c变量类型
 * @returns 生成的代码段
 */
function genWrite(srcName, parcelName, vType) {
    let matchs = re.match("(std::)?vector<([\x21-\x7e]+)[ ]?>", vType);
    if (matchs) {
        // vector类型变量包装成parcel data
        return genVectorWrite(srcName, parcelName, vType, matchs);
    }

    let parcelType = getParcelType(vType);
    let wFunc = DATA_W_MAP.get(parcelType);
    if (!wFunc) {
        let result = findClassGenInfo(vType);
        if (!result[0] && !result[1]) {
            NapiLog.logError("Unsupport writing with type: " + vType);
            return "";
        }

        // class与struct类型变量包装成parcel data
        return genClassWriteString(srcName, parcelName, result[0], result[1]);
    }

    // 基本类型变量包装成parcel data
    return "%s.%s(%s);".format(parcelName, wFunc, srcName);
}

/**
 * 生成从remote消息buffer(parcel data)中读取vector集合的代码段
 *
 * @param parcelName 待读取的消息buffer(parcel data)变量的名称
 * @param vectorName 待写入的vector变量名
 * @param vecType vector变量类型
 * @param matchs vector类型的正则匹配结果
 * @returns 生成的vector变量反序列化读取码段
 */
 function genVectorRead(parcelName, vectorName, vecType, matchs) {
    let rawType = re.getReg(vecType, matchs.regs[2]);
    let parcelType = getParcelType(rawType);
    let rFunc = VECTOR_R_MAP.get(parcelType);
    if (!rFunc) {
        NapiLog.logError("Unsupport reading with type: " + vecType);
        return "";
    }
    return "%s.%s(&(%s));".format(parcelName, rFunc, vectorName);
}

/**
 * 生成从remote消息buffer(parcel data)读取c参数的代码段
 * @param parcelName 待读取的parcel data变量名称
 * @param destObj 读取出的内容写入的c变量信息
 * @returns 生成的代码段
 */
function genRead(parcelName, destObj) {
    let matchs = re.match("(std::)?vector<([\x21-\x7e]+)[ ]?>", destObj.type);
    if (matchs) {
        // 从parcel data中读取vector类型变量
        return genVectorRead(parcelName, destObj.name, destObj.type, matchs);
    }

    let parcelType = getParcelType(destObj.type);
    let rFunc = DATA_R_MAP.get(parcelType);
    if (!rFunc) {
        let result = findClassGenInfo(destObj.type);
        if (!result[0] && !result[1]) {
            NapiLog.logError("Unsupport reading with type: " + destObj.type);
            return "";
        }

        // 从parcel data中读取class与struct类型变量
        return genClassReadString(destObj, parcelName, result[0], result[1]);
    }

    // 从parcel data中读取基本类型变量
    let result = destObj.setFunc ? "%s(%s.%s());".format(destObj.setFunc, parcelName, rFunc)
                         : "%s = %s.%s();".format(destObj.name, parcelName, rFunc) ;
    return result;
}

function genProxyFunc(funcInfo, className, paramStr) {
    let proxyFunc = replaceAll(proxyFuncTemplate, "[className]", className);
    proxyFunc = replaceAll(proxyFunc, "[funcName]", funcInfo.name);
    proxyFunc = replaceAll(proxyFunc, "[params]", paramStr);
    proxyFunc = replaceAll(proxyFunc, "[retType]", funcInfo.retType);
    proxyFunc = replaceAll(proxyFunc, "[funcEnum]", funcInfo.funcEnum);

    // 入参处理
    let writeDataStr = "";
    let tab = getTab(1);
    for (let i = 0; i < funcInfo.params.length; ++i) {
        let param = funcInfo.params[i];
        writeDataStr += (i == 0) ? "" : "\n" + tab;
        writeDataStr += genWrite(param.name, "data", param.type);
    }
    proxyFunc = replaceAll(proxyFunc, "[writeData]", writeDataStr);

    // 返回值处理
    let readReplyStr = "";
    if (funcInfo.retType != "void") {
        readReplyStr = "%s result;".format(funcInfo.retType);
        let destObj = {
            "name": "result",
            "setFunc": null,
            "type": funcInfo.retType
        };
        readReplyStr += "\n" + tab + genRead("reply", destObj);
        readReplyStr += "\n" + tab + "return result;";
    }
    proxyFunc = replaceAll(proxyFunc, "[readReply]", readReplyStr);

    return proxyFunc;
}

function genStubInnerFunc(funcInfo, className) {
    let innerFunc = replaceAll(stubInnerFuncTemplate, "[className]", className);
    innerFunc = replaceAll(innerFunc, "[funcName]", funcInfo.name);

    // 入参处理
    let readDataStr = ""; // 生成服务端读取客户端传参的代码段
    let tab = getTab(1);
    let innerParamStr = ""; // 调用业务方法时传入的入参列表
    for (let i = 0; i < funcInfo.params.length; ++i) {
        let param = funcInfo.params[i];
        let innerParamName = param.name + "Val";
        if (i > 0) {
            readDataStr += "\n" + tab;
            innerParamStr += " ,";
        }
        
        //将remote请求中的参数值读取到内部参数变量中
        readDataStr += "%s %s;".format(param.type, innerParamName); // 定义内部参数变量
        let destObj = {
            "name": param.name + "Val",
            "setFunc": null,
            "type": param.type
        };
        readDataStr += "\n" + tab + genRead("data", destObj);
        innerParamStr += innerParamName;
    }
    innerFunc = replaceAll(innerFunc, "[readData]", readDataStr);

    // 调用service的实际业务逻辑实现方法
    let writeReplyStr = ""; // 生成调用服务端实现并返回结果的代码段
    if (funcInfo.retType === "void") {
        writeReplyStr += "%s(%s); // call business implementation".format(funcInfo.name, innerParamStr);
        writeReplyStr += "\n" + tab + "reply.WriteInt32(retCode);";
    } else {
        writeReplyStr += "%s retVal = %s(%s);  // call business implementation".format(
            funcInfo.retType, funcInfo.name, innerParamStr);
        writeReplyStr += "\n" + tab + "reply.WriteInt32(retCode);";
        writeReplyStr += "\n" + tab + genWrite("retVal", "reply", funcInfo.retType);
    }
    innerFunc = replaceAll(innerFunc, "[writeReply]", writeReplyStr);
    return innerFunc;
}

function genServiceFunc(funcInfo, className, paramStr) {
    let serviceFunc = replaceAll(serviceFuncImplTemplate, "[retType]", funcInfo.retType);
    serviceFunc = replaceAll(serviceFunc, "[className]", className);
    serviceFunc = replaceAll(serviceFunc, "[funcName]", funcInfo.name);
    serviceFunc = replaceAll(serviceFunc, "[params]", paramStr);
    return serviceFunc;
}

function genFunctions(classInfo, files) {
    let res = genFunctionCode(classInfo);
    files.iServiceH = replaceAll(files.iServiceH, "[funcEnum]", res.funcEnumStr);
    files.iServiceH = replaceAll(files.iServiceH, "[functions]", res.iServiceFuncH);
    files.proxyH = replaceAll(files.proxyH, "[functions]", res.proxyFuncH);
    files.stubH = replaceAll(files.stubH, "[innerFuncDef]", res.stubInnerFuncH);
    files.serviceH = replaceAll(files.serviceH, "[functions]", res.proxyFuncH);
    files.proxyCpp = replaceAll(files.proxyCpp, "[remoteFuncImpl]", res.proxyFuncCpp);
    files.stubCpp = replaceAll(files.stubCpp, "[innerFuncMap]", res.stubInnerFuncMap);
    files.stubCpp = replaceAll(files.stubCpp, "[innerFuncImpl]", res.stubInnerFuncCpp);
    files.serviceCpp = replaceAll(files.serviceCpp, "[serviceFuncImpl]", res.serviceFuncCpp);
    files.clientCpp = replaceAll(files.clientCpp, "[clientFuncInvoke]", res.clientFuncCpp);
}

function genFilesByTemplate(upperServiceName, lowServiceName, rootInfo) {
    let files = {};
    // 按模板生成.h和.cpp文件内容框架
    files.iServiceH = replaceAll(iServiceHTemplate, "[marcoName]", upperServiceName);
    files.proxyH = replaceAll(proxyHTemplate, "[marcoName]", upperServiceName);
    files.stubH = replaceAll(stubHTemplate, "[marcoName]", upperServiceName);
    files.serviceH = replaceAll(serviceHTemplate, "[marcoName]", upperServiceName);
    files.proxyCpp = proxyCppTemplate;
    files.stubCpp = stubCppTemplate;
    files.serviceCpp = replaceAll(serviceCppTemplate, "[marcoName]", upperServiceName);
    files.clientCpp = replaceAll(clientCppTemplate, "[marcoName]", upperServiceName);
    files.iServiceCpp = iServiceCppTemplate;

    // 按模板生成资源配置文件内容框架
    files.buildGn = replaceAll(buildGnTemplate, "[lowServiceName]", lowServiceName);
    files.buildGn = replaceAll(files.buildGn, "[stubCppFile]", fileContent.stubCppFile.name);
    files.buildGn = replaceAll(files.buildGn, "[serviceCppFile]", fileContent.serviceCppFile.name);
    files.buildGn = replaceAll(files.buildGn, "[proxyCppFile]", fileContent.proxyCppFile.name);
    files.buildGn = replaceAll(files.buildGn, "[clientCppFile]", fileContent.clientCppFile.name);
    files.buildGn = replaceAll(files.buildGn, "[iServiceCppFile]", fileContent.iServiceCppFile.name);
    files.bundleJson = replaceAll(bundleJsonTemplate, "[lowServiceName]", lowServiceName);
    files.profileGn = replaceAll(profileGnTemplate, "[lowServiceName]", lowServiceName);
    files.profileGn = replaceAll(files.profileGn, "[serviceId]", rootInfo.serviceId);
    files.profileXml = replaceAll(profileXmlTemplate, "[lowServiceName]", lowServiceName);
    files.profileXml = replaceAll(files.profileXml, "[serviceId]", rootInfo.serviceId);
    files.serviceCfg = replaceAll(serviceCfgTemplate, "[lowServiceName]", lowServiceName);
    files.serviceGnCfg = replaceAll(serviceCfgGnTemplate, "[lowServiceName]", lowServiceName);
    return files;
}

function replaceClassName(files, classInfo) {
    files.iServiceH = replaceAll(files.iServiceH, "[className]", classInfo.name);
    files.proxyH = replaceAll(files.proxyH, "[className]", classInfo.name);
    files.stubH = replaceAll(files.stubH, "[className]", classInfo.name);
    files.serviceH = replaceAll(files.serviceH, "[className]", classInfo.name);
    files.proxyCpp = replaceAll(files.proxyCpp, "[className]", classInfo.name);
    files.stubCpp = replaceAll(files.stubCpp, "[className]", classInfo.name);
    files.serviceCpp = replaceAll(files.serviceCpp, "[className]", classInfo.name);
    files.clientCpp = replaceAll(files.clientCpp, "[className]", classInfo.name);
}

function replaceServiceName(files, rootInfo) {
    files.iServiceH = replaceAll(files.iServiceH, "[serviceName]", rootInfo.serviceName);
    files.proxyH = replaceAll(files.proxyH, "[serviceName]", rootInfo.serviceName);
    files.stubH = replaceAll(files.stubH, "[serviceName]", rootInfo.serviceName);
    files.serviceH = replaceAll(files.serviceH, "[serviceName]", rootInfo.serviceName);
    files.proxyCpp = replaceAll(files.proxyCpp, "[serviceName]", rootInfo.serviceName);
    files.stubCpp = replaceAll(files.stubCpp, "[serviceName]", rootInfo.serviceName);
    files.serviceCpp = replaceAll(files.serviceCpp, "[serviceName]", rootInfo.serviceName);
    files.clientCpp = replaceAll(files.clientCpp, "[serviceName]", rootInfo.serviceName);
}

function replaceIncludes(files, rootInfo) {
    files.iServiceH = replaceAll(files.iServiceH, "[includes]", getIncludeStr(rootInfo.includes));
    files.proxyH = replaceAll(files.proxyH, "[iServiceHInclude]", fileContent.iServiceHFile.name);
    files.stubH = replaceAll(files.stubH, "[iServiceHInclude]", fileContent.iServiceHFile.name);
    files.serviceH = replaceAll(files.serviceH, "[stubHInclude]", fileContent.stubHFile.name);
    files.proxyCpp = replaceAll(files.proxyCpp, "[proxyHInclude]", fileContent.proxyHFile.name);
    files.stubCpp = replaceAll(files.stubCpp, "[stubHInclude]", fileContent.stubHFile.name);
    files.serviceCpp = replaceAll(files.serviceCpp, "[serviceHInclude]", fileContent.serviceHFile.name);
    files.clientCpp = replaceAll(files.clientCpp, "[proxyHInclude]", fileContent.proxyHFile.name);
    files.iServiceCpp = replaceAll(files.iServiceCpp, "[iServiceHInclude]", fileContent.iServiceHFile.name);
}

function replaceUsing(files, rootInfo) {
    files.iServiceH = replaceAll(files.iServiceH, "[using]", getUsingStr(rootInfo.using));
}

function genFileNames(lowServiceName, rootInfo) {
    fileContent.iServiceHFile.name = "i_%s_service.h".format(lowServiceName);
    fileContent.proxyHFile.name = "%s_service_proxy.h".format(lowServiceName);
    fileContent.stubHFile.name = "%s_service_stub.h".format(lowServiceName);
    fileContent.serviceHFile.name = "%s_service.h".format(lowServiceName);
    fileContent.proxyCppFile.name = "%s_service_proxy.cpp".format(lowServiceName);
    fileContent.stubCppFile.name = "%s_service_stub.cpp".format(lowServiceName);
    fileContent.serviceCppFile.name = "%s_service.cpp".format(lowServiceName);
    fileContent.clientCppFile.name = "%s_client.cpp".format(lowServiceName);
    fileContent.buildGnFile.name = "BUILD.gn";
    fileContent.bundleJsonFile.name = "bundle.json";
    fileContent.profileGnFile.name = "BUILD.gn";
    fileContent.profileXmlFile.name = rootInfo.serviceId + ".xml";
    fileContent.serviceCfgFile.name = "%s_service.cfg".format(lowServiceName);
    fileContent.serviceCfgGnFile.name = "BUILD.gn";
    fileContent.iServiceCppFile.name = "i_%s_service.cpp".format(lowServiceName);
}

function genFunctionCode(classInfo) {
    let funcList = classInfo.functions;
    let genResult = {}
    genResult.funcEnumStr = "";
    genResult.iServiceFuncH = ""; //i_service.h 方法定义
    genResult.proxyFuncH = ""; //proxy.h 方法定义
    genResult.stubInnerFuncH = ""; // stub.h 的inner方法定义
    genResult.proxyFuncCpp = ""; //proxy.cpp 方法实现
    genResult.stubInnerFuncMap = ""; // stub.cpp 的inner方法映射表
    genResult.stubInnerFuncCpp = ""; // stub.cpp 的inner方法实现
    genResult.serviceFuncCpp = ""; // service.cpp的方法实现
    genResult.clientFuncCpp = ""; // client.cpp 的inner方法定义

    let enumTab = getTab(2);
    let funcTab = getTab(1);
    for (var i = 0; i < funcList.length; ++i) {
        funcList[i].funcEnum = funcList[i].name.toUpperCase(); // remote方法的枚举值
        genResult.funcEnumStr += (i == 0) ? "" : ",\n" + enumTab;
        genResult.funcEnumStr += funcList[i].funcEnum;

        let paramStr = getFuncParamStr(funcList[i].params);
        genResult.iServiceFuncH += (i == 0) ? "" : "\n" + funcTab;
        genResult.iServiceFuncH += "virtual %s %s(%s) = 0;".format(funcList[i].retType, funcList[i].name, paramStr);

        genResult.proxyFuncH += (i == 0) ? "" : "\n" + funcTab;
        genResult.proxyFuncH += "%s %s(%s) override;".format(funcList[i].retType, funcList[i].name, paramStr);

        genResult.stubInnerFuncH += (i == 0) ? "" : "\n" + funcTab;
        genResult.stubInnerFuncH += 
            "ErrCode %sInner(MessageParcel &data, MessageParcel &reply);".format(funcList[i].name);

        genResult.proxyFuncCpp += genProxyFunc(funcList[i], classInfo.name, paramStr);

        genResult.stubInnerFuncMap += (i == 0) ? "" : "\n" + funcTab;
        genResult.stubInnerFuncMap += "innerFuncs_[%s] = &%sStub::%sInner;".format(
            funcList[i].funcEnum, classInfo.name, funcList[i].name);

        genResult.stubInnerFuncCpp += genStubInnerFunc(funcList[i], classInfo.name);
        genResult.serviceFuncCpp += genServiceFunc(funcList[i], classInfo.name, paramStr);

        genResult.clientFuncCpp += (i == 0) ? "" : "\n" + funcTab;
        genResult.clientFuncCpp += "// proxy->%s(%s);".format(funcList[i].name, paramStr);
    }
    return genResult;
}

function genMarshallFuncs(files) {
    let marshallFuncH = "";
    for (let i = 0; i < marshallFuncList.length; ++i) {
        marshallFuncH += marshallFuncList[i].marshallFuncs.marshallFuncH;
        marshallFuncH += marshallFuncList[i].marshallFuncs.unmarshallFuncH;
    }
    files.iServiceH = files.iServiceH.replace("[marshallFunctions]", marshallFuncH);
}

function genDependClasses(files) {
    let dependSrc = "";
    for (let i = 0; i < dependSrcList.length; ++i) {
        dependSrc += dependSrcList[i].srcCode + ";\n\n";
    }
    files.iServiceH = files.iServiceH.replace("[dependClasses]", dependSrc);
}

function doGenerate(rootInfo) {
    rootHFileSrc = rootInfo.rawContent;
    let lowServiceName = rootInfo.serviceName.toLowerCase();
    let upperServiceName = rootInfo.serviceName.toUpperCase();

    // 生成文件名
    genFileNames(lowServiceName, rootInfo);

    // 按模板生成.h和.cpp文件内容框架
    let files = genFilesByTemplate(upperServiceName, lowServiceName, rootInfo);

    // 替换文件includes
    replaceIncludes(files, rootInfo);

    // 替换文件using
    replaceUsing(files, rootInfo);

    // 替换namespace
    replaceServiceName(files, rootInfo);

    // 替换类名
    let classInfo = rootInfo.class[0]
    replaceClassName(files, classInfo);

    // 生成函数定义与实现
    genFunctions(classInfo, files);

    // 生成复合对象的序列化反序列化方法
    genMarshallFuncs(files);

    // 生成依赖的class定义代码
    genDependClasses(files);

    // 文件内容汇总
    fileContent.iServiceHFile.content = files.iServiceH;
    fileContent.proxyHFile.content = files.proxyH;
    fileContent.stubHFile.content = files.stubH;
    fileContent.serviceHFile.content = files.serviceH;
    fileContent.proxyCppFile.content = files.proxyCpp;
    fileContent.stubCppFile.content = files.stubCpp;
    fileContent.serviceCppFile.content = files.serviceCpp;
    fileContent.clientCppFile.content = files.clientCpp;
    fileContent.buildGnFile.content = files.buildGn;
    fileContent.bundleJsonFile.content = files.bundleJson;
    fileContent.profileGnFile.content = files.profileGn;
    fileContent.profileXmlFile.content = files.profileXml;
    fileContent.serviceCfgFile.content = files.serviceCfg;
    fileContent.serviceCfgGnFile.content = files.serviceGnCfg;
    fileContent.iServiceCppFile.content = files.iServiceCpp;
    return fileContent;
}

module.exports = {
    doGenerate
}
