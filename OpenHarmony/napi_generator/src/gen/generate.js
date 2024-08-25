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
// 生成BUILD.gn
// 生成tool_utility.h，生成tool_utility.cpp
const { replaceAll } = require("./tools/tool");
const { generateNamespace } = require("./generate/namespace");
const { writeFile } = require("./tools/FileRW");
const re = require("./tools/re");
const { generateGYP } = require("./extend/binding_gyp");
const { generateGN } = require("./extend/build_gn");
const { generateBase } = require("./extend/tool_utility");
const { NumberIncrease, jsonCfgList } = require("./tools/common");
const os = require("os");
const path = require('path')
const { NapiLog } = require("./tools/NapiLog");
var fs = require('fs');

let moduleHTemplete = `\
#ifndef IMPL_[impl_name_upper]_H
#define IMPL_[impl_name_upper]_H

#include <cstring>
#include <string>
#include <memory>
#include <vector>
#include <node_api.h>
#include <any>
#include <optional>
#include "tool_utility.h"
#include "[implName].h"

[implH_detail]
#endif // IMPL_[impl_name_upper]_H
`

let moduleCppTmplete = `\
#include <cstring>
#include <string>
#include <memory>
#include <vector>
#include <node_api.h>
#include <any>
#include <optional>
#include "tool_utility.h"
#include "[implName]_middle.h"

#define NUMBER_JS_2_C(napi_v, type, dest)        \\
    if (typeid(type) == typeid(int32_t)) {       \\
        dest = pxt->SwapJs2CInt32(napi_v);       \\
    }                                            \\
    else if (typeid(type) == typeid(uint32_t)) { \\
        dest = pxt->SwapJs2CUint32(napi_v);      \\
    }                                            \\
    else if (typeid(type) == typeid(int64_t)) {  \\
        dest = pxt->SwapJs2CInt64(napi_v);       \\
    }                                            \\
    else if (typeid(type) == typeid(double_t)) { \\
        dest = pxt->SwapJs2CDouble(napi_v);      \\
    }

#define NUMBER_JS_2_C_ENUM(napi_v, type, dest, enum_type)      \\
    if (typeid(type) == typeid(int32_t))  {    \\
        dest = static_cast<enum_type>(pxt->SwapJs2CInt32(napi_v));     \\
    }                                           \\
    else if (typeid(type) == typeid(uint32_t)) { \\
        dest = static_cast<enum_type>(pxt->SwapJs2CUint32(napi_v));    \\
    }                                          \\
    else if (typeid(type) == typeid(int64_t)) { \\
        dest = static_cast<enum_type>(pxt->SwapJs2CInt64(napi_v));     \\
    }                                           \\
    else if (typeid(type) == typeid(double_t)) { \\
        dest = static_cast<enum_type>(pxt->SwapJs2CDouble(napi_v));    \\
    }
    
#define BOOLEAN_JS_2_C(napi_v, type, dest) {    \\
    dest = pxt->SwapJs2CBool(napi_v);          \\
}

#define C_DELETE(p)  \\
    if ((p)) {         \\
        delete (p);    \\
    }

__attribute__((unused)) static napi_value number_c_to_js(XNapiTool *pxt, const std::type_info &n, DataPtr num)
{
    if (n == typeid(int32_t))
        return pxt->SwapC2JsInt32(*(int32_t *)num);
    else if (n == typeid(uint32_t))
        return pxt->SwapC2JsUint32(*(uint32_t *)num);
    else if (n == typeid(int64_t))
        return pxt->SwapC2JsInt64(*(int64_t *)num);
    else if (n == typeid(double_t))
        return pxt->SwapC2JsDouble(*(double_t *)num);
    return nullptr;
}
#define NUMBER_C_2_JS(pxt, n) \\
    number_c_to_js(pxt, typeid((n)), reinterpret_cast<DataPtr>(&(n)))
[body_replace]
static napi_value init(napi_env env, napi_value exports)
{
    std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, exports);
    [init_replace]
    return exports;
}

static napi_module g_[implName]_Module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = init,
    .nm_modname = "[modulename]",
    .nm_priv = ((void *)0),
    .reserved = {(void *)0},
};

extern "C" __attribute__((constructor)) void Register_[implName]_Module(void)
{
    napi_module_register(&g_[implName]_Module);
}
`

let implHTemplete = `\
#ifndef IMPL_[impl_name_upper]_H
#define IMPL_[impl_name_upper]_H

#include <string>
#include <memory>
#include <vector>
#include <cmath>
#include <map>
#include <any>
#include <optional>
[importTs]
[numberUsing]
[implH_detail]
#endif // IMPL_[impl_name_upper]_H
`

let implCppTemplete = `\
#include "[implName].h"
#include "[implName]_middle.h"
[include_configure_hCode]
[implCpp_detail]
`
var genFileList = []

function deleteFolder(folderPath) {
    if (fs.existsSync(folderPath)) {
        fs.rmSync(folderPath, {"recursive": true})
    }
}

function createFolder(folderPath) {
    if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath)
    }
}

function formatCode(destDir) {
    let sysInfo = os.platform()
    let clangFmtName = sysInfo === 'win32' ? "clang-format.exe" : "clang-format"
    let callPath = NapiLog.getCallPath();
    callPath = callPath.substring(callPath.indexOf("[") + 1, callPath.indexOf("src"));
    let dumyClangFmtFile = path.join(callPath, clangFmtName)
    let dumyFmtCfgFile = path.join(callPath, ".clang-format")

    if(!fs.existsSync(dumyClangFmtFile)) {
        NapiLog.logInfo("Warning: clang-format does not exist, can not format cpp file.");
        return
    }

    // 使用pkg打包的napi_generator工具，其中的clang-format程序在运行时是解压到一个名为snapshot的虚拟目录中的，如C:\snapshot\napi_generator\
    // 虚拟目录中的clang-format程序不能直接运行，必须先将它拷贝到本地硬盘的真实目录下。
    createFolder(path.resolve("./tmpLocal"))
    let localClangFmtFile = path.resolve("./tmpLocal/" + clangFmtName) // clang-format可执行程序
    let localFmtCfgFile = path.resolve("./tmpLocal/.clang-format") // clang-format格式化配置文件
    fs.copyFileSync(dumyClangFmtFile, localClangFmtFile)
    fs.copyFileSync(dumyFmtCfgFile, localFmtCfgFile)

    let execSync = require("child_process").execSync
    if (sysInfo != 'win32') {
        // linux系统下需要为临时复制的clang-format程序增加可执行权限
        execSync("chmod +x " + "\"" + localClangFmtFile + "\"")
    }

    for (let i = 0; i < genFileList.length; ++i) {
        // 文件路径前后要用引号包含，防止因为路径中存在空格而导致命令执行失败 (windows的文件夹允许有空格)
        let cmd = "\"" + localClangFmtFile + "\" -style=file -i \"" + path.resolve(path.join(destDir, genFileList[i]))
            + "\""
        try {
            execSync(cmd) // C++文件格式化
        } catch (err) {
            NapiLog.logError("Failed to format code, exception: " + err.stderr)
        }
    }
    // 格式化结束后，删除临时目录文件
    deleteFolder(path.resolve("./tmpLocal"))
}

function analyzeJsonCfg(jsonCfg) {
    let len = jsonCfg.length;
    let jsonConfig = []
    // 将json文件的数据存入jsonCfgList中
    for (let i = 0; i < len; i++) {
        let interfaceBody = null
        if (jsonCfg[i].interfaceName.indexOf("::") > 0) {
            let tt = jsonCfg[i].interfaceName.split("::")
            interfaceBody = {
              className: tt[0],
              funcName: tt[1],
            }
        } else {
            interfaceBody = {
                className: "",
                funcName: jsonCfg[i].interfaceName,
            }
        }

        jsonConfig.push({
            includeName: jsonCfg[i].includeName,
            cppName: jsonCfg[i].cppName,
            interfaceName: interfaceBody,
            serviceCode: jsonCfg[i].serviceCode.replaceAll('\\n', '\n'),
        })
    }
    jsonCfgList.push(jsonConfig)
}

function generateAll(structOfTs, destDir, moduleName, numberType, jsonCfg) {
    let ns0 = structOfTs.declareNamespace[0];
    let license = structOfTs.declareLicense[0];
    if (ns0 === undefined) {
        NapiLog.logError('generateAll error:get namespace fail!');
        return;
    }
    // 分析业务配置代码的调用代码: 分析Json文件
    if (jsonCfg) {
        analyzeJsonCfg(jsonCfg);
    }

    let result = generateNamespace(ns0.name, ns0.body)

    jsonCfgList.pop()
    
    let numberUsing = ""
    var numbertype = "uint32_t";
    if(numberType != "" && numberType != undefined){
        numbertype = numberType;
    }
    for (let i = 1; i < NumberIncrease.get(); i++) {
        numberUsing += "using NUMBER_TYPE_%d = ".format(i) + numbertype + ";\n"
    }
    generateMiddleH(ns0, result, destDir, license);
    generateMiddleCpp(result, ns0, moduleName, destDir, license);

    generateImplH(ns0, numberUsing, result, structOfTs, destDir, license);

    let implCpp = implCppTemplete.replaceAll("[implName]", ns0.name)
    let bindingCpp = ''
    let buildCpp = ''
    let includeH = ''
    if (jsonCfg) {
        let includeHCppRes = includeHCppFunc(jsonCfg, includeH, bindingCpp, buildCpp);
        bindingCpp = includeHCppRes[0];
        includeH = includeHCppRes[1];
        buildCpp = includeHCppRes[2];
    }
    implCpp = implCpp.replaceAll("[include_configure_hCode]", includeH);
    implCpp = implCpp.replaceAll("[implCpp_detail]", result.implCpp)
    writeFile(re.pathJoin(destDir, "%s.cpp".format(ns0.name)), null != license ? (license + "\n" + implCpp) : implCpp)
    genFileList.push("%s.cpp".format(ns0.name));

    let partName = moduleName.replace('.', '_')
    generateGYP(destDir, ns0.name, license, bindingCpp) // 生成ubuntu下测试的编译脚本
    generateGN(destDir, ns0.name, license, partName, buildCpp) // 生成BUILD.gn for ohos
    generateBase(destDir, license) // tool_utility.h/cpp
    genFileList.push("tool_utility.h");
    genFileList.push("tool_utility.cpp");
    formatCode(destDir);
}

function generateImplH(ns0, numberUsing, result, structOfTs, destDir, license) {
    let implH = replaceAll(implHTemplete, "[impl_name_upper]", ns0.name.toUpperCase());
    implH = implH.replaceAll("[numberUsing]", numberUsing);
    implH = replaceAll(implH, "[implH_detail]", result.implH);
    let imports = '';
    for (let i = 0; i < structOfTs.imports.length; i++) {
      imports += structOfTs.imports[i];
    }
    implH = replaceAll(implH, "[importTs]", imports);
    writeFile(re.pathJoin(destDir, "%s.h".format(ns0.name)), null != license ? (license + "\n" + implH) : implH);
    genFileList.push("%s.h".format(ns0.name));
}

function generateMiddleCpp(result, ns0, moduleName, destDir, license) {
    let middleCpp = replaceAll(moduleCppTmplete, "[body_replace]", result.middleBody);
    middleCpp = replaceAll(middleCpp, "[init_replace]", result.middleInit);
    middleCpp = replaceAll(middleCpp, "[implName]", ns0.name);
    middleCpp = replaceAll(middleCpp, "[modulename]", moduleName);
    genFileList.splice(0, genFileList.length);
    writeFile(re.pathJoin(destDir, "%s_middle.cpp".format(ns0.name)),
      null != license ? (license + "\n" + middleCpp) : middleCpp);
    genFileList.push("%s_middle.cpp".format(ns0.name));
}

// 将业务代码的头文件导入，若重复则跳过
function includeHCppFunc(jsonCfg, includeH, bindingCpp, buildCpp) {;
    for (let i = 0; i < jsonCfg.length; i++) {
        if (jsonCfg[i].includeName !== "") {
            let includeNamePath = jsonCfg[i].includeName;
            let tmp = '#include "%s"\n'.format(includeNamePath);
            if (includeH.indexOf(tmp) < 0) {
                includeH += tmp;
            }
        }
        if (jsonCfg[i].cppName !== "") {
            let cppNamePath = jsonCfg[i].cppName;
            let tmpCpp = '\n              "%s",'.format(cppNamePath);
            let tmpBuildCpp = '\n        "%s",'.format(cppNamePath);
            if (bindingCpp.indexOf(tmpCpp) < 0) {
                bindingCpp += tmpCpp;
                buildCpp += tmpBuildCpp;
            }
        }
    }
    return [bindingCpp, includeH, buildCpp];
}

function generateMiddleH(ns0, result, destDir, license) {
    let implName = ns0.name + "_middle";
    let middleH = replaceAll(moduleHTemplete, "[impl_name_upper]", implName.toUpperCase());
    middleH = replaceAll(middleH, "[implName]", ns0.name);
    middleH = replaceAll(middleH, "[implH_detail]", result.middleH);
    writeFile(re.pathJoin(destDir, "%s_middle.h".format(ns0.name)),
        null != license ? (license + "\n" + middleH) : middleH);
    genFileList.push("%s_middle.h".format(ns0.name));
}

module.exports = {
    generateAll
}
