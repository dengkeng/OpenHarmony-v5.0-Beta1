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
// const { generateNamespace } = require("./generate/namespace");
const { writeFile } = require("./tools/FileRW");
const re = require("./tools/re");

const { jsonCfgList } = require("./tools/common");
const os = require("os");
const path = require('path')
const { NapiLog } = require("./tools/NapiLog");

const DIRECT = 1;
const SYNC = 2;
const ASYNC = 4;
const PROMISE = 8;
const MAXINT = 100;
const SUBSTREND = 11;
const LENGTH = 5;
const MODTWO = 2;
var fs = require('fs');

let indexEtsTemplete = `\
import napitest from '@ohos.[import_module_name]';
import hilog from '@ohos.hilog';

@Entry
@Component
struct Index {
  @State message: string = 'Hello NAPI Sample';

  build() {
    Row() {
      Column() {
        Text(this.message)
          .fontSize(50)
          .fontWeight(FontWeight.Bold)
        [test_interface_button]
      }
      .width('100%')
    }
    .height('100%')
  }
}
`
let buttonTemplate = `
Button() {
    Text('[button_test_interface_name]')
      .fontSize(20)
      .fontWeight(FontWeight.Bold)
  }
  .type(ButtonType.Capsule)
  .margin({
    top: 10
  })
  .backgroundColor('#0D9FFB')
  .width('90%')
  .height('5%')
  .onClick(() => {
    hilog.info(0x0000, 'testTag', 'button onClick!');

    [button_test_interface_code]

    hilog.info(0x0000, 'testTag', 'button onClick end !');
  });
`

// var genFileList = []
// function deleteFolder(folderPath) {
//     if (fs.existsSync(folderPath)) {
//         fs.rmSync(folderPath, {"recursive": true})
//     }
// }

// function createFolder(folderPath) {
//     if (!fs.existsSync(folderPath)) {
//         fs.mkdirSync(folderPath)
//     }
// }

// function formatCode(destDir) {
//     let sysInfo = os.platform()
//     let clangFmtName = sysInfo === 'win32' ? "clang-format.exe" : "clang-format"
//     let callPath = NapiLog.getCallPath();
//     callPath = callPath.substring(callPath.indexOf("[") + 1, callPath.indexOf("src"));
//     let dumyClangFmtFile = path.join(callPath, clangFmtName)
//     let dumyFmtCfgFile = path.join(callPath, ".clang-format")

//     if(!fs.existsSync(dumyClangFmtFile)) {
//         NapiLog.logInfo("Warning: clang-format does not exist, can not format cpp file.");
//         return
//     }

//     // 使用pkg打包的napi_generator工具，其中的clang-format程序在运行时是解压到一个名为snapshot的虚拟目录中的，如C:\snapshot\napi_generator\
//     // 虚拟目录中的clang-format程序不能直接运行，必须先将它拷贝到本地硬盘的真实目录下。
//     createFolder(path.resolve("./tmpLocal"))
//     let localClangFmtFile = path.resolve("./tmpLocal/" + clangFmtName) // clang-format可执行程序
//     let localFmtCfgFile = path.resolve("./tmpLocal/.clang-format") // clang-format格式化配置文件
//     fs.copyFileSync(dumyClangFmtFile, localClangFmtFile)
//     fs.copyFileSync(dumyFmtCfgFile, localFmtCfgFile)

//     let execSync = require("child_process").execSync
//     if (sysInfo != 'win32') {
//         // linux系统下需要为临时复制的clang-format程序增加可执行权限
//         execSync("chmod +x " + "\"" + localClangFmtFile + "\"")
//     }

//     for (let i = 0; i < genFileList.length; ++i) {
//         // 文件路径前后要用引号包含，防止因为路径中存在空格而导致命令执行失败 (windows的文件夹允许有空格)
//         let cmd = "\"" + localClangFmtFile + "\" -style=file -i \"" + path.resolve(path.join(destDir, genFileList[i]))
//             + "\""
//         try {
//             execSync(cmd) // C++文件格式化
//         } catch (err) {
//             NapiLog.logError("Failed to format code, exception: " + err.stderr)
//         }
//     }
//     // 格式化结束后，删除临时目录文件
//     deleteFolder(path.resolve("./tmpLocal"))
// }
let FuncCfgList = []
function analyzeJsonCfg(jsonCfg) {
    let len = jsonCfg.length;

    // 将json文件的数据存入jsonCfgList中，目前只配一个
    for (let i = 0; i < len; i++) {
      FuncCfgList.push({
          classOrInterfName: jsonCfg[i].classOrInterfName,
          functionName: jsonCfg[i].functionName
        })
    }
}

// 随机生成字符串
function generateRandomString(length) {
  var result = '';
  var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  var charactersLength = characters.length;

  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }

  return result;
}

// 随机生成整数
function generateRandomInteger(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 生成index.ets文件中测试接口相关的ETS代码
function genIndexETSCode(indexEts, testFuncName, funcInfo, className = null) {
    // 判断接口函数是否是要测试的接口函数
    if (testFuncName === funcInfo.name) {
      let funcType = funcInfo.type;
      let funcValue = funcInfo.value;
      let retValue = funcInfo.ret;

      // index.ets文件中测试接口button代码生成
      if (funcType === DIRECT) {
        indexEts = callDirectFunction(testFuncName, funcValue, retValue, indexEts, className);
      } else if (funcType === SYNC) {
        NapiLog.logInfo('SYNC type of function is not supported!');
      } else if (funcType === ASYNC) {
        NapiLog.logInfo('ASYNC type of function is not supported!');
      } else if (funcType === PROMISE) {
        NapiLog.logInfo('PROMISE type of function is not supported!');
      } else {
        NapiLog.logInfo('This type of function(%s) is not supported!'.format(funcType));
      }
    } else {
      NapiLog.logInfo("test function(%s) is not current function(%s)!".format(testFuncName, funcInfo.name));
    }
  return indexEts;
}

function generateAppCode(structOfTs, destDir, moduleName, jsonCfg) {
    let ns0 = structOfTs.declareNamespace[0];
    let license = structOfTs.declareLicense[0];
    if (ns0 === undefined) {
        NapiLog.logError('generateAll error:get namespace fail!');
        return;
    }

    // 分析配置测试接口的Json文件
    if (jsonCfg) {
        analyzeJsonCfg(jsonCfg);
    }

    // 从文件分析的数据中拿到接口名，接口参数类型与个数，读取出来以此给接口参数赋初值。
    // 当前只支持一个接口的测试代码生成
    let indexEts = ''
    // 测试interface中的方法
    for (let i in ns0.body.interface) {
        let ii = ns0.body.interface[i]
        indexEts = genInterClassFunc(ii, indexEts, FuncCfgList[0].classOrInterfName, FuncCfgList[0].functionName);
    }

    // 测试class中的方法
    for (let i in ns0.body.class) {
        let ii = ns0.body.class[i]
        indexEts = genInterClassFunc(ii, indexEts, FuncCfgList[0].classOrInterfName, FuncCfgList[0].functionName);
    }

    // 测试namespace域中的方法
    for (let i in ns0.body.function) {
        let ii = ns0.body.function[i];
        indexEts = genIndexETSCode(indexEts, FuncCfgList[0].functionName, ii);
    }

    // index.ets文件生成
    indexEts = replaceAll(indexEts, "[import_module_name]", moduleName)
    writeFile(re.pathJoin(destDir, "Index.ets"), null != license ? (license + "\n" + indexEts) : indexEts)
}

// 遍历 interface/class 中的function,生成对interface/class中的接口测试的代码
function genInterClassFunc(ii, indexEts, testClass = null, testFunc) {
  let className = ii.name;
  let interfaceBody = ii.body;

  if (testClass !== className) {
    NapiLog.logInfo("test class(%s) is not current class(%s)!".format(testClass, className));
    return indexEts;
  }
  // 遍历interface中的成员方法 
  for (let j = 0; j < interfaceBody.function.length; j++) {
    // index.ets文件中测试接口button代码生成
    indexEts = genIndexETSCode(indexEts, testFunc, interfaceBody.function[j], className);
  }
  return indexEts;
}

// 调用direct方法
function callDirectFunction(funcName, funcValue, retValue, indexEts, className = null) {
  let testInterfaceName = funcName;
  let testInterfaceButton = replaceAll(buttonTemplate, "[button_test_interface_name]", testInterfaceName);
  let testInterfaceValue = ''; // 给方法参数赋初值
  let funcParamValue = ''; // 调用方法参数
  // 给接口参数赋初值
  for (let j in funcValue) {
    if (funcValue[j].type === 'string') {
      testInterfaceValue += 'let %s: string = "%s";\n'.format(funcValue[j].name, generateRandomString(LENGTH));
      funcParamValue += funcValue[j].name + ', ';
    } else if (funcValue[j].type === 'boolean') {
      let randomBool = false;
      if (generateRandomInteger(0, LENGTH) % MODTWO === 0) {
        randomBool = true;
      }
      testInterfaceValue += 'let %s: boolean = %s;\n'.format(funcValue[j].name, randomBool);
      funcParamValue += funcValue[j].name + ', ';
    } else if (funcValue[j].type.substring(0, SUBSTREND) === 'NUMBER_TYPE') {
      testInterfaceValue += 'let %s: number = %s;\n'.format(funcValue[j].name, generateRandomInteger(0, MAXINT));
      funcParamValue += funcValue[j].name + ', ';
    } else {
      console.error('The current parameter type is not supported.');
    }
  }
  funcParamValue = funcParamValue.substring(0, funcParamValue.lastIndexOf(','));
  // 返回值的处理
  let useFunction = '';
  if (retValue === 'void') {
    useFunction = '%s.%s(%s);'.format(className === null? 'napitest': className + 'Obj', funcName, funcParamValue);
  } else if (retValue === 'string') {
    useFunction = 'let strRet: string = %s.%s(%s);\n'.format(className === null? 'napitest': className + 'Obj', funcName, funcParamValue);
    useFunction += 'hilog.info(0x0000, "testTag", "%s.%s ret: " + strRet);'.format(className === null? 'napitest': className + 'Obj', funcName);
  } else if (retValue === 'boolean') {
    useFunction = 'let boolRet: boolean = %s.%s(%s);\n'.format(className === null? 'napitest': className + 'Obj', funcName, funcParamValue);
    useFunction += 'hilog.info(0x0000, "testTag", "%s.%s ret: " + boolRet);'.format(className === null? 'napitest': className + 'Obj', funcName);
  } else if (retValue.substring(0, SUBSTREND) === 'NUMBER_TYPE') {
    useFunction = 'let numRet: number = %s.%s(%s);\n'.format(className === null? 'napitest': className + 'Obj', funcName, funcParamValue);
    useFunction += 'hilog.info(0x0000, "testTag", "%s.%s ret: " + numRet);'.format(className === null? 'napitest': className + 'Obj', funcName);
  } else {
    console.error('The current return type is not supported.');
  }
  let useInterface = ''
  if (className !== null) {
    useInterface = 'let %sObj: napitest.%s = new napitest.%s();\n'.format(className, className, className)
  }
  let buttonTestInterface = `%s%s%s`.format(useInterface, testInterfaceValue, useFunction);
  testInterfaceButton = replaceAll(testInterfaceButton, "[button_test_interface_code]", buttonTestInterface);
  indexEts = replaceAll(indexEtsTemplete, "[test_interface_button]", testInterfaceButton);
  return indexEts;
}

module.exports = {
    generateAppCode
}
