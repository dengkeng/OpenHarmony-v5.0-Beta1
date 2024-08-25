/*
* Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
const { writeFile, appendWriteFile, generateRandomInteger, readFile, getJsonCfg } = require("../tools/Tool");
const path = require('path')
const re = require("../tools/re");
const fs = require("fs");
const os = require("os");
const util = require('util');
const readline = require('readline');
const { generateDirectFunction } = require('../napiGen/functionDirect')
const { generateFuncTestCase } = require('../napiGen/functionDirectTest')
const { generateBase } = require('../tools/commonTemplete')
const { InterfaceList, TypeList } = require('../tools/common')

const MIN_RANDOM = 100
const MAX_RANDOM = 999
let tsFuncName = ''

function parseFileAll(hFilePath) {
    let execSync = require("child_process").execSync
    let cmd = ""

    // call exe file (for real runtime)
    let sysInfo = os.platform()
    let execPath = path.dirname(process.execPath)
    // console.info("execPath : " + execPath)
    let exeFile = sysInfo === 'win32' ? path.join(execPath, "header_parser.exe") :
    path.join(execPath, "header_parser")
    cmd = exeFile + " " + hFilePath

    let parseResult = null
    let stdout = execSync(cmd)
    parseResult = JSON.parse(stdout.toString()).result
    return parseResult
}

function createNameSpaceInfo(parseNameSpaceInfo) {
    let nameSpaceInfo = {
        "name": "",
        "classes": [],
        "functions": []
    }
    nameSpaceInfo.name = parseNameSpaceInfo
    return nameSpaceInfo
}

function analyzeNameSpace(rootInfo, parseResult) {
    let parseNameSpaces = parseResult.namespaces
    for (var i = 0; i < parseNameSpaces.length; ++i) {
        let nameSpaceInfo = createNameSpaceInfo(parseNameSpaces[i])
        rootInfo.namespaces.push(nameSpaceInfo)
    }
}

function isStringType(cType) {
    switch (cType) {
        case 'string':
        case 'std::string':
        case 'char':
        case 'wchar_t':
        case 'char16_t':
        case 'char32_t':
            return true
        default:
            return false
    }
}

function isBoolType(cType) {
    if (cType === 'bool') {
        return true
    }
    return false
}

function isNumberType(cType) {
    switch (cType) {
        case 'short':
        case 'int':
        case 'uint32_t':
        case 'size_t':
        case 'long':
        case 'long long':
        case 'float':
        case 'double':
        case 'long double':
        case 'int16_t':
        case 'uint16_t':
        case 'int32_t':
        case 'int64_t':
        case 'uint64_t':
        case 'double_t':
        case 'float_t':
            return true
        default:
            return false
    }
}

function basicC2js(cType) {
    let jsType = ""
    if (isStringType(cType)) {
        jsType = 'string'
    } else if (isBoolType(cType)) {
        jsType = 'boolean'
    } else if (isNumberType(cType)) {
        jsType = 'number'
    } else {
        jsType = cType
    }
    return jsType
}

function getJsTypeFromC(cType, typeInfo) {
    let basicCtype = cType
    let matchs = re.match("(std::)?vector<([\x21-\x7e ]+)>", basicCtype);
    if (matchs) {
        basicCtype = re.getReg(basicCtype, matchs.regs[2]).trim()
        typeInfo.array = 1
    }

    let unsignedIdx = basicCtype.indexOf('unsigned')
    if (unsignedIdx >= 0) {
        // cut off the keywords 'unsigned'
        basicCtype = basicCtype.substring(unsignedIdx + 8, basicCtype.length).trim()
    }
    let jsType = basicCtype
    if (typeInfo.array) {
        jsType = util.format("Array<%s>", jsType)
    }
    // 去掉const
    jsType = jsType.replaceAll('const', '')
    // struct cJson * 的情况
    let matchStruct = re.match("(struct)?[A-Z_a-z0-9 *]+", basicCtype);
    if (matchStruct) {
        let index = basicCtype.indexOf('struct')
        // 去掉struct和*
        if (index >=0) {
          jsType = jsType.substring(index + 6, basicCtype.length)
        }
        jsType = jsType.replaceAll('*', '').trim()
    }
    jsType = basicC2js(jsType)
    return jsType
}

function createParam(parseParamInfo) {
    let param = {
        "name": "",
        "type": ""
    }
    param.name = parseParamInfo.name
    let rawType = getJsTypeFromC(parseParamInfo.type, parseParamInfo)
    param.type = rawType

    return param
}

function createFuncInfo(parseFuncInfo, isClassFunc) {
    let funcInfo = {
        "name": "",
        "genName": "",
        "params": [],
        "namespace": "",
        "retType": "",
        "static": ""
    }
    funcInfo.name = parseFuncInfo.name
    funcInfo.namespace = parseFuncInfo.namespace
    let tokenIndex = funcInfo.namespace.indexOf('::')
    if (tokenIndex >= 0) {
        // delete '::' in namespace, get the pure space name.
        funcInfo.namespace = funcInfo.namespace.substring(0, tokenIndex)
    }

    let parseParams = parseFuncInfo.parameters
    // console.info("parseParams:  " +   JSON.stringify(parseParams))
    for (var i = 0; i < parseParams.length; ++i) {
        let param = createParam(parseParams[i])
        funcInfo.params.push(param)
    }

    funcInfo.isClassFunc = isClassFunc

    if (parseFuncInfo.static && isClassFunc) {
        funcInfo.static = "static "
    }
    let retType = parseFuncInfo.returns === '' ? parseFuncInfo.rtnType : parseFuncInfo.returns
    funcInfo.retType = getJsTypeFromC(retType, parseFuncInfo)
    return funcInfo
}

function putFuncIntoNamespace(funcInfo, namespaces) {
    for (var i = 0; i < namespaces.length; ++i) {
        if (namespaces[i].name === funcInfo.namespace) {
            namespaces[i].functions.push(funcInfo)
            return
        }
    }
    // NapiLog.logError('The namespace [%s] of function %s is not found.'.format(funcInfo.namespace, funcInfo.name));
}

function analyzeRootTypeDef(rootInfo, parseResult) {
  let parserTypedefs = Object.keys(parseResult.typedefs)

  for (let i = 0; i < parserTypedefs.length; ++i) {
    let objTypedefKeys = parserTypedefs[i]
    let objTypedefVal = parseResult.typedefs[parserTypedefs[i]]
    rootInfo.typedefs.push({objTypedefKeys, objTypedefVal})
  }
}

function analyzeRootFunction(rootInfo, parseResult) {
    let parseFunctions = parseResult.functions
    // console.info("parseFunctions:  " +   JSON.stringify(parseFunctions))
    for (var i = 0; i < parseFunctions.length; ++i) {
        // 普通方法生成模板
        let funcInfo = createFuncInfo(parseFunctions[i], false)
        //rootInfo.functions.push(funcInfo)
        if (parseFunctions[i].namespace != '') {
            // function in namespace
            putFuncIntoNamespace(funcInfo, rootInfo.namespaces)
        } else {
            // function without namespace, put on root
            rootInfo.functions.push(funcInfo)
        }
    }
}

function createProperties(parseProperties) {
    let propertyList = []
    for (var i = 0; i < parseProperties.length; ++i) {
        let property = {}
        property.name = parseProperties[i].name
        property.type = getJsTypeFromC(parseProperties[i].type, parseProperties[i])
        propertyList.push(property)
    }
    return propertyList
}

function createClassFunctions(parseFuncs) {
    let funcList = []
    for (var i = 0; i < parseFuncs.length; ++i) {
        let funcInfo = createFuncInfo(parseFuncs[i], true)
        funcList.push(funcInfo)
    }
    return funcList
}

function createClassInfo(parseClassInfo) {
    let classInfo = {
        "name": "",
        "namespace": "",
        "properties": [],
        "functions": [],
        "extends": []
    }
    classInfo.name = parseClassInfo.name
    classInfo.namespace = parseClassInfo.namespace
    classInfo.properties = createProperties(parseClassInfo.properties.public)
    classInfo.functions = createClassFunctions(parseClassInfo.methods.public)

    return classInfo
}

function putClassIntoNamespace(classInfo, namespaces) {
    for (var i = 0; i < namespaces.length; ++i) {
        if (namespaces[i].name === classInfo.namespace) {
            namespaces[i].classes.push(classInfo)
            return
        }
    }
    // NapiLog.logError('The namespace [%s] of class %s is not found.'.format(classInfo.namespace, classInfo.name));
}

function analyzeClasses(rootInfo, parseResult) {
    let parseClasses = parseResult.classes;

    for (var className in parseClasses) {
        let classInfo = createClassInfo(parseClasses[className])
        if (classInfo.namespace != '') {
            // class in namespace
            putClassIntoNamespace(classInfo, rootInfo.namespaces)
        } else {
            // class without namespace, put on root
            rootInfo.classes.push(classInfo)
        }
    }
}

function getTab(tabLv) {
    let tab = ""
    for (var i = 0; i < tabLv; ++i) {
        tab += "    "
    }
    return tab
}

function genFunction(func, tabLv, dtsDeclare) {
    let tab = getTab(tabLv)
    let funcPrefix = func.isClassFunc ? "" : "export const "
    let funcParams = ""
    for (var i = 0; i < func.params.length; ++i) {
        funcParams += i > 0 ? ", " : ""
        funcParams += func.params[i].name + ": " + func.params[i].type
    }
    func.genName = 'KH' + generateRandomInteger(MIN_RANDOM, MAX_RANDOM) + '_' + func.name
    let dtsDeclareContent = replaceAll(dtsDeclare, '[tab_replace]', tab)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[export_replace]', funcPrefix)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[func_name_replace]', func.genName)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[func_param_replace]', funcParams)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[input_introduce_replace]', funcParams === ''? "void": funcParams)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[func_return_replace]', func.retType)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[output_introduce_replace]', func.retType)
    dtsDeclareContent = replaceAll(dtsDeclareContent, '[func_introduce_replace]', func.name)

    let classFuncTestUseTemplete = '[func_name_replace]:([func_param_replace]) => [func_return_replace]'
    let classFuncTestUse = replaceAll(classFuncTestUseTemplete, '[func_name_replace]', func.genName)
    classFuncTestUse = replaceAll(classFuncTestUse, '[func_param_replace]', funcParams)
    classFuncTestUse = replaceAll(classFuncTestUse, '[func_return_replace]', func.retType)
    let interfaceFuncResult = null;
    if (func.isClassFunc) {
      interfaceFuncResult = {
        name: func.genName,
        type: classFuncTestUse,
      }
    }
    return [dtsDeclareContent,interfaceFuncResult]
}

function isJsBasicType(type) {
  if (type === 'number' || type === 'string' || type === 'boolean') {
    return true;
  } else {
    return false;
  }
}

function genClass(classInfo, tabLv, dtsDeclare, needDeclare = false) {
    let tab = getTab(tabLv)
    let tsClass = tab + 'export ' + "interface " + classInfo.name + " {\n"
    let tab1 = getTab(tabLv + 1)
    let interfaceBody = [];
    for (var i = 0; i < classInfo.properties.length; ++i) {
        let myType = classInfo.properties[i].type
        if (!isJsBasicType(myType)) {
          myType += ' | null'
        }
        tsClass += util.format("%s%s: %s;\n", tab1, classInfo.properties[i].name, myType)
        interfaceBody.push({
          name: classInfo.properties[i].name,
          type: classInfo.properties[i].type,
      })
    }

    // 循环加入class中的方法
    let interfaceFunc = null
    for (let i = 0; i < classInfo.functions.length; ++i) {
        let result = genFunction(classInfo.functions[i], tabLv+1, dtsDeclare);
        tsClass += result[0]
        interfaceFunc = result[1]
        if (interfaceFunc !== null) {
          interfaceBody.push(interfaceFunc)
        }
    }
    tsClass += tab + "}\n"

    let interfaceData = {
      name: classInfo.name,
      body: interfaceBody
    }
    InterfaceList.push(interfaceData)
    return tsClass
}

function genNamespace(namespace, tabLv, dtsDeclare) {
    let tab = getTab(tabLv)
    let tsNamespace = tab + util.format("declare namespace %s {\n", namespace.name)
    for (var i = 0; i < namespace.functions.length; ++i) {
        tsNamespace += genFunction(namespace.functions[i], tabLv + 1 , dtsDeclare)[0]
    }
    for (var i = 0; i < namespace.classes.length; ++i) {
        tsNamespace += genClass(namespace.classes[i], tabLv + 1, dtsDeclare)
    }
    tsNamespace += tab + "}\n"
    return tsNamespace
}

function genType(typeInfo, tabLv) {
  let tab = getTab(tabLv)
  let tsTypedef = ''
  for (let i = 0; i < typeInfo.length; i++) {
    if (isNumberType(typeInfo[i].objTypedefVal)) {
      tsTypedef += tab + 'type ' + typeInfo[i].objTypedefKeys + ' = number;\n'
      let typeData = {
        name: typeInfo[i].objTypedefKeys,
        body: "number"
      }
      TypeList.push(typeData)
    } else if (isBoolType(typeInfo[i].objTypedefVal)) {
      tsTypedef += tab + 'type ' + typeInfo[i].objTypedefKeys + ' = boolean;\n'
      let typeData = {
        name: typeInfo[i].objTypedefKeys,
        body: "boolean"
      }
      TypeList.push(typeData)
    } else if (isStringType(typeInfo[i].objTypedefVal)) {
      tsTypedef += tab + 'type ' + typeInfo[i].objTypedefKeys + ' = string;\n'
      let typeData = {
        name: typeInfo[i].objTypedefKeys,
        body: "string"
      }
      TypeList.push(typeData)
    }
  }

  return tsTypedef;
}

function genTsContent(rootInfo, dtsDeclare) {
    let tsContent = rootInfo.needCallback ? "import { AsyncCallback, Callback } from './../basic';\n\n" : ""

    // gen typedefs
    tsContent += genType(rootInfo.typedefs, 0)
    for (var i = 0; i < rootInfo.classes.length; ++i) {
        tsContent += genClass(rootInfo.classes[i], 0, dtsDeclare, true)
    }

    for (var i = 0; i < rootInfo.namespaces.length; ++i) {
        tsContent += genNamespace(rootInfo.namespaces[i], 0, dtsDeclare)
    }

    for (var i = 0; i < rootInfo.functions.length; ++i) {
        tsContent += genFunction(rootInfo.functions[i], 0, dtsDeclare)[0]
    }

    return tsContent
}

function removeMarco(hFilePath, tempFilePath, macros) {
    // 创建读取文件的流
    const fileStream = fs.createReadStream(hFilePath);
    // 创建逐行读取的接口
    const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
    });
    // 存储处理后的文件内容
    let processedContent = '';
    // 逐行读取文件内容并处理 去除方法中的宏
    rl.on('line', (line) => {
        // void *(CJSON_CDECL *malloc_fn)(size_t sz);
        // CJSON_PUBLIC(const char*) cJSON_Version(void);
        // 替换使用宏的地方，保留#define宏定义
        if (line.indexOf('#define') < 0 && line.indexOf('#ifndef') < 0 && line.indexOf('#ifdef')
            && line.indexOf('#elif') && line.indexOf('#if') < 0 && line.indexOf('#else')) {
          macros.forEach(macro => {
            // 去掉使用的宏以及括号()
            
            let index = line.indexOf(macro)
            if (index >= 0) {
              let regexPattern = new RegExp(macro + '\\s*\\(');
              let isMatch = regexPattern.test(line)
              if (isMatch) {
                let removeIndexLeft = line.indexOf('(') 
                line = line.substring(0, index) + line.substring(index + macro.length, removeIndexLeft)
                  + line.substring(removeIndexLeft + 1, line.length)
                let removeIndexRight = line.indexOf(')')
                line = line.substring(0, removeIndexRight) + line.substring(removeIndexRight + 1, line.length)
              } else {
                let tmpLeft = line.substring(0, index)
                let indexLeftBracket = tmpLeft.lastIndexOf('(')
                tmpLeft = tmpLeft.substring(0, indexLeftBracket) + tmpLeft.substring(indexLeftBracket + 1, tmpLeft.length)
                let tmpRight =  line.substring(index + macro.length, line.length)
                let indexRightBracket = tmpRight.indexOf(')')
                tmpRight = tmpRight.substring(0, indexRightBracket) + tmpRight.substring(indexRightBracket + 1, tmpRight.length)
                line =  tmpLeft + tmpRight
              }
            }
          })
        }
        processedContent += line + '\n';
    });

    // 完成读取操作
    rl.on('close', () => {
        writeFile(tempFilePath, processedContent)
    });
}

// 读取头文件并提取所有的#define宏
function extractMacros(headerFilePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(headerFilePath, 'utf8', (err, data) => {
      if (err) {
        return reject(err);
      }

      // 匹配#define指令的正则表达式
      const macroRegex = /^\s*#define\s+(\w+)/gm;
      // const macroRegex = /^\s*#define\s+(\w+)(?:\s+([^\s]+))?.*$/gm;
      let match;
      const macros = [];

      // 使用正则表达式迭代所有匹配项
      while ((match = macroRegex.exec(data)) !== null) {
        // match[1]是宏的名称，match[2]是宏的定义(如果存在)
        macros.push(match[1]);
      }

      resolve(macros);
    });
  });
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function doGenerate(hFilePath, testFilePath, tsFilePath, cppFilePath) {
    // 预处理文件，读出文件中所有的宏，存在数组中
    let macros = await extractMacros(hFilePath)
    // 将使用宏的地方置空
    let random = generateRandomInteger(MIN_RANDOM, MAX_RANDOM)
    let tempFileName = '../temp_' + random + '.h'
    let tempFilePath = path.join(hFilePath, tempFileName)
    removeMarco(hFilePath, tempFilePath, macros)
    while (!fs.existsSync(tempFilePath)) {
        await sleep(20); // 延迟 20 毫秒
    }

    let parseResult = parseFileAll(tempFilePath)

    let rootInfo = {
        "namespaces": [],
        "classes": [],
        "functions": [],
        "needCallback": false,
        "typedefs": [],
    }

    analyzeNameSpace(rootInfo, parseResult)
    analyzeRootTypeDef(rootInfo, parseResult)
    analyzeRootFunction(rootInfo, parseResult)
    analyzeClasses(rootInfo, parseResult)

    // 读取Json文件
    let funcJsonPath = path.join(__dirname, '../json/function.json');
    let funcJson = getJsonCfg(funcJsonPath);

    // 读取dts文件模板
    let dtsDeclarePath = path.join(__dirname, funcJson.directFunction.dtsTemplete);
    let dtsDeclare = readFile(dtsDeclarePath)
    
    let hFileName = hFilePath.substring(hFilePath.lastIndexOf("\\") + 1, hFilePath.length);
    // 生成dts声明文件内容
    let tsContent = genTsContent(rootInfo, dtsDeclare)
    tsContent = replaceAll(tsContent, "[file_introduce_replace]", hFileName)
    appendWriteFile(tsFilePath, '\n' + tsContent)
 
    // 生成native侧文件
    generateCppFile(cppFilePath, hFilePath, funcJson, rootInfo, parseResult);

    // 生成测试用例
    generateAbilityTest(funcJson, rootInfo, parseResult, testFilePath, hFileName);

    // 删除生成的中间文件
    clearTmpFile(tempFilePath)

    console.info('Generate success')
}

function checkPathType(path) {
  try {
    const stats = fs.statSync(path);
    if (stats.isDirectory()) {
      return "directory"
    } else if (stats.isFile()) {
      return "file"
    } else {
      return "badpath"
    }
  } catch (err) {
    console.error(err);
  }
}

function checkFileIsNull(filePath) {
  if (fs.existsSync(filePath)) {
    try {
      const fileContent = fs.readFileSync(filePath, 'utf-8');
      if (fileContent.trim() === '') {
        return true;
      }
      return false;
    } catch (err) {
      console.error(`读取文件 ${filePath} 失败: ${err}`);
    }
  } 
  return false;
}

function genTestTemplete(filePath, content) {
  try {
    fs.writeFileSync(filePath, content);
  } catch (err) {
    console.error(`创建文件 ${filePath} 失败: ${err}`);
  }
}


function generateAbilityTest(funcJson, rootInfo, parseResult, testFilePath, hFileName) {
  let index = hFileName.indexOf('.h')
  let hFileNameReplace = hFileName.substring(0, index)
  // 第一次生成时应生成框架
  let abilityTestFirstGenTempletePath = funcJson.directFunction.testTempleteDetails.abilityTestFirstGenTemplete;
  let abilityTestFirstGenAbsPath = path.join(__dirname, abilityTestFirstGenTempletePath);
  let abilityTestFirstGenTemplete = readFile(abilityTestFirstGenAbsPath);
  abilityTestFirstGenTemplete = replaceAll(abilityTestFirstGenTemplete, '[abilitytest_name_replace]', hFileNameReplace)

  // 判断testFilePath是文件还是文件夹，若是文件夹则生成文件，同时第一次写入内容
  let realTestFilePath = testFilePath
  let isDir = checkPathType(realTestFilePath)
  if (isDir === 'directory') {
    realTestFilePath = path.join(testFilePath, hFileNameReplace + 'Ability.test.ets');
    genTestTemplete(realTestFilePath, abilityTestFirstGenTemplete)
  } else if (isDir === 'file') {
    if (checkFileIsNull(realTestFilePath)) {
      genTestTemplete(realTestFilePath, abilityTestFirstGenTemplete)
    } 
  }

  // 不是第一次生成则追加写入
  let abilityTestTempletePath = funcJson.directFunction.testTempleteDetails.abilityTestTemplete;
  let abilityTestTempleteAbsPath = path.join(__dirname, abilityTestTempletePath);
  let abilityTestTemplete = readFile(abilityTestTempleteAbsPath);
  
  let genTestResult = '';
  // 生成测试用例  同时生成多个测试用例
  for (let i = 0; i < rootInfo.functions.length; i++) {
    genTestResult += generateFuncTestCase(parseResult, i, rootInfo.functions[i].genName, abilityTestTemplete, hFileName);
  }
  const importContent = "import testNapi from 'libentry.so';";
  writeTestFile(realTestFilePath, importContent, genTestResult);
}

function generateCppFile(cppFilePath, hFilePath, funcJson, rootInfo, parseResult) {
  // 写入common.h 和 common.cpp
  generateBase(cppFilePath, '', hFilePath);

  let index = hFilePath.lastIndexOf("\\");
  let indexH = hFilePath.lastIndexOf(".h");
  let napiHFileName = hFilePath.substring(index + 1, indexH).toLowerCase() + 'napi.h';
  let includes_replace = util.format('#include "%s"\n', napiHFileName);
  let hFileName = hFilePath.substring(hFilePath.lastIndexOf("\\") + 1, hFilePath.length);
  
  let funcDeclare = '';
  let funcInit = '';
  let directFuncPath = funcJson.directFunction;
  // 调用napi转换的方法
  for (let i = 0; i < rootInfo.functions.length; i++) {
    let cppFileName = rootInfo.functions[i].name.toLowerCase().replace('_', '').trim();
    let thisFuncCppFilePath = path.join(cppFilePath, cppFileName + '.cpp');
    let genResult = generateDirectFunction(parseResult, i, rootInfo.functions[i].genName, directFuncPath, hFileName);
    funcDeclare += genResult[0];
    funcInit += genResult[1];
    let funcBody = includes_replace + genResult[2];
    writeFile(thisFuncCppFilePath, funcBody);
  }

  // init函数内容
  let cppInitTempletePath = funcJson.directFunction.initTempleteDetails.cppInitTemplete;
  const cppInitTempleteAbsPath = path.join(__dirname, cppInitTempletePath);
  let cppInitTemplete = readFile(cppInitTempleteAbsPath);
  cppInitTemplete = replaceAll(cppInitTemplete, '[include_replace]', includes_replace);
  cppInitTemplete = replaceAll(cppInitTemplete, '[init_replace]', funcInit);
  let napiInitFileName = hFilePath.substring(index + 1, indexH).toLowerCase() + 'init.cpp';
  let initFilePath = path.join(cppFilePath, napiInitFileName);
  writeFile(initFilePath, cppInitTemplete);

  // 生成的napi方法声明文件
  let cppDeclareTempletePath = funcJson.directFunction.cppTempleteDetails.funcHDeclare.funcHDeclareTemplete;
  const cppDeclareTempleteAbsPath = path.join(__dirname, cppDeclareTempletePath);
  let cppDeclareTempleteContent = readFile(cppDeclareTempleteAbsPath);
  let napiHFileNameReplace = hFilePath.substring(index + 1, indexH).toLowerCase() + 'napi';
  cppDeclareTempleteContent = replaceAll(cppDeclareTempleteContent, '[h_file_name_replace]', napiHFileNameReplace.toUpperCase());
  cppDeclareTempleteContent = replaceAll(cppDeclareTempleteContent, '[func_declare_replace]', funcDeclare);
  cppDeclareTempleteContent = replaceAll(cppDeclareTempleteContent, '[h_filename_replace]',
      hFilePath.substring(index + 1, indexH).toLowerCase());
  let declareFilePath = path.join(cppFilePath, napiHFileName);
  writeFile(declareFilePath, cppDeclareTempleteContent);
}

function writeTestFile(filePath, importContent, funcTestContent) {
  // 读取原本文件内容
  const fileContent = fs.readFileSync(filePath, 'utf8');
  const importPosition = fileContent.indexOf('import ');
  let newFileContent = fileContent;
  // 判断是否有该import语句,没有则添加
  if (fileContent.indexOf(importContent) < 0) {
      const newImportStatement = importContent + '\n';
      newFileContent = fileContent.slice(0, importPosition) + newImportStatement + fileContent.slice(importPosition);
  }
  // 追加写入测试用例
  let testCasePosition = newFileContent.lastIndexOf('})')
  newFileContent = newFileContent.slice(0, testCasePosition) + funcTestContent + newFileContent.slice(testCasePosition);

  writeFile(filePath, newFileContent)
}

function replaceAll(s, sfrom, sto) {
  while (s.indexOf(sfrom) >= 0) {
      s = s.replace(sfrom, sto)
  }
  return s;
}

function clearTmpFile(filePath) {
    try {
        fs.unlinkSync(filePath);
    } catch (err) {
        console.error(err);
    }
}

module.exports = {
    doGenerate
}
