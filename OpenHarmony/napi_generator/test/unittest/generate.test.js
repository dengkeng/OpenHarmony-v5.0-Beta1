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
let genDir = "../../src/gen/"

const { analyzeFile } = require(genDir + "analyze");
var assert = require("assert");
const re = require(genDir + "/tools/re");
const { info, Console } = require("console");
const { JsxEmit } = require("typescript");
const { readFile } = require(genDir + "tools/FileRW");
const { generateEnum } = require(genDir + "generate/enum");
const { jsToC, jsToCEnum, paramGenerate, paramGenerateArray, anyTempleteFunc,
  objectTempleteFunc, unionTempleteFunc } = require(genDir + "generate/param_generate");
const { paramGenerateMap, mapTempleteFunc, paramGenerateCommon, paramGenerateUnion, paramGenerateCallBack,
  paramGenerateAny, paramGenerateObject } = require(genDir + "generate/param_generate");
const { cToJs, cToJsForInterface, cToJsForType, returnGenerate,
  objectTempleteFuncReturn } = require(genDir + "generate/return_generate");
const { generateInterface, generateVariable, anyTypeString,
  getHDefineOfVariable } = require(genDir + "generate/interface");
const { mapTypeString, connectResult } = require(genDir + "generate/interface");
const { generateNamespace, formatMiddleInit } = require(genDir + "generate/namespace");
const { generateEnumResult, generateFunction } = require(genDir + "generate/namespace");
const { generateFunctionAsync } = require(genDir + "generate/function_async");
const { generateFunctionDirect } = require(genDir + "generate/function_direct");
const { generateFunctionSync } = require(genDir + "generate/function_sync");
const { generateFunctionOnOff } = require(genDir + "generate/function_onoff");
const { generateThreadsafeFunc } = require(genDir + "generate/function_threadsafe");

var correctResult

function before() {
    let data = readFile("test/unittest/result.json")

    if (data) {
        correctResult = JSON.parse(data)
    }

    result = analyzeFile("test/unittest/@ohos.input_sample.d.ts")
}

describe('Generate', function () {
    before(function () {
        before()
    });

    partOfEnum();

    it('test gen/generate/function_async generateFunctionAsync', function () {
        let retJson = funcAsyncAssert();
        let struct = retJson.substring(retJson.indexOf("{"),retJson.indexOf("}")+1)
        assert.strictEqual(struct,"{\\n    void *data_ptr = data;\\n    if_async_value_struct *vio = static_cast<if_async_value_struct *>(data_ptr);\\n    TestClass1 *pInstance = (TestClass1 *)pxt->GetAsyncInstance();\\n    pInstance->if_async(vio->in0, vio->outErrCode, vio->out);\\n}")

        let execute = retJson.substring(retJson.indexOf("if_async_execute"),retJson.indexOf("*data")+6)
        assert.strictEqual(execute,"if_async_execute(XNapiTool *pxt, DataPtr data)\\n{\\n    void *data_")
        let complete = retJson.substring(retJson.indexOf("if_async_complete"),retJson.lastIndexOf("*data")+6)
        assert.strictEqual(complete,"if_async_complete(XNapiTool *pxt, DataPtr data)\\n{\\n    void *data_")
        let middle = retJson.substring(retJson.indexOf("if_async_middle"),retJson.indexOf("info)")+5)
        assert.strictEqual(middle,"if_async_middle(napi_env env, napi_callback_info info)")
    });

    it('test gen/generate/function_direct generateFunctionDirect', function () {
        let retJson = funcDirectAssert();
        let struct = retJson.substring(retJson.indexOf("{"), retJson.indexOf("}") + 1)
        assert.strictEqual(struct, "{\\n    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\\n    if (pxt->IsFailed()) {\\n        napi_value err = pxt->GetError();\\n        delete pxt;\\n        return err;\\n    }")
        let middle = retJson.substring(retJson.indexOf("if_direct_middle"), retJson.indexOf("info)") + 5)
        assert.strictEqual(middle, "if_direct_middle(napi_env env, napi_callback_info info)")
    }); 

    it('test gen/generate/function_direct generateFunctionStaticDirect', function () {
        let retJson = funcStaticDirectAssert();
        let struct = retJson.substring(retJson.indexOf("{"), retJson.indexOf("}") + 1);
        assert.strictEqual(struct, "{\\n    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\\n    if (pxt->IsFailed()) {\\n        napi_value err = pxt->GetError();\\n        delete pxt;\\n        return err;\\n    }");
        let middle = retJson.substring(retJson.indexOf("if_direct_middle"), retJson.indexOf("info)") + 5);
        assert.strictEqual(middle, "if_direct_middle(napi_env env, napi_callback_info info)");
        let implH = retJson.search("static bool if_direct");
        assert.strictEqual(implH > 0, true);
    });

    it('test gen/generate/function_sync generateFunctionSync', function () {
        let retJson = funcSyncAssert();
        let struct = retJson.substring(retJson.indexOf("{"), retJson.indexOf("}") + 1)
        assert.strictEqual(struct, "{\\n    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\\n    if (pxt->IsFailed()) {\\n        napi_value err = pxt->GetError();\\n        delete pxt;\\n        return err;\\n    }")
        let middle = retJson.substring(retJson.indexOf("if_callback_middle"), retJson.indexOf("info)") + 5)
        assert.strictEqual(middle, "if_callback_middle(napi_env env, napi_callback_info info)")
    });

    partOfFuncOnOff();

    partOfFuncThread();
    
    partOfInterface(correctResult);

    partOfTest();

    partOfNamespace(correctResult)

    partofParamGenerate(correctResult)

});

function funcAsyncAssert() {
    let valueFi = { name: 'v1', type: 'string' };
    let value1Se = { name: 'cb', type: 'AsyncCallback<string>' };
    let funParam = { name: 'if_async', type: 4, value: [valueFi, value1Se], ret: 'string' }
    let data = {
        class: [],
        const: [],
        enum: [],
        exports: [],
        function: [{ name: 'if_async', type: 4, value: [valueFi, value1Se], ret: 'string' }],
        interface: [],
        namespace: [],
        type: [],
    }
    let ret = generateFunctionAsync(funParam, data, 'TestClass1');
    let retJson = JSON.stringify(ret);
    return retJson
}

function funcDirectAssert() {
    let valueFi = [{ name: 'v1', type: 'string', optional: false }, {name: 'v2', type: 'boolean', optional: true}];
    let funParam = { name: 'if_direct', type: 1, value: valueFi, ret: 'string', isStatic: false };
    let data = {
        class: [],
        const: [],
        enum: [],
        exports: [],
        function: [{ name: 'if_direct', type: 1, value: [valueFi], ret: 'string', isStatic: false }],
        interface: [],
        namespace: [],
        type: [],
    }
    let ret = generateFunctionDirect(funParam, data, 'TestClass1');
    let retJson = JSON.stringify(ret);
    return retJson
}

function funcStaticDirectAssert() {
  let valueFi = { name: 'v1', type: 'string', optional: false };
  let funParam = { name: 'if_direct', type: 1, value: [valueFi], ret: 'string', isStatic: true };
  let data = {
      class: [],
      const: [],
      enum: [],
      exports: [],
      function: [{ name: 'if_direct', type: 1, value: [valueFi], ret: 'string', isStatic: true }],
      interface: [],
      namespace: [],
      type: [],
  }
  let ret = generateFunctionDirect(funParam, data, 'TestClass1');
  let retJson = JSON.stringify(ret);
  return retJson
}

function funcSyncAssert() {
    let valueFi = { name: 'v1', type: 'string' };
    let value1Se = { name: 'cb', type: 'Callback<string>' };
    let funParam = { name: 'if_callback', type: 2, value: [valueFi, value1Se], ret: 'string' };
    let data = {
        class: [],
        const: [],
        enum: [],
        exports: [],
        function: [{ name: 'if_callback', type: 2, value: [valueFi, value1Se], ret: 'string' }],
        interface: [],
        namespace: [],
        type: [],
    }
    let ret = generateFunctionSync(funParam, data, 'TestClass1');
    let retJson = JSON.stringify(ret);
    return retJson
}

function funcOnOffAssert(funcName) {
  let valueFi = { name: 'v1', type: 'string', optional: false };
  let value1Se = { name: 'cb', type: 'Callback<string>', optional: false };
  let funParam = { name: funcName, type: 2, value: [valueFi, value1Se], ret: 'void' };
  let data = {
      class: [],
      const: [],
      enum: [],
      exports: [],
      function: [{ name: funcName, type: 2, value: [valueFi, value1Se], ret: 'string' }],
      interface: [],
      namespace: [],
      type: [],
  }
  let ret = generateFunctionOnOff(funParam, data, 'TestClass1');
  let retJson = JSON.stringify(ret);
  return retJson;
}

function funcRegistUnregistAssert(funcName, type, retVal) {
  let funParam = {
    isParentMember: false,
    isStatic: false,
    name: funcName,
    ret: retVal,
    value: [{name: 'cb', optional: false, realType: type, type: type}]
  }
  let data = {
    allProperties: {
      functions: [{isParentMember: false, isStatic: false, name: funcName, ret: retVal, type: 2,
        value: [{name: 'cb', optional: false, realType: type, type: type}]}],
      values: []
    },
    childList: [],
    function: [{isParentMember: false, isStatic: false, name: funcName, ret: retVal, type: 2,
      value: [{name: 'cb', optional: false, realType: type, type: type}]}],
    parentList: [],
    parentNameList: [],
    value: []
  }
  let ret = generateFunctionOnOff(funParam, data, 'TestClass1');

  return ret
}

function partOfEnum() {
    it('test gen/generate/enum generateEnum', function () {
        let data = {
            element: [{ name: "STATUS0", value: "0", type: "NUMBER_TYPE_1" }],
            function: [],
            enumValueType: 0
        }
        let ret = generateEnum('GrantStatus', data);
        let retJson = JSON.stringify(ret);
        let qiepianEnd = retJson.search('\"implCpp\":\"\"') - 1;
        let actualResult = retJson.substring(1, qiepianEnd);
        let expectresult = '"implH":"\\nenum class GrantStatus {\\n    STATUS0 = 0,\\n};\\n"'; 
        assert.strictEqual(actualResult, expectresult);

        let data2 = {
            element: [{ name: "ACTION_HOME", value: "ohos.want.action.home", type: "string" }],
            function: [],
            enumValueType: 1
        }
        let ret2 = generateEnum('Action', data2);
        let retJson2 = JSON.stringify(ret2);
        let qiepianEnd2 = retJson2.search('\"implCpp\":') - 1;
        let actualResult2 = retJson2.substring(1, qiepianEnd2);
        let expectresult2 =
          '"implH":"\\nclass Action {\\npublic:\\n    static const std::string ACTION_HOME;\\n};\\n"'; 
        assert.strictEqual(actualResult2, expectresult2);
    });
}

function funcThreadsafeAssert(funcName) {
  let func = {
    isParentMember: false,
    isStatic: false,
    name: funcName,
    ret: 'void',
    type: 1,
    value: [{name: 'name', optional: false, realType: 'string', type: 'string'},
      {name: 'callback', optional: false, realType: '(value', type: '(value'}]
  }

  let data = {
    allProperties: {
      functions: [{
        isParentMember: false,
        isStatic: false,
        name: funcName,
        ret: 'void',
        type: 1,
        value: [{name: 'name', optional: false, realType: 'string', type: 'string'},
          {name: 'callback', optionalz: false, realType: 'string', type: 'string'}]
      }],
      values: [],
    },
    childList: [],
    function: [{
      isParentMember: false,
      isStatic: false,
      name: funcName,
      ret: 'void',
      type: 1,
      value: [{name: 'name', optional: false, realType: 'string', type: 'string'},
        {name: 'callback', optional: false, realType: 'string', type: 'string'}]
    }],
    parentList: [],
    parentNameList: [],
    value: []
  }
  let ret = generateThreadsafeFunc(func, data, 'TestClass1');
  return ret;
}

function partOfFuncThread() {
  it('test gen/generate/function_threadsafe generateThreadsafeFunc', function () {
    let ret = funcThreadsafeAssert('createThreadSafeFuncClass1');
    let middleCppRet = JSON.stringify(ret[0]);
    let implHRet = JSON.stringify(ret[1]);
    let implCppRet = JSON.stringify(ret[2]);
    let middleHRet = JSON.stringify(ret[3]);
    assert.strictEqual(implHRet, '""');
    assert.strictEqual(implCppRet, '""');
    assert.strictEqual(middleHRet, '"\\nstruct createThreadSafeFuncClass1_value_struct {\\n    std::string eventName;\\n};\\n\\nstatic  napi_value createThreadSafeFuncClass1_middle(napi_env env, napi_callback_info info);\\n"')
    let index = middleCppRet.indexOf('status = napi_create_threadsafe_function(env, pxt->GetArgv(argc - 1), nullptr,')
    assert.strictEqual(index > 0, true);
    let indexRegisterFunc = middleCppRet.indexOf('pxt->RegistThreadsafeFunc(vio->eventName, threadsafeFunc);')
    assert.strictEqual(indexRegisterFunc > 0, true);
  });
}

function partOfFuncOnOff() {
    // on/off test
    it('test gen/generate/function_onoff generateFunctionOnOff on/off', function () {
        let retJson = funcOnOffAssert('on');
        let struct = retJson.substring(retJson.indexOf("{"), retJson.indexOf("}") + 1)
        assert.strictEqual(struct, "{\\n    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\\n    if (pxt->IsFailed()) {\\n        napi_value err = pxt->GetError();\\n        delete pxt;\\n        return err;\\n    }")
        let middle = retJson.substring(retJson.indexOf("on_middle"), retJson.indexOf("info)") + 5)
        assert.strictEqual(middle, "on_middle(napi_env env, napi_callback_info info)")

        let retJson2 = funcOnOffAssert('off');
        let struct2 = retJson2.substring(retJson2.indexOf("{"), retJson2.indexOf("}") + 1)
        assert.strictEqual(struct2, "{\\n    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\\n    if (pxt->IsFailed()) {\\n        napi_value err = pxt->GetError();\\n        delete pxt;\\n        return err;\\n    }")
        let middle2 = retJson2.substring(retJson2.indexOf("off_middle"), retJson2.indexOf("info)") + 5)
        assert.strictEqual(middle2, "off_middle(napi_env env, napi_callback_info info)")
    });

    // registerXXX/UnregisterXXX test
    partOfFuncRegistUnregist();
}
function partOfFuncRegistUnregist() {
    // registerXXX test Function
    it('test gen/generate/function_onoff generateFunctionOnOff registerXXX', function () {
        let ret = funcRegistUnregistAssert('registerTestfunc11', 'Function', 'void');
        let middleCppRet = ret[0];
        let implHRet = ret[1];
        let implCppRet = ret[2];
        let middleHRet = ret[3];
        let indexImplH = implHRet.indexOf('void Testfunc11Callback();');
        assert.strictEqual(indexImplH >= 0, true);
        let indexImplCpp = implCppRet.indexOf('ptr->Testfunc11CallbackMiddle(eventName);');
        assert.strictEqual(indexImplCpp > 0, true);
        let indexMiddleH = middleHRet.indexOf('struct registerTestfunc11_value_struct {');
        assert.strictEqual(indexMiddleH >= 0, true);
        let indexMiddleCpp = middleCppRet.indexOf('pxt->RegistOnOffFunc(vio->eventName, pxt->GetArgv(XNapiTool::ZERO));');
        assert.strictEqual(indexMiddleCpp > 0, true);
    });

    // unRegisterXXX test Function
    it('test gen/generate/function_onoff generateFunctionOnOff unRegisterXXX', function () {
        let ret = funcRegistUnregistAssert('unRegisterTestfunc11', 'Function', 'void');
        let middleCppRet = ret[0];
        let implHRet = ret[1];
        let implCppRet = ret[2];
        let middleHRet = ret[3];
        assert.strictEqual(JSON.stringify(implHRet), '""');
        assert.strictEqual(JSON.stringify(implCppRet), '""');
        let indexMiddleH = middleHRet.indexOf('struct unRegisterTestfunc11_value_struct {');
        assert.strictEqual(indexMiddleH >= 0, true);
        let indexMiddleCpp = middleCppRet.indexOf('pxt->UnregistOnOffFunc(vio->eventName);');
        assert.strictEqual(indexMiddleCpp > 0, true);
    });

    // registerXXX test Callback<boolean>
    it('test gen/generate/function_onoff generateFunctionOnOff registerXXX', function () {
        let ret = funcRegistUnregistAssert('registerTestfunc13', 'Callback<boolean>', 'void');
        let middleCppRet = ret[0];
        let implHRet = ret[1];
        let implCppRet = ret[2];
        let middleHRet = ret[3];
        let indexImplH = implHRet.indexOf('void Testfunc13Callback(bool &valueIn);');
        assert.strictEqual(indexImplH >= 0, true);
        let indexImplCpp = implCppRet.indexOf('ptr->Testfunc13CallbackMiddle(eventName, valueIn);');
        assert.strictEqual(indexImplCpp > 0, true);
        let indexMiddleH = middleHRet.indexOf('struct registerTestfunc13_value_struct {');
        assert.strictEqual(indexMiddleH >= 0, true);
        let indexMiddleCpp = middleCppRet.indexOf('pxt->RegistOnOffFunc(vio->eventName, pxt->GetArgv(XNapiTool::ZERO));');
        assert.strictEqual(indexMiddleCpp > 0, true);
    });

    // unRegisterXXX test Callback<boolean>
    it('test gen/generate/function_onoff generateFunctionOnOff unRegisterXXX', function () {
        let ret = funcRegistUnregistAssert('unRegisterTestfunc13', 'Callback<boolean>', 'void');
        let middleCppRet = ret[0];
        let implHRet = ret[1];
        let implCppRet = ret[2];
        let middleHRet = ret[3];
        assert.strictEqual(JSON.stringify(implHRet), '""');
        assert.strictEqual(JSON.stringify(implCppRet), '""');
        let indexMiddleH = middleHRet.indexOf('struct unRegisterTestfunc13_value_struct {');
        assert.strictEqual(indexMiddleH >= 0, true);
        let indexMiddleCpp = middleCppRet.indexOf('pxt->UnregistOnOffFunc(vio->eventName);');
        assert.strictEqual(indexMiddleCpp > 0, true);
    });
}

function partOfInterface() {
    partOfInterfaceOne();

    it('test gen/generate/interface anyTypeString', function () {
      let ret = anyTypeString("any", "v");
      let result = "\n    std::string v_type;\n    std::any v;";
      assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));
    });

    partOfInterfaceFour();

    it('test gen/generate/interface generateInterface', function () {
        let data = {
            function: [],
            value: [{ name: "disable", type: "boolean" }, { name: "map1", type: "Map<string,string>" }]
        }
        let ret = generateInterface('ConfigOption', data, 'napitest::');
        let retJson = JSON.stringify(ret).substring(1, JSON.stringify(ret).length);
        let configOption = retJson.substring(retJson.indexOf("{"), retJson.indexOf("}") + 1);
        let configResult = "{\\npublic:\\n    bool disable;\\n    std::map<std::string, std::string> map1;\\n\\n}";
        assert.strictEqual(configOption, configResult);
        assert.strictEqual(retJson.search("ConfigOption_middle") > 0, true)
        assert.strictEqual(retJson.search("middleInit") > 0, true)
    });

    partOfInterfaceTwo();
    partOfInterfaceThree();
}

function partOfInterfaceFour() {
    it('test gen/generate/interface mapTypeString', function () {
        let ret = mapTypeString("Map<string,string>", "map1");
        let result = "\n    std::map<std::string, std::string> map1;";
        assert.strictEqual(JSON.stringify(ret), JSON.stringify(result));

        let ret2 = mapTypeString("Map<string,NUMBER_TYPE_1>", "map1");
        let result2 = "\n    std::map<std::string, NUMBER_TYPE_1> map1;";
        assert.strictEqual(JSON.stringify(ret2), JSON.stringify(result2));

        let ret3 = mapTypeString("Map<string,boolean>", "map1");
        let result3 = "\n    std::map<std::string, bool> map1;";
        assert.strictEqual(JSON.stringify(ret3), JSON.stringify(result3));

        let ret4 = mapTypeString("{[key:string]:string}", "map1");
        let result4 = "\n    std::map<std::string, std::string> map1;";
        assert.strictEqual(JSON.stringify(ret4), JSON.stringify(result4));

        let ret5 = mapTypeString("{[key:string]:NUMBER_TYPE_1}", "map1");
        let result5 = "\n    std::map<std::string, NUMBER_TYPE_1> map1;";
        assert.strictEqual(JSON.stringify(ret5), JSON.stringify(result5));

        let ret6 = mapTypeString("{[key:string]:boolean}", "map1");
        let result6 = "\n    std::map<std::string, bool> map1;";
        assert.strictEqual(JSON.stringify(ret6), JSON.stringify(result6));

        let ret7 = mapTypeString("Map<string,Map<string,string>>", "map1");
        let result7 = "\n    std::map<std::string, std::map<std::string, std::string>> map1;";
        assert.strictEqual(JSON.stringify(ret7), JSON.stringify(result7));

        let ret8 = mapTypeString("{[key:string]:{[key:string]:string}}", "map1");
        let result8 = "\n    std::map<std::string, std::map<std::string, std::string>> map1;";
        assert.strictEqual(JSON.stringify(ret8), JSON.stringify(result8));

        let ret9 = mapTypeString("Map<string,string[]>", "map1");
        let result9 = "\n    std::map<std::string, std::vector<std::string>> map1;";
        assert.strictEqual(JSON.stringify(ret9), JSON.stringify(result9));

        let ret10 = mapTypeString("Map<string,Array<string>>", "map1");
        let result10 = "\n    std::map<std::string, std::vector<std::string>> map1;";
        assert.strictEqual(JSON.stringify(ret10), JSON.stringify(result10));
    });
}

function partOfInterfaceOne() {
    it('test gen/generate/interface generateVariable', function () {
        // test basic type
        let retBool = generateVariableAsset("boolean");
        let ex = JSON.stringify(variableMiddleBoolValue())
        assert.strictEqual(retBool, ex);
 
        // test Array
        let retArrStr = generateVariableAsset("Array<string>");
        retArrStr = re.replaceAll(retArrStr, "tt[0-9]+", "tt");
        retArrStr = re.replaceAll(retArrStr, "tnv[0-9]+", "tnv");
        retArrStr = re.replaceAll(retArrStr, "outLen[0-9]+", "outLen");
        retArrStr = re.replaceAll(retArrStr, "len[0-9]+", "len");
        retArrStr = re.replaceAll(retArrStr, "i[0-9]+", "i");
        let resultArrStr = JSON.stringify(variableMiddleArrStrValue());
        assert.strictEqual(retArrStr, resultArrStr);

        let retArrStr2 = generateVariableAsset("string[]");
        retArrStr2 = re.replaceAll(retArrStr2, "tt[0-9]+", "tt");
        retArrStr2 = re.replaceAll(retArrStr2, "tnv[0-9]+", "tnv");
        retArrStr2 = re.replaceAll(retArrStr2, "outLen[0-9]+", "outLen");
        retArrStr2 = re.replaceAll(retArrStr2, "len[0-9]+", "len");
        retArrStr2 = re.replaceAll(retArrStr2, "i[0-9]+", "i");
        assert.strictEqual(retArrStr2, resultArrStr);

        // test Map
        let retMapStr = generateVariableAsset("Map<string, string>");
        let resultMapStr = JSON.stringify(variableMiddleMapStrValue());
        retMapStr = re.replaceAll(retMapStr, "tt[0-9]+", "tt");
        retMapStr = re.replaceAll(retMapStr, "tnv[0-9]+", "tnv");
        retMapStr = re.replaceAll(retMapStr, "len[0-9]+", "len");
        retMapStr = re.replaceAll(retMapStr, "i[0-9]+", "i");
        assert.strictEqual(retMapStr, resultMapStr);

        let retMapStr2 = generateVariableAsset("{[key:string]: string}");
        let resultMapStr2 = JSON.stringify(variableMiddleMapStrValue());
        retMapStr2 = re.replaceAll(retMapStr2, "tt[0-9]+", "tt");
        retMapStr2 = re.replaceAll(retMapStr2, "tnv[0-9]+", "tnv");
        retMapStr2 = re.replaceAll(retMapStr2, "len[0-9]+", "len");
        retMapStr2 = re.replaceAll(retMapStr2, "i[0-9]+", "i");
        assert.strictEqual(retMapStr2, resultMapStr2);
    });
}

function generateVariableAsset(valType) {
    let variable = {
        hDefine: "",
        middleValue: "",
    };
    let value = {
        name: "disable",
        type: valType,
    }
    generateVariable(value, variable, 'ConfigOption');
    let ret = JSON.stringify(variable.middleValue);
    return ret;
}

function partOfInterfaceThree() {
    it('test gen/generate/interface getHDefineOfVariable', function () {
        let retStr = getHDefineOfVariableAsset("string");
        let resultStr = "\"\\n    std::string vName;\"";
        assert.strictEqual(retStr, resultStr);

        let retBool = getHDefineOfVariableAsset("boolean");
        let resultBool = "\"\\n    bool vName;\"";
        assert.strictEqual(retBool, resultBool);

        let retNum = getHDefineOfVariableAsset("NUMBER_TYPE_1");
        let resultNum = "\"\\n    NUMBER_TYPE_1 vName;\"";
        assert.strictEqual(retNum, resultNum);

        let retArrStr1 = getHDefineOfVariableAsset("Array<string>");
        let resultArrStr1 = "\"\\n    std::vector<std::string> vName;\"";
        assert.strictEqual(retArrStr1, resultArrStr1);

        let retArrAny1 = getHDefineOfVariableAsset("Array<any>");
        let resultArrAny1 = "\"\\n    std::string vName_type; \\n    std::any vName;\"";
        assert.strictEqual(retArrAny1, resultArrAny1);

        let retArrStr2 = getHDefineOfVariableAsset("string[]");
        let resultArrStr2 = "\"\\n    std::vector<std::string> vName;\"";
        assert.strictEqual(retArrStr2, resultArrStr2);

        let retArrAny2 = getHDefineOfVariableAsset("any[]");
        let resultArrAny2 = "\"\\n    std::string vName_type;\\n    std::any vName;\"";
        assert.strictEqual(retArrAny2, resultArrAny2);

        let retObject = getHDefineOfVariableAsset("Object");
        let resultObject= "\"\\n    std::map<std::string, std::any> vName;\"";
        assert.strictEqual(retObject, resultObject);
    });
}

function getHDefineOfVariableAsset(valType) {
    let variable = {
        hDefine: "",
        middleValue: ""
    }
    getHDefineOfVariable("vName", valType, variable);
    let ret = variable.hDefine;
    return JSON.stringify(ret);
}

function partOfInterfaceTwo() {
    it('test gen/generate/interface connectResult', function () {
        let data = {
            function: [],
            value: [{ name: "disable", type: "boolean" }, { name: "map1", type: "Map<string,string>" }]
        }
        let ret = connectResult(data, 'napitest::', 'ConfigOption');
        let retJson = JSON.stringify(ret);
        let getDisable = retJson.search("static napi_value getvalue_disable");
        assert.strictEqual(getDisable > 0, true)
        let setDisable = retJson.search("static napi_value setvalue_disable");
        assert.strictEqual(setDisable > 0, true)
        let getMap1 = retJson.search("static napi_value getvalue_map1");
        assert.strictEqual(getMap1 > 0, true)
        let setMap1 = retJson.search("static napi_value setvalue_map1");
        assert.strictEqual(setMap1 > 0, true)
    });
}

function partOfTest() {
    it('test gen/generate/param_generate jsToC', function () {
        assert.strictEqual(jsToC("a", "b", "string"), "pxt->SwapJs2CUtf8(b, a);");

        assert.strictEqual(jsToC("a", "b", "NUMBER_TYPE_1"), "NUMBER_JS_2_C(b, NUMBER_TYPE_1, a);");

        assert.strictEqual(jsToC("a", "b", "boolean"), "BOOLEAN_JS_2_C(b, bool, a);\n");

        let retJsToC = JSON.stringify(jsToC("a", "b", "Array<string>"));
        retJsToC = re.replaceAll(retJsToC, "len[0-9]*", "len");
        retJsToC = re.replaceAll(retJsToC, "i[0-9]*", "i");
        retJsToC = re.replaceAll(retJsToC, "tt[0-9]*", "tt");
        assert.strictEqual(retJsToC, JSON.stringify(jsToCParam()));

        let retJsToC1 = JSON.stringify(jsToC("a", "b", "string[]"));
        retJsToC1 = re.replaceAll(retJsToC1, "len[0-9]*", "len");
        retJsToC1 = re.replaceAll(retJsToC1, "i[0-9]*", "i");
        retJsToC1 = re.replaceAll(retJsToC1, "tt[0-9]*", "tt");
        assert.strictEqual(retJsToC1, JSON.stringify(jsToCParamArray()));

        let retJsToC2 = JSON.stringify(jsToC("a", "b", "{[key:string]:boolean}"));
        retJsToC2 = re.replaceAll(retJsToC2, "len[0-9]*", "len");
        retJsToC2 = re.replaceAll(retJsToC2, "i[0-9]*", "i");
        retQiepian = retJsToC2.substring(retJsToC2.indexOf("tt"), retJsToC2.indexOf("tt") + 3)
        retJsToC2 = re.replaceAll(retJsToC2, retQiepian, "tt");
        retJsToC2 = re.replaceAll(retJsToC2, "tt[0-9]+", "tt1");
        assert.strictEqual(retJsToC2, JSON.stringify(jsToCParamMap()));

        let retJsToC3 = JSON.stringify(jsToC("a", "b", "Map<string,number>"));
        retJsToC3 = re.replaceAll(retJsToC3, "len[0-9]*", "len");
        retJsToC3 = re.replaceAll(retJsToC3, "i[0-9]*", "i");
        retQiepian = retJsToC3.substring(retJsToC3.indexOf("tt"), retJsToC3.indexOf("tt") + 3)
        retJsToC3 = re.replaceAll(retJsToC3, retQiepian, "tt");
        retJsToC3 = re.replaceAll(retJsToC3, "tt[1-9]+", "tt1");
        assert.strictEqual(retJsToC3, JSON.stringify(jsToCParamMap1()));
    });

    it('test gen/generate/param_generate jsToCEnum', function () {
        let ret = jsToCEnum('string', 'vio->in0', 'pxt->GetArgv(0)')
        let retJson = JSON.stringify(ret)
        assert.strictEqual(retJson, 'null')
    });

    partOfTestTwo()
}

function partOfTestTwo(){
    it('test gen/generate/return_generate cToJs', function () {
        assert.strictEqual(cToJs("a", "string", "b", 1), "b = pxt->SwapC2JsUtf8(a.c_str());\n")

        ret = cToJs("a", "NUMBER_TYPE_1", "b", 1)
        assert.strictEqual(ret, "b = NUMBER_C_2_JS(pxt, a);\n")

        ret1 = cToJs("a", "boolean", "b", 1)
        assert.strictEqual(ret1, "b = pxt->SwapC2JsBool(a);\n")

        ret2 = cToJs("a", "void", "b", 1)
        assert.strictEqual(ret2, "b = pxt->UndefinedValue();\n")

        ret3 = cToJs("a", "any", "b", 1)
        assert.strictEqual(ret3, "pxt->GetAnyValue(a_type, result, a);")

        let retcToJs = JSON.stringify(cToJs("a", "Array<string>", "b", 1))
        retcToJs = re.replaceAll(retcToJs, "len[0-9]*", "len")
        retcToJs = re.replaceAll(retcToJs, "i[0-9]*", "i")
        retcToJs = re.replaceAll(retcToJs, "tnv[0-9]*", "tnv")
        assert.strictEqual(retcToJs, JSON.stringify(cToJsParamArray()))

        let retcToJs1 = JSON.stringify(cToJs("a", "string[]", "b", 1))
        retcToJs1 = re.replaceAll(retcToJs1, "len[0-9]*", "len")
        retcToJs1 = re.replaceAll(retcToJs1, "i[0-9]*", "i")
        retcToJs1 = re.replaceAll(retcToJs1, "tnv[0-9]*", "tnv")
        assert.strictEqual(retcToJs1, JSON.stringify(cToJsParamArray()))

        let retcToJs2 = JSON.stringify(cToJs("a", "Map<string,string>", "b", 1))
        retcToJs2 = re.replaceAll(retcToJs2, "i[0-9]*", "i")
        retQiepian = retcToJs2.substring(retcToJs2.indexOf("tnv"), retcToJs2.indexOf("tnv") + 4)
        retcToJs2 = re.replaceAll(retcToJs2, retQiepian, "tnv")
        retcToJs2 = re.replaceAll(retcToJs2, "tnv[0-9]+", "tnv1")
        assert.strictEqual(retcToJs2, JSON.stringify(cToJsParamMap()))

        let retcToJs3 = JSON.stringify(cToJs("a", "{[key:string]:string}", "b", 1))
        retcToJs3 = re.replaceAll(retcToJs3, "i[0-9]*", "i")
        retQiepian = retcToJs3.substring(retcToJs3.indexOf("tnv"), retcToJs3.indexOf("tnv") + 4)
        retcToJs3 = re.replaceAll(retcToJs3, retQiepian, "tnv")
        retcToJs3 = re.replaceAll(retcToJs3, "tnv[0-9]+", "tnv1")
        assert.strictEqual(retcToJs3, JSON.stringify(cToJsParamMap1()))
    });

    partOfTestTwo2();
}

function partOfTestTwo2() {
    it('test gen/generate/return_generate cToJsForInterface', function () {
        let ret = cToJsForInterface('vio->out', 'ConfigOption', 'result', 1)
        let retJson = JSON.stringify(ret)
        assert.strictEqual(retJson, '""')
    });

    it('test gen/generate/return_generate cToJsForType', function () {
        let ret = cToJsForType('vio->out', 'ConfigOption', 'result', 1)
        let retJson = JSON.stringify(ret)
        assert.strictEqual(retJson, '""')
    });

    it('test gen/generate/return_generate objectTempleteFuncReturn', function () {
        let ret = objectTempleteFuncReturn('vio->out');
        let retJson = JSON.stringify(ret)
        assert.strictEqual(retJson, '"pxt->GetObjectValue(result, vio->out);"')
    });
}

function variableMiddleBoolValue() {
    let variableMidVal = '\n      ' +
    '    napi_value ConfigOption_middle::getvalue_disable(napi_env env, napi_callback_info info)\n    ' +
    '    {\n        ' +
    '    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\n        ' +
    '    void *instPtr = pxt->UnWarpInstance();\n        ' +
    '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n        ' +
    '    napi_value result = nullptr;\n          ' +
    '    result = pxt->SwapC2JsBool(p->disable);\n\n        ' +
    '    delete pxt;\n        ' +
    '    return result;\n    ' +
    '    }\n      ' +
    '    napi_value ConfigOption_middle::setvalue_disable(napi_env env, napi_callback_info info)\n    ' +
    '    {\n        ' +
    '    std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);\n        ' +
    '    void *instPtr = pxt->UnWarpInstance();\n        ' +
    '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n          ' +
    '    BOOLEAN_JS_2_C(pxt->GetArgv(XNapiTool::ZERO), bool, p->disable);\n\n        ' +
    '    return nullptr;\n    ' +
    '    }'
    return  variableMidVal
}

function variableMiddleArrStrValue() {
    let variableMidVal = '\n      ' +
        '    napi_value ConfigOption_middle::getvalue_disable(napi_env env, napi_callback_info info)\n    ' +
        '    {\n        ' +
        '    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\n        ' +
        '    void *instPtr = pxt->UnWarpInstance();\n        ' +
        '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n        ' +
        '    napi_value result = nullptr;\n          ' +
        '    pxt->CreateArray(result);\n' +
        '    uint32_t outLen = p->disable.size();\n' +
        '    for (uint32_t i = 0; i < outLen; i++) {\n    ' +
        '    napi_value tnv = nullptr;\n    ' +
        '    tnv = pxt->SwapC2JsUtf8(p->disable[i].c_str());\n    ' +
        '    pxt->SetArrayElement(result, i, tnv);\n    }\n        ' +
        '    delete pxt;\n        ' +
        '    return result;\n    ' +
        '    }\n      ' +
        '    napi_value ConfigOption_middle::setvalue_disable(napi_env env, napi_callback_info info)\n    ' +
        '    {\n        ' +
        '    std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);\n        ' +
        '    void *instPtr = pxt->UnWarpInstance();\n        ' +
        '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n              ' +
        '    uint32_t len = pxt->GetArrayLength(pxt->GetArgv(XNapiTool::ZERO));\n' +
        '    for (uint32_t i = 0; i < len; i++) {\n    ' +
        '    std::string tt;\n    ' +
        '    pxt->SwapJs2CUtf8(pxt->GetArrayElement(pxt->GetArgv(XNapiTool::ZERO), i), tt);\n    ' +
        '    p->disable.push_back(tt);\n    }\n\n        ' +
        '    return nullptr;\n    ' +
        '    }'    
    return variableMidVal;
}

function variableMiddleMapStrValue() {
    // let variableMidVal = '\n      ' +
    //     '    static napi_value getvalue_disable(napi_env env, napi_callback_info info)\n    {\n    ' +
    //     '    XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\n    ' +
    //     '    void *instPtr = pxt->UnWarpInstance();\n    ' +
    //     '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n    ' +
    //     '    napi_value result = nullptr;\n    ' +
    //     '    result = nullptr;\n' +
    //     '    for (auto i = p->disable.begin(); i != p->disable.end(); i++) {\n    ' +
    //     '    const char * tnv;\n    ' +
    //     '    napi_value tnv = nullptr;\n    ' +
    //     '    tnv = (i -> first).c_str();\n    ' +
    //     '    tnv = pxt->SwapC2JsUtf8(i->second.c_str());\n    ' +
    //     '    pxt->SetMapElement(result, tnv, tnv);\n    }\n    ' +
    //     '    delete pxt;\n    ' +
    //     '    return result;\n    }\n' +
    //     '    static napi_value setvalue_disable(napi_env env, napi_callback_info info)\n    {\n    ' +
    //     '    std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);\n    ' +
    //     '    void *instPtr = pxt->UnWarpInstance();\n    ' +
    //     '    ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n    ' +
    //     '    uint32_t len = pxt->GetMapLength(pxt->GetArgv(XNapiTool::ZERO));\n' +
    //     'for (uint32_t i = 0; i < len; i++) {\n' +
    //     '    std::string tt;\n' +
    //     '    std::string tt;\n' +
    //     '    pxt->SwapJs2CUtf8(pxt->GetMapElementName(pxt->GetArgv(XNapiTool::ZERO), i), tt);\n    ' +
    //     '    pxt->SwapJs2CUtf8(pxt->GetMapElementValue(pxt->GetArgv(XNapiTool::ZERO), tt.c_str()), tt);\n\n' +
    //     '    p->disable.insert(std::make_pair(tt, tt));\n}\n    ' +
    //     '    return nullptr;\n    }'

    let variableMidVal = "\n          napi_value ConfigOption_middle::getvalue_disable(napi_env env, napi_callback_info info)\n        {\n            XNapiTool *pxt = std::make_unique<XNapiTool>(env, info).release();\n            void *instPtr = pxt->UnWarpInstance();\n            ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n            napi_value result = nullptr;\n              result = nullptr;\n    for (auto i = p->disable.begin(); i != p->disable.end(); i++) {\n        const char * tnv;\n        napi_value tnv = nullptr;\n        tnv = (i -> first).c_str();\n        tnv = pxt->SwapC2JsUtf8(i->second.c_str());\n        pxt->SetMapElement(result, tnv, tnv);\n    }\n            delete pxt;\n            return result;\n        }\n          napi_value ConfigOption_middle::setvalue_disable(napi_env env, napi_callback_info info)\n        {\n            std::shared_ptr<XNapiTool> pxt = std::make_shared<XNapiTool>(env, info);\n            void *instPtr = pxt->UnWarpInstance();\n            ConfigOption *p = static_cast<ConfigOption *>(instPtr);\n              uint32_t len = pxt->GetMapLength(pxt->GetArgv(XNapiTool::ZERO));\nfor (uint32_t i = 0; i < len; i++) {\n    std::string tt;\n    std::string tt;\n    pxt->SwapJs2CUtf8(pxt->GetMapElementName(pxt->GetArgv(XNapiTool::ZERO), i), tt);\n        pxt->SwapJs2CUtf8(pxt->GetMapElementValue(pxt->GetArgv(XNapiTool::ZERO), tt.c_str()), tt);\n\n    p->disable.insert(std::make_pair(tt, tt));\n}\n            return nullptr;\n        }"
    return variableMidVal;
}

function cToJsParamArray() {
    let value = 'pxt->CreateArray(b);\n' +
    '    uint32_t outLen1 = a.size();\n' +
    '    for (uint32_t i = 0; i < outLen1; i++) {\n' +
    '        napi_value tnv = nullptr;\n' +
    '        tnv = pxt->SwapC2JsUtf8(a[i].c_str());\n' +
    '        pxt->SetArrayElement(b, i, tnv);\n' +
    '    }'
    return value
}

function cToJsParamMap() {
    let value = 'result = nullptr;\n' +
        '    for (auto i = a.begin(); i != a.end(); i++) {\n' +
        '        const char * tnv;\n' +
        '        napi_value tnv1 = nullptr;\n' +
        '        tnv = (i -> first).c_str();\n' +
        '        tnv1 = pxt->SwapC2JsUtf8(i->second.c_str());\n' +
        '        pxt->SetMapElement(b, tnv, tnv1);\n' +
        '    }'
    return value
}

function cToJsParamMap1() {
    let value = 'result = nullptr;\n' +
        '    for (auto i = a.begin(); i != a.end(); i++) {\n' +
        '        const char * tnv;\n' +
        '        napi_value tnv1 = nullptr;\n' +
        '        tnv = (i -> first).c_str();\n' +
        '        tnv1 = pxt->SwapC2JsUtf8(i->second.c_str());\n' +
        '        pxt->SetMapElement(b, tnv, tnv1);\n' +
        '    }'
    return value
}

function jsToCParam() {
    let value = '    uint32_t len = pxt->GetArrayLength(b);\n' +
        '    for (uint32_t i = 0; i < len; i++) {\n' +
        '        std::string tt;\n' +
        '        pxt->SwapJs2CUtf8(pxt->GetArrayElement(b, i), tt);\n' +
        '        a.push_back(tt);\n' +
        '    }\n'
    return value
}

function jsToCParamArray() {
    let value = '    uint32_t len = pxt->GetArrayLength(b);\n' +
        '    for (uint32_t i = 0; i < len; i++) {\n' +
        '        std::string tt;\n' +
        '        pxt->SwapJs2CUtf8(pxt->GetArrayElement(b, i), tt);\n' +
        '        a.push_back(tt);\n' +
        '    }\n'
    return value
}

function jsToCParamMap() {
    let value = 'uint32_t len = pxt->GetMapLength(b);\n' +
        'for (uint32_t i = 0; i < len; i++) {\n' +
        '    std::string tt1;\n' +
        '    bool tt1;\n' +
        '    pxt->SwapJs2CUtf8(pxt->GetMapElementName(b, i), tt1);\n' +
        '        tt1 = pxt->SwapJs2CBool(pxt->GetMapElementValue(b, tt1.c_str()));\n' +
        '\n' +
        '    a.insert(std::make_pair(tt1, tt1));\n' +
        '}'
    return value
}

function jsToCParamMap1() {
    // let value = 'uint32_t len = pxt->GetMapLength(b);\n' +
    //     'for (uint32_t i = 0; i < len; i++) {\n' +
    //     '    std::string tt;\n' +
    //     '    number tt1;\n' +
    //     '    [replace_swap]\n' +
    //     '    a.insert(std::make_pair(tt, tt1));\n' +
    //     '}'
    // let value = "uint32_t len = pxt->GetMapLength(b);\nfor (uint32_t i = 0; i < len; i++) {\n    std::string tt0;\n    number tt1;\n    [replace_swap]\n    a.insert(std::make_pair(tt0, tt1));\n}"
    let value = "uint32_t len = pxt->GetMapLength(b);\nfor (uint32_t i = 0; i < len; i++) {\n    std::string tt1;\n    number tt1;\n    [replace_swap]\n    a.insert(std::make_pair(tt1, tt1));\n}"
    return value
}

function partOfNamespace(correctResult) {
    it('test gen/generate/namespace generateNamespace', function () {
        let enumElement = [{ name: "name", value: "", type: "string" }];
        let interfaceBody = { function: [], value: [{ name: "age", type: "NUMBER_TYPE_1" }] }
        let data = {
            class: [],
            const: [],
            enum: [{ name: "TestEnum", body: { element: enumElement, function: [], enumValueType: 0 } }],
            export: [],
            function: [{ name: "fun1", type: 1, value: [{ name: "v", type: "Array<string>" }], ret: "string" }],
            interface: [{ name: "TestInterface", body: interfaceBody }],
            namespace: []
        };
        let retJson = JSON.stringify(generateNamespace('napitest', data, inNamespace = ""));
        retJson = re.replaceAll(retJson, " ", "")
        retJson = re.replaceAll(retJson, "\\n", "")
        retJson = re.replaceAll(retJson, "len[0-9]+", "len")
        retJson = re.replaceAll(retJson, "i[0-9]+", "i")
        retJson = re.replaceAll(retJson, "tt[0-9]+", "tt")
        assert.strictEqual(retJson, correctResult['Generate']['generateNamespace']);
    });

    it('test gen/generate/namespace generateEnumResult', function () {
        let data = {
            "exports": ["GrantStatus"],
            "enum": [{
                "name": "GrantStatus",
                "body": {
                    "element": [
                        { "name": "PERMISSION_DEFAULT", "value": "", "type": "string" }],
                    "function": [],
                    "enumValueType": 1
                }
            }],
            "const": [],
            "type": [],
            "function": [],
            "interface": [],
            "class": [],
            "namespace": []
        };
        let retJson = JSON.stringify(generateEnumResult(data));
        let actualResult = retJson.substring(1,retJson.indexOf("implCpp") - 2);
        let expectresult1 = "\"implH\":\"\\nclass GrantStatus {\\npublic:\\n    ";
        let expectresult2 = "static const std::string PERMISSION_DEFAULT;\\n};\\n\"";
        assert.strictEqual(actualResult, expectresult1 + expectresult2);
    });

    partOfNamespaceTwo();
}
function partOfNamespaceTwo(){
    it('test gen/generate/namespace generateFunction', function () {
        let func = { name: "fun1", type: 4, value: [{ name: "cb", type: "AsyncCallback<string>" }] };
        let funcValue = [{ name: "cb", type: "AsyncCallback<string>" }]
        let data = {
            class: [],
            const: [],
            enum: [],
            export: [],
            function: [{ name: "fun1", type: 4, value: funcValue, ret: "string" }],
            interface: [],
            namespace: []
        };
        let retJson = JSON.stringify(generateFunction(func, data));
        retJson = re.replaceAll(retJson, "  ", "")
        assert.strictEqual(retJson, correctResult['Generate']['generateFunction']);
    });

    it('test gen/generate/namespace formatMiddleInit', function () {
        let ret = formatMiddleInit('', 'napitest');
        assert.strictEqual(JSON.stringify(ret), '""');
    })
}

function partofParamGenerate(correctResult) {
    partofParamGenerateArr(correctResult);

    partofParamGenerateMap(correctResult);

    partofParamGenerateCommon(correctResult);

    partofParamGenerateUnion(correctResult);

    partofParamGenerateCallBack(correctResult);

    partofParamGenerateAny(correctResult);

    partofParamGenerateObject(correctResult);

    partmapTempleteFunc()

    partunionTempleteFunc()

    partanyTempleteFunc()

    partobjectTempleteFunc()

    it('test gen/generate/param_generate ParamGenerate', function () {
        paramGenerateResult(correctResult);
    });

    it('test gen/generate/return_generate returnGenerate', function () {
        returnGenerateParam(correctResult);
    });
}

function partofParamGenerateArr(correctResult) {
    it('test gen/generate/param_generate paramGenerateArray', function () {
        let param = {
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        let funcValue = { name: 'v', type: 'Array<string>' }
        paramGenerateArray('0', funcValue, param);
        let retParam = JSON.stringify(param);
        retParam = re.replaceAll(retParam,"  ","");
        retParam = re.replaceAll(retParam,"len[0-9]+","len")  
        retParam = re.replaceAll(retParam,"i[0-9]+","i") 
        retParam = re.replaceAll(retParam,"tt[0-9]+","tt")
        assert.strictEqual(retParam, correctResult['Generate']['paramGenerateArray'])
    });
}

function partofParamGenerateMap(correctResult) {
    it('test gen/generate/param_generate paramGenerateMap', function () {
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        let funcVlaue = { name: 'v', type: '{[key:string]:string}', optional: false };
        paramGenerateMap(funcVlaue, param1, '0');
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        retParam1 = re.replaceAll(retParam1,"len[0-9]+","len")  
        retParam1 = re.replaceAll(retParam1,"i[0-9]+","i") 
        let parmQiepian = retParam1.substring(retParam1.indexOf("tt"),retParam1.indexOf("tt")+3)
        retParam1 = re.replaceAll(retParam1,parmQiepian,"tt")
        retParam1 = re.replaceAll(retParam1,"tt[0-9]+","tt")
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateMap'])
    });
}

function partofParamGenerateCommon(correctResult) {
    it('test gen/generate/param_generate paramGenerateCommon', function () {
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        let funcVlaue = { name: 'v', type: 'string', optional: false };
        paramGenerateCommon('0', 'std::string', funcVlaue, param1, '&', 'vio->in0');
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        retParam1 = re.replaceAll(retParam1,"len[0-9]+","len")  
        retParam1 = re.replaceAll(retParam1,"i[0-9]+","i") 
        retParam1 = re.replaceAll(retParam1,"tt[0-9]+","tt")
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateCommon'])
    });
}

function partofParamGenerateUnion(correctResult) {
    it('test gen/generate/param_generate paramGenerateUnion', function () {
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        paramGenerateUnion('string|NUMBER_TYPE_1|boolean', param1, '0', 'v');
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateUnion'])
    });
}

function partofParamGenerateCallBack(correctResult) {
    it('test gen/generate/param_generate paramGenerateCallBack', function () {
        let data = {
            class: [],
            const: [],
            enum:  [],
            exports: [],
            function: [
                {isStatic: false,
                name: 't1', 
                type: 2, 
                value: [{name: 'v1', type: 'string', optional: false},
                        {name: 'cb', type: 'Callback<string>', optional: false}],
                ret: 'void'}],
            interface: [],
            namespace: []
        }
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        let funcVlaue = { name: 'cb', type: 'Callback<string>', optional: false };
        paramGenerateCallBack(data, funcVlaue, param1, '1');
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateCallBack'])
    });
}

function partofParamGenerateAny(correctResult) {
    it('test gen/generate/param_generate paramGenerateAny', function () {
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        paramGenerateAny('0', 'v', 'any', param1);
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateAny'])
    });
}

function partofParamGenerateObject(correctResult) {
    it('test gen/generate/param_generate paramGenerateObject', function () {
        let param1 = {
            optionalParamDestory: '',
            valueCheckout: '',
            valueDefine: '',
            valueFill: '',
            valueIn: '',
            valueOut: '',
            valuePackage: ''
        }
        let funcVlaue = { name: 'v', type: 'Object', optional: false };
        paramGenerateObject('0', funcVlaue, param1);
        let retParam1 = JSON.stringify(param1);
        retParam1 = re.replaceAll(retParam1,"  ","");
        retParam1 = re.replaceAll(retParam1,"len[0-9]+","len");  
        retParam1 = re.replaceAll(retParam1,"i[0-9]+","i"); 
        retParam1 = re.replaceAll(retParam1,"tt[0-9]+","tt");
        retParam1 = re.replaceAll(retParam1,"NUMBER_TYPE_[0-9]+","NUMBER_TYPE_");
        assert.strictEqual(retParam1, correctResult['Generate']['paramGenerateObject'])
    });
}

function partmapTempleteFunc() {
    it('test gen/generate/param_generate mapTempleteFunc', function () {
        let ret = mapTempleteFunc('vio->in0', 'pxt->GetArgv(0)', '{[key:string]:string}')
        let retJson = JSON.stringify(ret)
        retJson = re.replaceAll(retJson,"  ","");
        retJson = re.replaceAll(retJson,"len[0-9]+","len");
        retJson = re.replaceAll(retJson,"i[0-9]+","i"); 
        let parmQiepian = retJson.substring(retJson.indexOf("tt"),retJson.indexOf("tt")+4)
        retJson = re.replaceAll(retJson,parmQiepian,"kk1");
        retJson = re.replaceAll(retJson,"tt[0-9]+","kk2");
        retJson = re.replaceAll(retJson,"\n","")
        assert.strictEqual(retJson, correctResult['Generate']['mapTempleteFunc'])
    })
}

function partunionTempleteFunc(){
  it('test gen/generate/param_generate unionTempleteFunc', function () {
      let ret = unionTempleteFunc('vio->in0', 'pxt->GetArgv(XNapiTool::ZERO)', 'string|NUMBER_TYPE_1|boolean')
      let retJson = JSON.stringify(ret)
      retJson = re.replaceAll(retJson,"  ","");
      retJson = re.replaceAll(retJson,"\n","")
      assert.strictEqual(retJson, correctResult['Generate']['unionTempleteFunc'])
  })
}

function partanyTempleteFunc(){
  it('test gen/generate/param_generate anyTempleteFunc', function () {
      let ret = anyTempleteFunc('vio->in0');
      let retJson = JSON.stringify(ret);
      retJson = re.replaceAll(retJson,"  ","");
      retJson = re.replaceAll(retJson,"\n","");
      assert.strictEqual(retJson, correctResult['Generate']['anyTempleteFunc']);
  })
}

function partobjectTempleteFunc(){
  it('test gen/generate/param_generate objectTempleteFunc', function () {
      let ret = objectTempleteFunc('vio->in0', 'pxt->GetArgv(XNapiTool::ZERO)')
      let retJson = JSON.stringify(ret)
      retJson = re.replaceAll(retJson,"  ","");
      retJson = re.replaceAll(retJson,"len[0-9]+","len");
      retJson = re.replaceAll(retJson,"i[0-9]+","i"); 
      retJson = re.replaceAll(retJson,"tt[0-9]+","tt");
      retJson = re.replaceAll(retJson,"NUMBER_TYPE_[0-9]+","NUMBER_TYPE_");
      retJson = re.replaceAll(retJson,"\n","")
      assert.strictEqual(retJson, correctResult['Generate']['objectTempleteFunc'])
  })
}

function returnGenerateParam(correctResult) {
    let retJson = returnGenerateAndAssert("string")
    retJson = re.replaceAll(retJson,"  ","")

    assert.strictEqual(retJson, correctResult['Generate']['returnGenerate'])

    let retJson1 = returnGenerateAndAssert("NUMBER_TYPE_1")
    retJson1 = re.replaceAll(retJson1,"  ","")

    assert.strictEqual(retJson1, correctResult['Generate']['returnGenerate1'])

    let retJson2 = returnGenerateAndAssert("boolean")
    retJson2 = re.replaceAll(retJson2,"  ","")
    assert.strictEqual(retJson2, correctResult['Generate']['returnGenerate2'])

    let retJson3 = returnGenerateAndAssert("Array<string>")
    retJson3 = re.replaceAll(retJson3,"  ","")
    retJson3 = re.replaceAll(retJson3,"len[0-9]*","len")
    retJson3 = re.replaceAll(retJson3,"i[0-9]*","i")
    retJson3 = re.replaceAll(retJson3,"tnv[0-9]*","tnv")

    assert.strictEqual(retJson3, correctResult['Generate']['returnGenerate3'])

    let retJson4 = returnGenerateAndAssert("Array<NUMBER_TYPE_1>")
    retJson4 = re.replaceAll(retJson4,"  ","")
    retJson4 = re.replaceAll(retJson4,"len[0-9]*","len")
    retJson4 = re.replaceAll(retJson4,"i[0-9]*","i")
    retJson4 = re.replaceAll(retJson4,"tnv[0-9]*","tnv")
    assert.strictEqual(retJson4, correctResult['Generate']['returnGenerate4'])

    let retJson5 = returnGenerateAndAssert("Array<boolean>")
    retJson5 = re.replaceAll(retJson5,"  ","")
    retJson5 = re.replaceAll(retJson5,"len[0-9]*","len")
    retJson5 = re.replaceAll(retJson5,"i[0-9]*","i")
    retJson5 = re.replaceAll(retJson5,"tnv[0-9]*","tnv")
    assert.strictEqual(retJson5, correctResult['Generate']['returnGenerate5'])   

    returnGenerateParamTwo(correctResult);

    returnGenerateParamThree(correctResult);
}

function returnGenerateParamTwo(correctResult){
    let retJson6 = returnGenerateAndAssert("string[]")
    retJson6 = re.replaceAll(retJson6,"  ","")
    retJson6 = re.replaceAll(retJson6,"len[0-9]*","len")
    retJson6 = re.replaceAll(retJson6,"i[0-9]*","i")
    retJson6 = re.replaceAll(retJson6,"tnv[0-9]*","tnv")
    assert.strictEqual(retJson6, correctResult['Generate']['returnGenerate6'])

    let retJson7 = returnGenerateAndAssert("boolean[]")
    retJson7 = re.replaceAll(retJson7,"  ","")
    retJson7 = re.replaceAll(retJson7,"len[0-9]*","len")
    retJson7 = re.replaceAll(retJson7,"i[0-9]*","i")
    retJson7 = re.replaceAll(retJson7,"tnv[0-9]*","tnv")
    assert.strictEqual(retJson7, correctResult['Generate']['returnGenerate7'])

    let retJson8 = returnGenerateAndAssert("NUMBER_TYPE_1[]")
    retJson8 = re.replaceAll(retJson8,"  ","")
    retJson8 = re.replaceAll(retJson8,"len[0-9]*","len")
    retJson8 = re.replaceAll(retJson8,"i[0-9]*","i")
    retJson8 = re.replaceAll(retJson8,"tnv[0-9]*","tnv")
    assert.strictEqual(retJson8, correctResult['Generate']['returnGenerate8'])
}

function returnGenerateParamThree(correctResult){
  let retJson9 = returnGenerateAndAssert("Map<string, string>")
  retJson9 = re.replaceAll(retJson9,"  ","")
  retJson9 = re.replaceAll(retJson9,"len[0-9]*","len")
  retJson9 = re.replaceAll(retJson9,"i[0-9]*","i")
  retJson9 = re.replaceAll(retJson9,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson9, correctResult['Generate']['returnGenerate9'])

  let retJson10 = returnGenerateAndAssert("{[key:string]: string}")
  retJson10 = re.replaceAll(retJson10,"  ","")
  retJson10 = re.replaceAll(retJson10,"len[0-9]*","len")
  retJson10 = re.replaceAll(retJson10,"i[0-9]*","i")
  retJson10 = re.replaceAll(retJson10,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson10, correctResult['Generate']['returnGenerate9'])

  let retJson11 = returnGenerateAndAssert("Map<string, NUMBER_TYPE_1>")
  retJson11 = re.replaceAll(retJson11,"  ","")
  retJson11 = re.replaceAll(retJson11,"len[0-9]*","len")
  retJson11 = re.replaceAll(retJson11,"i[0-9]*","i")
  retJson11 = re.replaceAll(retJson11,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson11, correctResult['Generate']['returnGenerate10'])

  let retJson12 = returnGenerateAndAssert("{[key:string]: NUMBER_TYPE_1}")
  retJson12 = re.replaceAll(retJson12,"  ","")
  retJson12 = re.replaceAll(retJson12,"len[0-9]*","len")
  retJson12 = re.replaceAll(retJson12,"i[0-9]*","i")
  retJson12 = re.replaceAll(retJson12,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson12, correctResult['Generate']['returnGenerate10'])

  let retJson13 = returnGenerateAndAssert("Map<string, boolean>")
  retJson13 = re.replaceAll(retJson13,"  ","")
  retJson13 = re.replaceAll(retJson13,"len[0-9]*","len")
  retJson13 = re.replaceAll(retJson13,"i[0-9]*","i")
  retJson13 = re.replaceAll(retJson13,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson13, correctResult['Generate']['returnGenerate11'])

  let retJson14 = returnGenerateAndAssert("{[key:string]: boolean}")
  retJson14 = re.replaceAll(retJson14,"  ","")
  retJson14 = re.replaceAll(retJson14,"len[0-9]*","len")
  retJson14 = re.replaceAll(retJson14,"i[0-9]*","i")
  retJson14 = re.replaceAll(retJson14,"tnv[0-9]*","tnv")
  assert.strictEqual(retJson14, correctResult['Generate']['returnGenerate11'])
}

function returnGenerateAndAssert(dataType) {
    param = {
        optionalParamDestory:'',
        valueCheckout:'',
        valueDefine:'',
        valueFill:'',
        valueIn:'',
        valueOut:'',
        valuePackage:''
    }
    data = {
        class: [],
        const: [],
        enum:  [],
        exports: [],
        function: [{name: 'fun1', type: 1, value: [], ret: dataType}],
        interface: [],
        namespace: []
    }
    let returnInfo = { type: dataType, optional: false }
    if (null != data) {
        returnGenerate(returnInfo, param, data)
    } else {
        returnGenerate(returnInfo, param)
    }
    let result = JSON.stringify(param);
    return result
}

function paramGenerateResult(correctResult) {
    let retJson = JSON.stringify(paramGenerateAndAssert("string"))
    retJson = re.replaceAll(retJson,"  ", "")
    assert.strictEqual(retJson, correctResult['Generate']['ParamGenerate'])

    let retJson1 = JSON.stringify(paramGenerateAndAssert("NUMBER_TYPE_1"));
    retJson1 = re.replaceAll(retJson1,"  ","")
    let qiepian = retJson1.substring(retJson1.indexOf("NUMBER_TYPE_"),retJson1.indexOf("NUMBER_TYPE_")+13);
    retJson1 = re.replaceAll(retJson1,qiepian,"NUMBER_TYPE_1")
    assert.strictEqual(retJson1, correctResult['Generate']['ParamGenerate1'])

    let retJson2 = JSON.stringify(paramGenerateAndAssert("boolean"))
    retJson2 = re.replaceAll(retJson2,"  ","")
    assert.strictEqual(retJson2, correctResult['Generate']['ParamGenerate2'])

    let retJson3 = JSON.stringify(paramGenerateAndAssert("Array<string>"))
    retJson3 = re.replaceAll(retJson3,"  ","")
    retJson3 = re.replaceAll(retJson3,"i[0-9]+","i")
    retJson3 = re.replaceAll(retJson3,"len[0-9]+","len")
    retJson3 = re.replaceAll(retJson3,"tt[0-9]+","tt")
    assert.strictEqual(retJson3, correctResult['Generate']['ParamGenerate3'])

    let retJson4 = JSON.stringify(paramGenerateAndAssert("Array<boolean>"))
    retJson4 = re.replaceAll(retJson4,"  ","")
    retJson4 = re.replaceAll(retJson4,"i[0-9]+","i")
    retJson4 = re.replaceAll(retJson4,"len[0-9]+","len")
    retJson4 = re.replaceAll(retJson4,"tt[0-9]+","tt")
    assert.strictEqual(retJson4, correctResult['Generate']['ParamGenerate4'])

    paramGenerateResultTwo(correctResult)

    paramGenerateResultThree(correctResult)
}

function paramGenerateResultTwo(correctResult){
    let retJson5 = JSON.stringify(paramGenerateAndAssert("Array<number>"));
    retJson5 = re.replaceAll(retJson5,"  ","")
    retJson5 = re.replaceAll(retJson5,"i[0-9]+","i")
    retJson5 = re.replaceAll(retJson5,"len[0-9]+","len")
    retJson5 = re.replaceAll(retJson5,"tt[0-9]+","tt")
    assert.strictEqual(retJson5, correctResult['Generate']['ParamGenerate5'])

    let retJson6 = JSON.stringify(paramGenerateAndAssert("string[]"))
    retJson6 = re.replaceAll(retJson6,"  ","")
    retJson6 = re.replaceAll(retJson6,"i[0-9]+","i")
    retJson6 = re.replaceAll(retJson6,"len[0-9]+","len")
    retJson6 = re.replaceAll(retJson6,"tt[0-9]+","tt")
    assert.strictEqual(retJson6, correctResult['Generate']['ParamGenerate6'])

    let retJson7 = JSON.stringify(paramGenerateAndAssert("boolean[]"));
    retJson7 = re.replaceAll(retJson7,"  ","")
    retJson7 = re.replaceAll(retJson7,"i[0-9]+","i")
    retJson7 = re.replaceAll(retJson7,"len[0-9]+","len")
    retJson7 = re.replaceAll(retJson7,"tt[0-9]+","tt")
    assert.strictEqual(retJson7, correctResult['Generate']['ParamGenerate7'])

    let retJson8 = JSON.stringify(paramGenerateAndAssert("number[]"))
    retJson8 = re.replaceAll(retJson8,"  ","")
    retJson8 = re.replaceAll(retJson8,"i[0-9]+","i")
    retJson8 = re.replaceAll(retJson8,"len[0-9]+","len")
    retJson8 = re.replaceAll(retJson8,"tt[0-9]+","tt")
    assert.strictEqual(retJson8, correctResult['Generate']['ParamGenerate8'])
}

function paramGenerateResultThree(correctResult){
    let retJson9 = paramGenerateAndAssert("Map<string, string>")
    retJson9 = re.replaceAll(retJson9,"  ","")
    retJson9 = re.replaceAll(retJson9,"len[0-9]*","len")
    retJson9 = re.replaceAll(retJson9,"i[0-9]*","i")
    retJson9 = re.replaceAll(retJson9,"tt[0-9]+","tt")
    assert.strictEqual(retJson9, correctResult['Generate']['ParamGenerate9'])

    let retJson10 = paramGenerateAndAssert("{[key:string]: string}")
    retJson10 = re.replaceAll(retJson10,"  ","")
    retJson10 = re.replaceAll(retJson10,"len[0-9]*","len")
    retJson10 = re.replaceAll(retJson10,"i[0-9]*","i")
    retJson10 = re.replaceAll(retJson10,"tt[0-9]+","tt")
    assert.strictEqual(retJson10, correctResult['Generate']['ParamGenerate9'])

    let retJson11 = paramGenerateAndAssert("Map<string, NUMBER_TYPE_1>")
    retJson11 = re.replaceAll(retJson11,"  ","")
    retJson11 = re.replaceAll(retJson11,"len[0-9]*","len")
    retJson11 = re.replaceAll(retJson11,"i[0-9]*","i")
    retJson11 = re.replaceAll(retJson11,"tt[0-9]+","tt")
    assert.strictEqual(retJson11, correctResult['Generate']['ParamGenerate10'])

    let retJson12 = paramGenerateAndAssert("{[key:string]: NUMBER_TYPE_1}")
    retJson12 = re.replaceAll(retJson12,"  ","")
    retJson12 = re.replaceAll(retJson12,"len[0-9]*","len")
    retJson12 = re.replaceAll(retJson12,"i[0-9]*","i")
    retJson12 = re.replaceAll(retJson12,"tt[0-9]+","tt")
    assert.strictEqual(retJson12, correctResult['Generate']['ParamGenerate10'])

    let retJson13 = paramGenerateAndAssert("Map<string, boolean>")
    retJson13 = re.replaceAll(retJson13,"  ","")
    retJson13 = re.replaceAll(retJson13,"len[0-9]*","len")
    retJson13 = re.replaceAll(retJson13,"i[0-9]*","i")
    retJson13 = re.replaceAll(retJson13,"tt[0-9]+","tt")
    assert.strictEqual(retJson13, correctResult['Generate']['ParamGenerate11'])

    let retJson14 = paramGenerateAndAssert("{[key:string]: boolean}")
    retJson14 = re.replaceAll(retJson14,"  ","")
    retJson14 = re.replaceAll(retJson14,"len[0-9]*","len")
    retJson14 = re.replaceAll(retJson14,"i[0-9]*","i")
    retJson14 = re.replaceAll(retJson14,"tt[0-9]+","tt")
    assert.strictEqual(retJson14, correctResult['Generate']['ParamGenerate11'])
}

function paramGenerateAndAssert(dataType) {
    param = {
        optionalParamDestory:'',
        valueCheckout:'',
        valueDefine:'',
        valueFill:'',
        valueIn:'',
        valueOut:'',
        valuePackage:''
    }
    data = {
        class: [],
        const: [],
        enum:  [],
        exports: [],
        function: [
            {name: 'fun1', 
             type: 1, 
             value: [{name: 'v', type: dataType, optional: false}],
             ret: 'void'}],
        interface: [],
        namespace: []
    }
    let funcValue = { name: "v", type: dataType, optional: false, realType: dataType }
    if (null != data) {
        paramGenerate(0, funcValue, param, data)
    } else {
        paramGenerate(0, funcValue, param)
    }
    let result = JSON.stringify(param);
    return result
}