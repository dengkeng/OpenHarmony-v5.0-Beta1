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
const main = require("../../hdc/appCodeGen/src/main");
const { getJsonCfg } = require("../../hdc/appCodeGen/src/app_code_gen");
const { NapiLog } = require("./tools/NapiLog");
const re = require("./tools/re");


//let file_path = `./@ohos.napitest.d.ts`
//let file_path = `D:\\code\\gitee\\napi_gen\\napi_generator-master\\src\\gen\\@ohos.napitest.d.ts`
//let file_path = `D:\\code\\commit\\napi_generator\\test\\storytest\\test_enum_interface\\@ohos.test.d.ts`
//let file_path = `D:\\code\\commit\\napi_generator\\test\\storytest\\test_enum_interface\\@ohos.test2.d.ts`

//let file_path = `D:\\DOC\\NAPI\\feature\\callback\\@ohos.napitestcallback.d.ts`
//let file_path = `D:\\DOC\\NAPI\\feature\\callback\\@ohos.napitestcallbackok.d.ts`

//let file_path = `D:\\DOC\\NAPI\\feature\\supported\\@ohos.napitestsupport.d.ts`
//let file_path = `D:\\DOC\\NAPI\\feature\\supported\\zzctest\\@ohos.napitestsupport.d.ts`
//let file_path = `D:\\DOC\\NAPI\\feature\\optional\\@ohos.test.d.ts`
//let file_path = `D:\\commit\\zhongwenqin\\napi_generator_0803\\test\\storytest\\test_interface_no_name\\@ohos.test.d.ts`

// let file_path = `D:\\DOC\\NAPI\\feature\\supported\\@ohos.napitestsupportSingle.d.ts`
//  let file_path = './test/storytest/test_type/@ohos.test.d.ts'
let file_path = 'D:\\Code\\debugAppCodeGen\\napi1109\\napi_generator_0824\\@ohos.napitest.d.ts'
let fn = re. getFileInPath(file_path)
let jsonCfg = `D:\\Code\\debugAppCodeGen\\napi1109\\napi_generator_0824\\funTestCfg.json`
NapiLog.init(NapiLog.LEV_INFO, "napi_gen.log")
NapiLog.logError("Begin to test.");
let funcConfig
if (jsonCfg) {
    funcConfig = getJsonCfg(jsonCfg);
}
let tt = re.match("(@ohos\.)*([.a-z_A-Z0-9]+).d.ts", fn) // @ohos\.[a-zA-Z0-9]+\.d\.ts  
if (tt) {
    main.doGenerate(file_path, "D:\\Code\\debugAppCodeGen\\napi1109\\napi_generator_0824\\appOut", funcConfig)
}
