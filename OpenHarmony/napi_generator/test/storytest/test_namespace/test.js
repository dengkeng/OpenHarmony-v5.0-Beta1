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
const { TestClass2 } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('Interface', function () {
    it('test TestClass2 fun3', function () {
        let ret = test.Space3.fun3("kkk");
        assert.strictEqual(ret, '');
    });

    it('test TestClass2 fix', function () {
        let tc1 = new test.Space3.TestClass2();
        let ret = tc1.fix('ccc');
        assert.strictEqual(ret, '');
    });

    it('test TestClass2 fun4', function () {
        let tc1 = new test.Space3.TestClass2();
        let ret = tc1.fun2([1,2,3,4],{name:'haha',age:20});
        let retJson=JSON.stringify(ret);
        assert.strictEqual(retJson, '{"name":"","age":0}');
    });
});





