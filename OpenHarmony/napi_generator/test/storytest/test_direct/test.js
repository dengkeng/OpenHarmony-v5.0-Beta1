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
const { TestClass1, func1 } = require("./out/build/Release/napitest")
var assert = require("assert");

describe('Number', function () {
    function abc(ret) {
        assert.strictEqual(ret, 0);
    }

    // fun1(v: number): number;    
    it('test TestClass1 fun1', function () {
        let tc1 = new TestClass1();
        let ret = tc1.fun1(1);
        assert.strictEqual(ret, 0);
    });

    // fun2(v: string): Result;
    it('test TestClass1 fun2', function () {
        let tc1 = new TestClass1();
        let ret = tc1.fun2('aaa');
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '{"code":0,"data":""}');
    });
});

describe('Direct', function () {
  // function func1(v1: string, v2: number, v3: boolean);
  it('test func1', function () {
      func1('aaa', 10, true);
  });
});

