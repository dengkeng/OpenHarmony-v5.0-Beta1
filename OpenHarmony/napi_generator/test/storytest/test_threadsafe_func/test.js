/*
* Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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
const test = require("./out/build/Release/napitest")
const { TestClass1} = require("./out/build/Release/napitest")
var assert = require("assert");

describe('threadSafe func', function () {
    // function fun1(v: string): string;
    it('createThreadSafeFuncTest1', function () {
         test.createThreadSafeFuncTest1('Test1', (value, value1) => {
            return value + value1
         });
        // assert.deepStrictEqual(ret, '');
    });

    // interface TestClass1 {
    //     createThreadSafeFuncClass1(name: string, callback: (value?: number, value1?: number) => number):void
    // }
    it('TestClass1 createThreadSafeFuncClass1', function () {
        let ret = ''
        let tc = new TestClass1();
        tc.createThreadSafeFuncClass1('Class1', (value, value1) => {
         let res = value + value1
         console.log('value + value1 is: ' + res)
           return res
        });
        assert.deepStrictEqual(ret, '');
   });
});

