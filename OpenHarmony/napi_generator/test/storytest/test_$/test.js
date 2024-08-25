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
const test = require("./out/build/Release/napitest")
const { Test, Person } = require("./out/build/Release/napitest")
var assert = require("assert");

describe('$', function () {
    // interface Test {
    //     $name: string;
    //     $listInputMethod(V: string): void;
    // }
    it('test $listInputMethod', function () {
        let te = new Test();
        let ret = te.$listInputMethod("1");
        assert.deepStrictEqual(typeof ret, 'undefined');
    });

    //     class Person {
    //     static $getMaxAge(v1: string): number;
    // }
    it('test $getMaxAge', function () {
        let pe = new Person();
        let ret = pe.$getMaxAge("1");
        assert.strictEqual(ret, 0);
    });

    // function $fun2(v: string): string;
    it('test $fun2', function () {
        let ret = test.$fun2("1");
        assert.strictEqual(ret, '');
    });

    // function fun3(v: Test): number;
    it('test fun3', function () {
        let ret = test.fun3('aaaaa');
        assert.strictEqual(ret, 0);
    });
});

