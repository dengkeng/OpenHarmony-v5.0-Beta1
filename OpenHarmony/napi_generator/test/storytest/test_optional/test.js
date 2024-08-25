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
const { TestClass1, TestClass2 } = require("./out/build/Release/napitest")
const { TestClass3, TestClass4 } = require("./out/build/Release/napitest")
var assert = require("assert");
const { type } = require("os");

describe('Optional basic', function () {

    it('test basic type', function () {
        let ret = test.fun1("a");
        assert.strictEqual(ret, 0);
        ret = test.fun1("a", "b");
        assert.strictEqual(ret, 0);
        ret = test.fun1("a", "b", 3);
        assert.strictEqual(ret, 0);
        ret = test.fun1("a", "b", 3, true);
        assert.strictEqual(ret, 0);

        let tc = new TestClass1();
        ret = tc.interFun1();
        assert.strictEqual(ret, 0);
        ret = tc.interFun1("a");
        assert.strictEqual(ret, 0);
        ret = tc.interFun1("a", "b");
        assert.strictEqual(ret, 0);
        ret = tc.interFun1("a", "b", 3);
        assert.strictEqual(ret, 0);
        ret = tc.interFun1("a", "b", 3, true);
        assert.strictEqual(ret, 0);
    });
});

describe('Optional Array', function () {

    it('test Array', function () {
        let ret = test.fun21("a");
        assert.strictEqual(ret, 0);
        ret = test.fun21("a", ['aa', 'bb', 'cc']);
        assert.strictEqual(ret, 0);
        ret = test.fun21("a", ['aa', 'bb', 'cc'], [1, 2, 3]);
        assert.strictEqual(ret, 0);
        ret = test.fun21("a", 
            ['aa', 'bb', 'cc'], [1, 2, 3], [true, true, true]);
        assert.strictEqual(ret, 0);
    });

    function def(ret) {
        assert.deepStrictEqual(ret, '');
    }

    it('test AsyncCallback<Array>', function () {
        test.fun23('15').then(def);
    });

    it('test AsyncCallback<Array>', function () {
        let promiseObj = test.fun23('15');
        promiseObj.then(ret => { def(ret) });
    });

    it('test interface array', function () {
        let tc = new TestClass2();
        ret = tc.interFun21();
        assert.strictEqual(ret, 0);
        ret = tc.interFun21([1, 2, 3, 4]);
        assert.strictEqual(ret, 0);
        ret = tc.interFun21([1, 2, 3, 4], ['a', 'b', 'c', 'd']);
        assert.strictEqual(ret, 0);
        ret = tc.interFun21([1, 2, 3, 4], 
            ['a', 'b', 'c', 'd'], [true, false, true, false]);
        assert.strictEqual(ret, 0);
    });
});

describe('Optional Map', function () {

    it('test map{}', function () {
        let ret = test.fun31("a");
        assert.strictEqual(ret, 0);
        ret = test.fun31("a", { 'test': 15, 'test1': 18 });
        assert.strictEqual(ret, 0);
    });

    it('test map<>', function () {
        let ret = test.fun32("a");
        assert.strictEqual(ret, 0);
        ret = test.fun32("a", { 'test': '15', 'test1': '18' });
        assert.strictEqual(ret, 0);
    });

    it('test interface map{}', function () {
        let tc = new TestClass3();
        ret = tc.interFun31('aaaa');
        assert.strictEqual(ret, 0);
        ret = tc.interFun31('aaaa', { 'test': 18, 'tst1': 20 });
        assert.strictEqual(ret, 0);
    });

    it('test interface map<>', function () {
        let tc = new TestClass3();
        ret = tc.interFun32('aaaa');
        assert.strictEqual(ret, 0);
        ret = tc.interFun32('aaaa', { 'test': true, 'tst1': false });
        assert.strictEqual(ret, 0);
    });
});

describe('Optional enum', function () {
    var GrantStatus = {
        PERMISSION_DEFAULT: "",
        PERMISSION_DENIED: "-1",
        PERMISSION_GRANTED: "2",
        PERMISSION_PASS: "3",
    }
    var HttpStatus = {
        STATUS0: 0,
        STATUS1: 500,
        STATUS2: 503,
    }
    function cb3(ret) {
        assert.strictEqual(typeof ret, 'number');
    }
    it('test enum type', function () {
        let ret = test.fun41();
        assert.strictEqual(ret, 0);
        ret = test.fun41(HttpStatus.STATUS1);
        assert.strictEqual(ret, 0);
        ret = test.fun41(HttpStatus.STATUS1, GrantStatus.PERMISSION_DENIED);
        assert.strictEqual(ret, 0);
        ret = test.fun42('1');
        ret = test.fun42('1', cb3);
    });
});

describe('Optional interface', function () {
    function cb4(ret) {
        assert.notEqual(ret.name, undefined)
        assert.notEqual(ret.age, undefined)
    }
    it('test interface', function () {
        let ret = test.fun51();
        assert.strictEqual(ret, 0);
        ret = test.fun51({ name: 'n1', age: 20 });
        assert.strictEqual(ret, 0);
        ret = test.fun51({ name: 'n1', age: 20 }, { name: 'n2', age: 30 });
        assert.strictEqual(ret, 0);
        ret = test.fun51({ name: 'n1', age: 20 }, 
            { name: 'n2', age: 30 }, { name: 'n3', age: 40 });
        assert.strictEqual(ret, 0);

        ret = test.fun52({ name: 'n1', age: 20 });
        assert.strictEqual(ret, 0);
        ret = test.fun52({ name: 'n1', age: 20 }, 
            [{ name: 'm1', age: 121 }, { name: 'm2', age: 123 }]);
        assert.strictEqual(ret, 0);

        ret = test.fun53({ name: 'n1', age: 20 });
        ret = test.fun53({ name: 'n1', age: 20 }, cb4);

        ret = test.fun61();
        assert.strictEqual(ret, 0);
        ret = test.fun61({ name: 'n2', age: 25 });
        assert.strictEqual(ret, 0);
    });

    it('test interface type', function () {
        let tc = new TestClass4();
        ret = tc.interFun51({ name: 'n2', age: 25 });
        assert.strictEqual(ret, 0);
        ret = tc.interFun51({ name: 'n2', age: 25 }, { name: 'n2', age: 25 });
        assert.strictEqual(ret, 0);
        ret = tc.interFun51({ name: 'n2', age: 25 }, 
            { name: 'n2', age: 25 }, { name: 'n2', age: 25 });
        assert.strictEqual(ret, 0);
    });

});

