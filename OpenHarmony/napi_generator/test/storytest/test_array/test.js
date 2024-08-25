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
var assert = require("assert");

describe('AsyncCallback<string/number>', function () {
    function asynFun1(err, ret) {
        assert.strictEqual(err.code, 0)
        assert.deepStrictEqual(ret, [])
    }
    function def1(ret) {
        assert.deepStrictEqual(ret, [])
    }

    // function fun1(v1: string, v2: AsyncCallback<Array<string>>): void;
    it('test fun1_callback', function () {
        test.fun1('a', asynFun1)
        test.fun1('a').then(def1)
    });

    // function fun1(v1: string): Promise<Array<string>>;
    it('test fun1_promise', function () {
        let promiseObj = test.fun1('a');
        promiseObj.then(ret => { def1(ret) })
    });

    function asynFun2(err, ret) {
        assert.strictEqual(err.code, 0)
        assert.deepStrictEqual(ret, [])
    }

    function def2(ret) {
        assert.deepStrictEqual(ret, []);
    }

    // function fun2(v1: Array<number>, v2: AsyncCallback<Array<number>>): void;
    it('test fun2_callback', function () {
        test.fun2([2, 3], asynFun2);
        test.fun2([2, 3]).then(def2);
    });

    // function fun2(v1: Array<number>): Promise<Array<number>>;
    it('test fun2_promise', function () {
        let promiseObj = test.fun2([2, 3]);
        promiseObj.then(ret => { def2(ret) });
    });
});

describe('AsyncCallback<boolean>', function () {
    function asynFun3(err, ret) {
        assert.strictEqual(err.code, 0)
        assert.deepStrictEqual(ret, [])
    }

    function def3(ret) {
        assert.deepStrictEqual(ret, []);
    }

    // function fun3(v1: Array<boolean>, v2: AsyncCallback<Array<boolean>>): void;
    it('test fun3_callback', function () {
        test.fun3([true, false], asynFun3);
        test.fun3([true, false]).then(def3);
    });

    // function fun3(v1: Array<boolean>): Promise<Array<boolean>>;
    it('test fun3_promise', function () {
        let promiseObj = test.fun3([true, false]);
        promiseObj.then(ret => { def3(ret) });
    });
});

describe('array<basic>', function () {

    // function testArray(v: Array<string>): Array<string>;
    it('test testArray string', function () {
        let ret = test.testArray(['kkk', 'hhh']);
        assert.deepStrictEqual(ret, []);
    });

    // function testArray1(v: Array<number>): Array<number>;
    it('test testArray1 number', function () {
        let ret = test.testArray1([15, 18]);
        assert.deepStrictEqual(ret, []);
    });

    // function testArray2(v: Array<boolean>): Array<boolean>;
    it('test testArray2 boolean', function () {
        let ret = test.testArray2([true, false]);
        assert.deepStrictEqual(ret, []);
    });
});

describe('Array<interface>/map<array>', function () {
    // function fun4(v1: Array<string>, v2: Array<Test>): Array<number>;
    it('test fun4', function () {
        let ret = test.fun4(['kkk', 'hhh'], 
            [{ 'name': 'kkk', 'age': 18 }, { 'name': 'kkk', 'age': 18 }]);
        assert.deepStrictEqual(ret, []);
    });

    // function fun5(v1: Array<number>, v2: Array<Test>): Array<string>;
    it('test fun5', function () {
        let ret = test.fun5([12, 18], 
            [{ 'name': 'kkk', 'age': 18 }, { 'name': 'kkk', 'age': 18 }]);
        assert.deepStrictEqual(ret, []);
    });

    // function fun6(v1: Array<boolean>, v2: Array<Test>): Array<boolean>;
    it('test fun6', function () {
        let ret = test.fun6([true, false], 
            [{ 'name': 'kkk', 'age': 18 }, { 'name': 'kkk', 'age': 18 }]);
        assert.deepStrictEqual(ret, []);
    });

    // function fun7(v0: Array<string>, v1: { [key: string]: Array<string> }): number;
    it('test fun7', function () {
        let ret = test.fun7(['hhh', 'ooo'], 
            { 'name': ['aaa', 'bbb'], 'age': ['ccc', 'ddd'] });
        assert.strictEqual(ret, 0);
    });

    // function fun8(v0: Array<number>, v1: { [key: string]: Array<number> }): number;
    it('test fun8', function () {
        let ret = test.fun8([13, 15], 
            { 'name': [125, 126], 'age': [145, 146] });
        assert.strictEqual(ret, 0);
    });

    // function fun9(v0: Array<boolean>, v1: { [key: string]: Array<boolean> }): number;
    it('test fun9', function () {
        let ret = test.fun9([false, true], 
            { 'name': [true, false], 'age': [false, true] });
        assert.strictEqual(ret, 0);
    });

    // function fun11(v1: Map<string, Array<string>>): number;
    it('test fun11', function () {
        let ret = test.fun11({ 'name': ['aaa', 'bbb'], 'age': ['ccc', 'ddd'] });
    assert.strictEqual(ret, 0);
    });

    // function fun12(v1: Map<string, Array<number>>): string;
    it('test fun12', function () {
    let ret = test.fun12({ 'name': [111, 222], 'age': [333, 444] });
    assert.strictEqual(ret, '');
    });

    // function fun13(v1: Map<string, Array<boolean>>): boolean;
    it('test fun13', function () {
        let ret = test.fun13({ 'name': [true, true], 'age': [false, false] });
        assert.deepStrictEqual(ret, false);
    });
});

describe('map<array>', function () {
    function cb1(ret) {
        assert.deepStrictEqual(ret, [])
    }

    // function fun14(v1: Array<string>, callback: Callback<Array<string>>): void;
    it('test fun14', function () {
        test.fun14(['aaa', 'bbb', 'ccc'], cb1);
    });

    function cb2(ret) {
        assert.deepStrictEqual(ret, [])
    }

    // function fun15(v1: Array<number>, callback: Callback<Array<number>>): void;
    it('test fun15', function () {
        test.fun15([12, 15, 18], cb2);
    });

    function cb3(ret) {
        assert.deepStrictEqual(ret, [])
    }

    // function fun16(v1: Array<boolean>, callback: Callback<Array<boolean>>): void;
    it('test fun16', function () {
        test.fun16([true, true, false], cb3);
    });

    function cb4(ret) {
        assert.deepStrictEqual(ret, [])
    }

    // function fun17(callback: Callback<Array<Test>>): void;
    it('test fun17', function () {
        test.fun17(cb4);
    });

    // function fun21(v: string, v1: Array<Entry>): Array<Entry>;
    it('test fun21', function () {
        let ret = test.fun21('sdfghjk',
            [{ 'key': [15, 18], 'value': ['aa', 'bb'], 'isExit': [true, true] },
            { 'key': [15, 18], 'value': ['aa', 'bb'], 'isExit': [true, true] }]);
        assert.strictEqual(typeof ret, 'object');
    });
});
