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

describe('string case', function () {
    // function fun1(v: string): string;
    it('test fun1', function () {
        let ret = test.fun1('18');
        assert.deepStrictEqual(ret, '');
    });

    // function fun2(v1: string, v2: string[]): string[];
    it('test fun2', function () {
        let ret = test.fun2('18', ['18', '20']);
        assert.deepStrictEqual(ret, []);
    });

    // function fun3(v1: Array<string>, v2: string): Array<string>;
    it('test fun3', function () {
        let ret = test.fun3(['18', '20'], '20');
        assert.deepStrictEqual(ret, []);
    });

    // function fun4(v: { [key: string]: string }): string;
    it('test fun4', function () {
        let ret = test.fun4({ 'isTrue': '18', 'isExit': '20' });
        assert.deepStrictEqual(ret, '');
    });

    // function fun5(v1: Map<string, string>, v2: string): string;
    it('test fun5', function () {
        let ret = test.fun5({ 'isTrue': '18', 'isExit': '20' }, '18');
        assert.deepStrictEqual(ret, '');
    });

    function asynFun1(err, ret) {
        assert.strictEqual(err.code, 0)
        assert.deepStrictEqual(ret, '')
    }
    function def1(ret) {
        assert.deepStrictEqual(ret, '');
    }
    // function fun6(v1: string, callback: AsyncCallback<string>): void;
    it('test fun6_callback', function () {
        test.fun6('15', asynFun1);
        test.fun6('15').then(def1);
    });
    // function fun6(v1: string): Promise<string>;
    it('test fun6_promise', function () {
        let promiseObj = test.fun6('15');
        promiseObj.then(ret => { def1(ret) });
    });
});

describe('string case part2', function () {
    function asynFun2(err, ret) {
        assert.deepStrictEqual(err.code, 0)
        assert.deepStrictEqual(ret, [])
    }
    function def2(ret) {
        assert.deepStrictEqual(ret, []);
    }
    // function fun7(v: string, v1: AsyncCallback<Array<string>>): void;
    it('test fun7_callback', function () {
        test.fun7('15', asynFun2);
        test.fun7('15').then(def2);
    });
    // function fun7(v: string): Promise<Array<string>>;
    it('test fun7_promise', function () {
        let promiseObj = test.fun7('15');
        promiseObj.then(ret => { def2(ret) });
    });
    // define callback for fun8
    function asynFun8(err, ret) {
        assert.deepStrictEqual(err.code, 0)
        assert.deepStrictEqual(ret, [])
    }
    function def8(ret) {
        assert.deepStrictEqual(ret, []);
    }
    // function fun8(v1: string, callback: AsyncCallback<string[]>): void;
    it('test fun8_AsyncCallback', function () {
        test.fun8('funTest', asynFun8);
        test.fun8('funTest').then(def8);
    });
    // function fun8(v1: string): Promise<string[]>;
    it('test fun8_promise', function () {
        let promiseObj = test.fun8('funTest');
        promiseObj.then(ret => { def8(ret) });
    });
});

describe('string case part3', function () {
            
    function cb1(ret) {
        assert.deepStrictEqual(ret, '')
    }

    // function fun9(v1: string, callback: Callback<string>): void;
    it('test fun9', function () {
        test.fun9('15', cb1);
    });

    // function fun10(v1: Test): Test;
    it('test fun10', function () {
        let ret = test.fun10(
            { age: '18', height: ['20', '20'], width: ['18', '18'] });
        assert.deepStrictEqual(typeof ret, 'object');
        assert.strictEqual(ret.age, '')
        assert.deepStrictEqual(ret.height, [])
        assert.deepStrictEqual(ret.width, [])
    });

    // function fun11(v: string, v1: string, v2: string): void;
    it('test fun11', function () {
        test.fun11('15', 'bb', 'cc');
    });

    //function fun12(v1: Test1): void;
    it('test fun12', function () {
        let ff = test.fun12({lon: {'isTrue': '18', 'isExit': '20' }, address: {'kvkey': 'valuetest'}});
    });

    // function fun13(v: number, v1: string, v2: string): void;
    it('test fun13', function () {
        test.fun13(15, 'bb', 'cc');
    });

    // function fun14(v: string, v1: string, v2: number): void;
    it('test fun14', function () {
        test.fun14('aa', 'bb', 10);
    });
});