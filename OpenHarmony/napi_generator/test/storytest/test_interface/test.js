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
const { TestClass1, func1, func2, func3 } = require("./out/build/Release/napitest")
const { TestInterfaceUse, TestInterfaceLater} = require("./out/build/Release/napitest")

const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('Interface', function () {

    // fun1(v: number): number;
    it('test TestClass1 fun1', function () {
        let tc1 = new TestClass1();
        let ret = tc1.fun1(1);
        assert.strictEqual(ret, 0);
    });

    // fun2(numcc: Array<number>, mancc: Human): Human;
    it('test TestClass1 fun2', function () {
        let tc = new TestClass1();
        let ret = tc.fun2([1, 2, 3], { name: 'haha', age: 20 });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '{"name":"","age":0}');
    });

    // fun3: (v: number, v1: string, v2: boolean) => boolean;
    it('test TestClass1 fun3', function () {
        let tc = new TestClass1();
        let ret = tc.fun3(2,'aaa',true);
        assert.strictEqual(ret, false);
    });

    // fun4: (mancc: Map<string, string>,v?: string) => Array<number>;
    it('test TestClass1 fun4', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun4({ 'name': 'haha', 'age': '20' });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
        ret = tc.fun4({ 'name': 'haha', 'age': '20' },'aaa');
        retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
    });
});

describe('Interface', function () {

    // fun5: (data: Array<Human>) => Human;
    it('test TestClass1 fun5', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun5(
            [{ name: 'haha', age: 20 }, { name: 'houhou', age: 23 }]);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '{"name":"","age":0}');
    });

    // fun6: (v: string[], v1: { [key: string]: boolean }) => string[];
    it('test TestClass1 fun6', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun6(['11','22','33'],{'isExit':true,'isTrue':false});
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
    });

    // fun8: () => void;
    it('test TestClass1 fun8', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun8();
        assert.deepStrictEqual(typeof ret, 'undefined');
    });

    //  fun9(manA: Man): void;
    // interface Man 
    // {
    //     name: string;
    //     age: number;
    // }
    it('test TestClass1 fun9', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun9({name: 'asa', age: 3});
        assert.deepStrictEqual(typeof ret, 'undefined');
    });

    // fun12(v: TestStatus): string;
    // export enum TestStatus {
    //     UNKNOWN = 0,
    //     START_ABILITY = 1,
    //     CALL = 2,
    //     CONTINUATION = 3,
    // }    
    it('test TestClass1 fun12', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun12(test.TestStatus.CONTINUATION);
        assert.strictEqual(ret, 0);
    });

    // fun13(v: TestEnumString): string;
    // export enum TestEnumString {
    //     ACTION_HOME = 'ohos.want.action.home',
    //     ACTION_DIAL = 'ohos.want.action.dial',
    //     ACTION_SEARCH = 'ohos.want.action.search',
    //     ACTION_WIRELESS_SETTINGS = 'ohos.settings.wireless',
    // }    
    it('test TestClass1 fun13', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun13(test.TestEnumString.ACTION_SEARCH);
        assert.strictEqual(ret, 0);
    });
});

describe('Interface', function () {
    // fun16(v1: number, v2: string, v3: boolean);
    it('test TestClass1 fun16', function () {
        let tc = new TestClass1()
        tc.fun16(5, "fun16",false);
    });
});

describe('Interface Optional Param func1', function () {
    it('test Function func1 test1', function () {
        let ret = func1({aa: 'aa', bb: false, cc: 7, dd: 'dd', ee: 27}, 17);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func1 test2', function () {
        let ret = func1({aa: 'aa', bb: false, cc: 7, dd: 'dd', ee: 27});
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func1 test3', function () {
        let ret = func1({aa: 'aa', dd: 'dd', bb: false, cc: 7,ee: 27});
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func1 test4', function () {
        let ret = func1({aa: 'aa', bb: false, cc: 7}, 17);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func1 test5', function () {
        let ret = func1({aa: 'aa', cc: 7}, 17);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func1 test6', function () {
        let ret = func1({aa: 'aa', dd: 'ababab', cc: 7}, 17);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });
});

describe('Interface Optional Param func2', function () {
    it('test Function func2 test1', function () {
        let ret = func2({
            a1: { 'name': 999, 'age': 20 }, 
            c1: [1, 2, 3],
        });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func2 test2', function () {
        let ret = func2({
            a1: { 'name': 999, 'age': 20 }, 
            b1: { 'name': 'ahah', 'age': '02' }, 
            c1: [1, 2, 3],
            d1: ['a', 'b', 'c'],
            e1: 999,
            g1: {aa: 'aa', dd: 'ababab', cc: 7}
        });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    it('test Function func3 test1', function () {
        let ret = func3({
            test: {a1: 23,
            bb: [1,2,3], cc:{'map': 'value'}, 
            aa: false, dd: [true, false], ee: {'map2': 25}, 
            gg: 23}
        });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '""');
    });

    // fun1(v: number): number;
    // interface testInterfaceUse {
    //     v0: string;
    //     //v1: testInterfaceLater;
    //     // funceUse(n0: number): string;
    //     funceUse(n0: testInterfaceLater): string;
    // }
    it('test TestInterfaceUse funceUse', function () {
        let testLater = new TestInterfaceLater();
        let tUse = new TestInterfaceUse();
        let ret = tUse.funceUse(testLater);
        assert.strictEqual(ret, "");
    });
});