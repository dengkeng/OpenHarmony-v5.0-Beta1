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
const { TestClass1, TestClass2, TestClassUse, TestClassLater } = require("./out/build/Release/napitest")
const { Demo, Test, funcTest, funcTest2, Woman, Child } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('Class', function () {
    it('test TestClass1 fun1', function () {
        let tc1 = new TestClass1();
        let ret = tc1.fun1(1);
        assert.strictEqual(ret, 0);
    });

    it('test TestClass1 fun2', function () {
        let tc = new TestClass1();
        let ret = tc.fun2([1, 2, 3], { name: 'haha', age: 20 });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '{"name":"","age":0}');
    });

    it('test TestClass1 fun3', function () {
        let tc = new TestClass1();
        let ret = tc.fun3(2,'aaa',true);
        assert.strictEqual(ret, false);
    });

    it('test TestClass1 fun4', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun4({ 'name': 'haha', 'age': '20' });
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
        ret = tc.fun4({ 'name': 'haha', 'age': '20' },'aaa');
        retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
    });

    // export class Woman {
    //   constructor(name_: string, age_: number, isMarried_: boolean, status_: TestStatus;);
    //   w_name: string;
    //   w_age: number;
    //   w_isMarried: boolean;
    //   w_status: TestStatus;
    // }
    it('test Woman constructor', function () {
        let tc = new Woman("haha", 22, true, test.TestStatus.START_ABILITY);
        console.info("w_name is " + tc.w_name);
        console.info("w_age is " + tc.w_age);
        console.info("w_isMarried is " + tc.w_isMarried);
        console.info("w_status is " + tc.w_status);
    });

    // export class Child {
    //   constructor(name_: string, age_: number, status_: TestEnumString);
    //   w_name: string;
    //   w_age: number;
    //   w_status: TestEnumString;
    // }
    it('test Child constructor', function () {
        let tc = new Child("xixi", 10, test.TestEnumString.ACTION_SEARCH);
        console.info("w_name is " + tc.w_name);
        console.info("w_age is " + tc.w_age);
        console.info("w_status is " + tc.w_status);
    });
});

describe('Class Exception Test', function () {
    // 异常测试：class构造函数包含数值型枚举的异常测试
    it('test Woman constructor exception', function () {
        let ret = false;
        try {
            let tc = new Woman("hhh", 23, true, 5);
            console.info("w_name is " + tc.w_name);
            console.info("w_age is " + tc.w_age);
            console.info("w_isMarried is " + tc.w_isMarried);
            console.info("w_status is " + tc.w_status);
        } catch(err) {
            ret = true;
            console.error("error: " + err);
        }
        assert.strictEqual(ret, true);
    });

    // 异常测试：class构造函数包含字符型枚举的异常测试
    it('test Child constructor exception', function () {
        let ret = false;
        try {
            let tc = new Child("xixi", 10, "ggg");
            console.info("w_name is " + tc.w_name);
            console.info("w_age is " + tc.w_age);
            console.info("w_status is " + tc.w_status);
        } catch(err) {
            ret = true;
            console.error("error: " + err);
        }
        assert.strictEqual(ret, true);
    });
    
});

describe('Class defined later', function () {
    it('test TestClassUse funceUse', function () {
        let testLater = new TestClassLater();
        let tUse = new TestClassUse();
        let ret = tUse.funceUse(testLater);
        assert.strictEqual(ret, "");
    });
});

describe('Class part2', function () {
    it('test TestClass1 fun5', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun5(
            [{ name: 'haha', age: 20 }, { name: 'houhou', age: 23 }]);
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '{"name":"","age":0}');
    });

    it('test TestClass1 fun6', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun6(['11','22','33'],{'isExit':true,'isTrue':false});
        let retJson = JSON.stringify(ret);
        assert.strictEqual(retJson, '[]');
    });

    it('test TestClass1 fun8', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun8();
        assert.deepStrictEqual(typeof ret, 'undefined');
    });

    // fun9(manA: Man): string;
    // class Man 
    // {
    //     name: string;
    //     age: number;
    // }
    it('test TestClass1 fun9', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun9({ name: "testaa", age: 10});
        assert.strictEqual(ret, '');
    });

    // fun10(v: Image): Image;
    // export class Image {
    //     width: number;
    //     height: number;
    //     toDataURL(type?: string, quality?: number): string;
    // }
    it('test TestClass1 fun10', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun10({ width: 5, height: 10});
        assert.strictEqual(ret, '');
    });

    // fun11(v: LaunchReason): string;
    it('test TestClass1 fun11', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun11(test.LaunchReason.START_ABILITY);
        assert.strictEqual(ret, '');
    });

    // fun12(v: TestStatus): number;
    // export enum TestStatus {
    //     UNKNOWN = 0,
    //     START_ABILITY = 1,
    //     CALL = 2,
    //     CONTINUATION = 3,
    // }
    it('test TestClass1 fun12', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun12(test.TestStatus.CALL);
        assert.strictEqual(ret, '');
    });

    // fun13(v: TestEnumString): number;
    // export enum TestEnumString {
    //     ACTION_HOME = 'ohos.want.action.home',
    //     ACTION_DIAL = 'ohos.want.action.dial',
    //     ACTION_SEARCH = 'ohos.want.action.search',
    //     ACTION_WIRELESS_SETTINGS = 'ohos.settings.wireless',
    // }    
    it('test TestClass1 fun13', function () {
        let tc = new test.TestClass1();
        let ret = tc.fun13(test.TestEnumString.ACTION_DIAL);
        assert.strictEqual(ret, '');
    });

    // interface testClassUse {
    //     v0: string;
    //     //v1: testClassLater;
    //     // funceUse(n0: number): string;
    //     funceUse(n0: testClassLater): string;
    // }
});

describe('TestClass2', function () {    
    // func1(name : string, fp3: {nm: string, age: number}): string;
    it('test TestClass2 func1', function () {
        let tc = new TestClass2()
        let ret = tc.func1("func1p1", {nm:"aaa",age:18,flag:false});
        //assert.strictEqual(ret.read, 0);
    });

    // func2(input: string): { read: number; written: number; flag: boolean };
    it('test TestClass2 func2', function () {
        let tc = new TestClass2()
        let ret = tc.func2("name");
        //assert.strictEqual(ret.read, 0);
    });

    // func3(from: string, to: string): Promise<{result: number, errMsg: string, isT: boolean}>;
    it('test TestClass2 func3', function () {
        let tc = new TestClass2()
        let ret = tc.func3("from", "to");
        //assert.strictEqual(ret.read, 0);
    });

    // func4(from: string, to: string): Promise<{result: number; errMsg: string; isT: boolean}>;
    it('test TestClass2 func4', function () {
        let tc = new TestClass2()
        let ret = tc.func4("responeFrom", "responseTo");
        //assert.strictEqual(ret.read, 0);
    });

    // func5(v1: string, v2: number, v3: boolean);
    it('test TestClass2 func5', function () {
      let tc = new TestClass2()
      tc.func5("func5", 5, false);
    });
});

describe('Class Nest', function () {
  // class Demo {
  //     equals(other: Demo): boolean;
  //     handleCallback(): void;
  //     intPro: number;
  //     strPro: string;
  //     boolPro: boolean;
  //     inter: aa;
  //     type: Type;
  // }
  it('test Demo equals', function () {
      let tc1 = new test.Demo();
      let ret = tc1.equals({
          intPro: 1,
          strPro: "string",
          boolPro: true,
          inter: {abc: "abc", def: 7},
          type: test.Type.typeA,
      });
      assert.strictEqual(ret, false);
  });

    // class Test {
    //     type: Type;
    //     func(param: Type): boolean;
    // }
    it('test Test func', function () {
        let tc1 = new test.Test();
        let ret = tc1.func(test.Type.typeB);
        assert.strictEqual(ret, false);
    });

    // function funcTest(v: Type): boolean;
    it('test funcTest', function () {
        let ret = test.funcTest(test.Type.typeA);
        assert.strictEqual(ret, false);
    });

    // function funcTest2(v: Test): boolean;
    it('test funcTest2', function () {
        let ret = test.funcTest2({type: test.Type.typeB});
        assert.strictEqual(ret, false);
    });
});


