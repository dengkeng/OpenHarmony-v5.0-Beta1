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
const { TestClass1, fun5} = require("./out/build/Release/napitest")
const { fun6, fun7, fun8} = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");

describe('Object interface', function () { 
    var Radio = {
        RADIO_UNKNOWN : 0,
        RADIO_GSM : 1,
        RADIO_1XRTT : 2,
    }

    let tc1 = new TestClass1(); 
    // fun1(v: Object): number;
    it('test TestClass1 fun1', function () {
        let ret = tc1.fun1({"age":10,"name":"nameValue"});
        assert.strictEqual(ret, 0);
        ret = tc1.fun1({"age":[10,15],"name":"nameValue"});
        assert.strictEqual(ret,0)
        ret = tc1.fun1({"age":10,"name":{'test':'"nameValue"'}});
        assert.strictEqual(ret,0)
        ret = tc1.fun1({"age":10,"name":{'test':'nameValue','test1':15}});
        assert.strictEqual(ret,0)
        ret = tc1.fun1({"age":10,"name": Radio.RADIO_GSM});
        assert.strictEqual(ret,0)
    });

    // fun2(num: number, v: Object): number;
    it('test TestClass1 fun2', function () {
        let ret = tc1.fun2(2, {"age":10,"name":"nameValue"});
        assert.strictEqual(ret, 0);
    });

    // fun3(num: number, v: Object, Sam: string): number;
    it('test TestClass1 fun3', function () {
        let ret = tc1.fun3(2, {"age":10,"name":"nameValue"}, "test4");
        assert.strictEqual(ret, 0);
    });

    // fun4(numcc: number): Object;
    it('test TestClass1 fun4', function () {      
        let ret = tc1.fun4(2);
        assert.deepStrictEqual(typeof ret, 'object');
    });

    // fun9(): number;
    it('test TestClass1 fun9', function () {
        let ret = tc1.fun9();
        assert.strictEqual(ret, 0);
    });

});

describe('Object function', function () { 
    var Radio = {
        RADIO_UNKNOWN : 0,
        RADIO_GSM : 1,
        RADIO_1XRTT : 2,
    }
    
    // function fun5(v1: Object): number;
    it('test fun5', function () {        
        let ret = fun5({"name":"sam","age":10});
        assert.strictEqual(ret, 0);
        ret = fun5({"name":['Sam','Peter'],"age":10});
        assert.strictEqual(ret, 0);
        ret = fun5({"name":{'test': '11'},"age":10});
        assert.strictEqual(ret, 0);
        ret = fun5({"name":{'test': '11','test1':true},"age":10});
        assert.strictEqual(ret, 0);
        ret = fun5({"name":Radio.RADIO_GSM,"age":10});
        assert.strictEqual(ret, 0);
    });

    // function fun6(num1: number, v2: Object): number;
    it('test fun6', function () {
        let ret = fun6(2, {"age":10,"name":"nameValue"});
        assert.strictEqual(ret, 0);
    });

    // function fun7(num2: number, v3: Object, nike: string): number;
    it('test fun7', function () { 
        let ret = fun7(2, {"age":10,"name":"nameValue"}, "test4");
        assert.strictEqual(ret, 0);
    });

    // function fun8(dd: number): Object;
    it('test fun8', function () {
        let ret = fun8(2);
        assert.deepStrictEqual(typeof ret, 'object');
    });
});