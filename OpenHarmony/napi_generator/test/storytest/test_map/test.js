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
const { TestClass1 ,TestClass2 } = require("./out/build/Release/napitest")
var assert = require("assert");

describe('Map', function () {
    it('test TestClass2 fun1', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun1({"age":"ageValue","name":"nameValue"},'aaaa');
        assert.strictEqual(ret, 0);
    });
    
    it('test TestClass2 fun2', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun2({"age":1234,"name":5678});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun3', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun3({"age":true,"name":false});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun4', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun4({"age":["1","12","145"],"name":["21","22","23"]});
        assert.strictEqual(ret, 0);
    });
        
    it('test TestClass2 fun5', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun5({"age":[122,222,322],"name":[422,522,622]});
        assert.strictEqual(ret, 0);
    });
});

describe('Map', function () {
    it('test TestClass2 fun6', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun6({"age":[true,true,true],"name":[false,false,false]});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun7', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun7({"age":"ageValue","name":"nameValue"});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun8', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun8(
            {"peter":{"age":"ageValue","name":"nameValue"},
            "jane":{"age":"ageValue","name":"nameValue"}});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun9', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun9(
            {"peter":{"age":666,"name":"peter","isTrue":true},
            "jane":{"age":666,"name":"jane","isTrue":false}});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun10', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun10(
            {"peter":{"age":666,"name":"peter","isTrue":true},
            "jane":{"age":666,"name":"jane","isTrue":false}});
        assert.strictEqual(ret, 0);
    });    
});

describe('Map_Any', function () {
    it('test TestClass2 fun11', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun11({"age":"ageValue","name":"nameValue"});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun11', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun11({"age":1234,"name":5678});
        assert.strictEqual(ret, 0);
    });
    
    it('test TestClass2 fun11', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun11({"age":true,"name":false});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun11', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun11({"age":[1,23,456],"name":[7,89,101112]});
        assert.strictEqual(ret, 0);
    });

    it('test TestClass2 fun11', function () {
        let tc2 = new TestClass2();
        let ret = tc2.fun11({"peter":{"age":"ageValue","name":"nameValue"},
                            "jane":{"age":"ageValue","name":"nameValue"}});
        assert.strictEqual(ret, 0);
    });
});