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
const { TestClass1 } = require("./out/build/Release/napitest")
const testObj = require("./out/build/Release/napitest")
var assert = require("assert");

function onPromiseVoid (ret) {
    assert.strictEqual(ret, undefined);
}

function onPromiseNumber (ret) {
    assert.strictEqual(ret, 0);
}

function onPromiseBool (ret) {
    assert.strictEqual(ret, false);
}

function onPromiseString (ret) {
    assert.strictEqual(ret, "");
}

function onPromiseIf (ret) {
    assert.strictEqual(ret.dataName, "");
    assert.strictEqual(ret.dataIndex, 0);
}

function onPromiseArray (ret) {
    assert.strictEqual(ret, object);
}

function onAsyncCallString (err, ret) {
    assert.strictEqual(err.code, 0);
    assert.strictEqual(ret, "");
}

function onAsyncCallNumber (err, ret) {
    assert.strictEqual(err.code, 0);
    assert.strictEqual(ret, 0);
}

let testClass = new TestClass1();

describe('Test Promise1', function () {
    it('return basic type', function () {
        testObj.fun0().then(onPromiseVoid);
        testObj.fun1().then(onPromiseNumber);
        testObj.fun2().then(onPromiseBool);
        testObj.fun3().then(onPromiseString);
    });

    it('return basic type(interface method)', function () {
        testClass.fun10().then(onPromiseVoid);
        testClass.fun11().then(onPromiseNumber);
        testClass.fun12().then(onPromiseBool);
        testClass.fun13().then(onPromiseString);
    });

    it('return interface obj', function () {
        testObj.fun4(50).then(onPromiseIf);
        testClass.fun14(50).then(onPromiseIf);
    });
});

describe('Test Promise2', function () {
    it('return enum value', function () {
        // enum返回实际是按number处理的
        testObj.fun5(50).then(onPromiseNumber);
        testClass.fun15(50).then(onPromiseNumber);
    });
    
    it('return array', function () {
        testObj.fun6(50).then(onPromiseArray);
        testClass.fun16(50).then(onPromiseArray);
    });
});

describe('Test Promise3', function () {
    it('test AsCallback and Promise', function () {
        testObj.funX1(50, "60", onAsyncCallString);
        testObj.funX1(50, "60").then(onPromiseString);
        testClass.funX11(50, "60", onAsyncCallString);
        testClass.funX11(50, "60").then(onPromiseString);
    });

    it('test Promise and AsCallback', function () {
        testObj.funX2(50, "60", onAsyncCallNumber);
        testObj.funX2(50, "60").then(onPromiseNumber);
        testClass.funX12(50, "60", onAsyncCallNumber);
        testClass.funX12(50, "60").then(onPromiseNumber);
    });
});

