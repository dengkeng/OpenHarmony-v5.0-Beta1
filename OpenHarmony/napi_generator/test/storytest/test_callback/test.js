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

function onCallback (ret) {
    assert.strictEqual(ret, 0);
}

function onVoidCallback (ret) {
    assert.strictEqual(ret, undefined);
}

function onAsyncCallback (err, ret) {
    assert.strictEqual(err.code, 0);
    assert.strictEqual(ret, 0);
}

function onVoidAsyncCallback (err, ret) {
    assert.strictEqual(err.code, 0);
    assert.strictEqual(ret, undefined);
}

function onCallbackNumStr(num) {
    assert.strictEqual(num, 0);
    return '' + num
}

function onCallbackVoid () {

}

// cb: (wid: boolean, str: string, tc2:number) => string
function onCallbackfun9(wid, str, tc2) {
    return 'wid' + 'str' + 'tc2'
}

// cb: (wid: boolean) => string
function onCallbackfun10nm(wid) {
    return 'fun10nm'
}

function onCallbackBooleanVStr (isOK) {
    let str
    if (isOK) {
        str = 'a' + 'b'
    }
    // return 'test aaa'
}

function onCallbackBooleanVStrRet (isOK) {
    let str = ''
    if (isOK) {
        str = 'onCallbackBooleanVStr' + 'a' + 'b' + 'isOK'
    }
    return str
}

function onCallbackfun22nm(isOk) {
    let flag = 0
    if(isOk) {
        flag = 1
    }
    return flag
}

function onCallbackfun21nm(isOk) {
    let flag = false
    if(isOk) {
        flag = true
    }
    return flag
}

describe('Test interface callback', function () {
    // fun11(cb: Callback<number>): void;
    it('test callback in interface fun11', function () {
        let testClass = new TestClass1();
        testClass.fun11(onCallback);
    });

    // fun12(cb: Callback<void>): void;
    it('test callback in interface fun12', function () {
        let testClass = new TestClass1();
        testClass.fun12(onVoidCallback);
    });

    // fun13(cb: AsyncCallback<number>): void;
    it('test callback in interface fun13', function () {
        let testClass = new TestClass1();
        testClass.fun13(onAsyncCallback);
    });

    // fun14(cb: AsyncCallback<void>): void; 
    it('test callback in interface fun14', function () {
        let testClass = new TestClass1();
        testClass.fun14(onVoidAsyncCallback);
    });

    // function fun15(cb: Callback<number>): string;
    it('test common func callback fun15', function () {
        let testClass = new TestClass1();
        testClass.fun15(onCallbackNumStr);
    });

    // fun16(tt: function): void;
    it('test common func callback fun16', function () {
        let testClass = new TestClass1();       
        testClass.fun16(onCallbackVoid);
    });

    // fun17(tt: Function): string;
    it('test common func callback fun17', function () { 
        let testClass = new TestClass1();       
        let ret = testClass.fun17(onCallbackVoid);
            assert.strictEqual(ret, '');
    });

    // fun110(cb: (wid: boolean) => string): string;
    it('test common func callback fun110', function () { 
        let testClass = new TestClass1();       
        let ret = testClass.fun110(onCallbackBooleanVStrRet);
            assert.strictEqual(ret, '');
    });

    // fun111(cb: (wid: boolean) => string): boolean;
    it('test common func callback fun111', function () { 
        let testClass = new TestClass1();       
        let ret = testClass.fun111(onCallbackBooleanVStrRet);
            assert.strictEqual(ret, false);
    });

    // fun112(cb: (wid: boolean) => string): number;
    it('test common func callback fun112', function () { 
        let testClass = new TestClass1();       
        let ret = testClass.fun112(onCallbackBooleanVStrRet);
            assert.strictEqual(ret, 0);
    });

    // 待补充用例
    // fun210(cb: (wid: boolean) => string): boolean;
    // fun211(cb: (wid: boolean) => boolean): string;
    // fun212(cb: (wid: boolean) => number): string;
});

describe('Test callback', function () {
    // function fun1(cb: Callback<number>): void;
    it('test common func callback fun1', function () {
        testObj.fun1(onCallback);
    });

    // function fun2(cb: Callback<void>): void;
    it('test common func callback fun2', function () {
        testObj.fun2(onVoidCallback);
    });

    // function fun3(cb: AsyncCallback<number>): void;
    it('test common func callback fun3', function () {
        testObj.fun3(onAsyncCallback);
    });

    // function fun4(cb: AsyncCallback<void>): void;
    it('test common func callback fun4', function () {
        testObj.fun4(onVoidAsyncCallback);
    });

    // function fun5(cb: Callback<number>): string;
    it('test common func callback fun5', function () {        
        testObj.fun5(onCallbackNumStr);
    });

    // function fun6(tt: function): void;
    it('test common func callback fun6', function () {        
        testObj.fun5(onCallbackVoid);
    });
    
    // fun7(tt: Function): string;
    it('test common func callback fun7', function () {        
       let ret = testObj.fun7(onCallbackVoid);
        assert.strictEqual(ret, '');
    });
});

describe('Test namespace arrow callback ', function () {
    // function fun8(cb: (wid: boolean) => void): string;
it('test common func callback fun8', function () {
let ret = ''   
ret = testObj.fun8(onCallbackBooleanVStr);
assert.strictEqual(ret, '');
});

// function fun9(cb: (wid: boolean, str: string, tc2:number) => string): string;
it('test common func callback fun9', function () {
let ret = ''   
ret = testObj.fun9(onCallbackfun9);
assert.strictEqual(ret, '');
});

// function fun10nm(cb: (wid: boolean) => string): string;
it('test common func callback fun10nm', function () {
let ret = ''   
ret = testObj.fun10nm(onCallbackfun10nm);
assert.strictEqual(ret, '');
});

// function fun11nm(cb: (wid: boolean) => string): boolean;
it('test common func callback fun11nm', function () {
let ret = ''   
ret = testObj.fun11nm(onCallbackfun10nm);
assert.strictEqual(ret, false);
});

// function fun12nm(cb: (wid: boolean) => string): number;
it('test common func callback fun12nm', function () {
let ret = ''   
ret = testObj.fun12nm(onCallbackfun10nm);
assert.strictEqual(ret, 0);
});

// function fun20nm(cb: (wid: boolean) => string): boolean;
it('test common func callback fun20nm', function () {
let ret = ''   
ret = testObj.fun20nm(onCallbackBooleanVStrRet);
assert.strictEqual(ret, false);
});

// function fun21nm(cb: (wid: boolean) => boolean): string;
it('test common func callback fun21nm', function () {
let ret = ''   
ret = testObj.fun21nm(onCallbackfun21nm);
assert.strictEqual(ret, '');
});

// function fun22nm(cb: (wid: boolean) => number): string;
it('test common func callback fun22nm', function () {
let ret = ''   
ret = testObj.fun22nm(onCallbackfun22nm);
assert.strictEqual(ret, '');
});

});