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
const { fun1 } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");

// function fun1(v: any, v1: string): number;
describe('Any fun1', function () {    
    it('test fun1 any num string', function () {
        let ret = test.fun1("1", "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any number', function () {
        let ret = test.fun1(45678, "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any boolean', function () {
        let ret = test.fun1(true, "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any string array', function () {
        let ret = test.fun1(['11', '22', '33'], "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any number array', function () {
        let ret = test.fun1([1, 2, 3], "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any boolean array', function () {
        let ret = test.fun1({ "test": "okay", "test1": "res" }, "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any map number', function () {
        let ret = test.fun1({ "test": 15, "test1": 18 }, "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 any map number', function () {
        let ret = test.fun1({ "test": true, "test1": false }, "aa");
        assert.strictEqual(ret, 0);
    });

    it('test fun1 string', function () {
        let ret = test.fun1('guding', 'aaa');
        assert.strictEqual(ret, 0);
    });
 
});

describe('Any fun1 array map part', function () {
    it('test fun1 Array<map<string>>', function () {
        let ret = test.fun1([{ "test": "okay", "test1": "res" }, { "test2": "okay2", "test3": "res3" }], 'aaa');
        assert.strictEqual(ret, 0);
    });
    it('test fun1 Array<map<number>>', function () {
        let ret = test.fun1([{ "test": 17, "test1": 18 }, { "test2": 20, "test3": 22 }], 'aaa');
        assert.strictEqual(ret, 0);
    });
    it('test fun1 Array<map<boolean>>', function () {
        let ret = test.fun1([{ "test": true, "test1": false }, { "test2": true, "test3": false }], 'aaa');
        assert.strictEqual(ret, 0);
    });

    it('test fun1 map<Array<string>>', function () {
        let ret = test.fun1({ "test": ["okay", "okay1"], "test1": ["res", "res1"] }, 'aaa');
        assert.strictEqual(ret, 0);
    });
    it('test fun1 Array<map<number>>', function () {
        let ret = test.fun1({ "test": [15, 18], "test1": [18, 20] }, 'aaa');
        assert.strictEqual(ret, 0);
    });
    it('test fun1 Array<map<boolean>>', function () {
        let ret = test.fun1({ "test": [true, true], "test1": [false, false] }, 'aaa');
        assert.strictEqual(ret, 0);
    });
});

// function fun2(v: number, v1: TestClass1): number;
describe('Any fun2', function () {
    it('test fun2 interface any string', function () {
        let ret = test.fun2(15, { 'any1': 'aaa', 'focused': 'aaa' });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any number', function () {
        let ret = test.fun2(15, { 'any1': 11, 'def': 15 });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any boolean', function () {
        let ret = test.fun2(15, { 'any1': true, 'arr': [15, 20] });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any string array', function () {
        let ret = test.fun2(15, { 'any1': ['222', '333'], 'arr1': ['aaa', 'bbb'] });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any number array', function () {
        let ret = test.fun2(15,{'any1':[11,12],'extraInfo':{'name':'zhangsan','name1':'lisi'}});
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any boolean array', function () {
        let ret = test.fun2(15, { 'any1': [true, true], 'focused': true });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any map string', function () {
        ret = test.fun2(15, { 'any1': { 'test': '666' }, 'def': ['12', '15'] });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any map number', function () {
        let ret = test.fun2(15, { 'any1': { 'test': 88 }, 'arr': [true, false] });
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any map boolean', function () {
        let ret = test.fun2(15,{'any1':{'test':true},'arr1':[{'name':'hhh'},{'name':'lisi'}]});
        assert.strictEqual(ret, 0);
    });

    it('test fun2 interface any string number array', function () {
        ret = test.fun2(15,{'any1':'guding','extraInfo':{'name':[11, 15],'name1':[15, 18]}});
        assert.strictEqual(ret, 0);
    });
});

// function fun4(v: number, v1: Array<any>): number;
describe('Any fun4', function () {
    it('test fun4 Array string', function () {
        let ret = test.fun4(15,['aaa', 'bbb']);
        assert.strictEqual(ret, 0);
    });

    it('test fun4 Array number', function () {
        let ret = test.fun4(15, [15, 18]);
        assert.strictEqual(ret, 0);
    });

    it('test fun4 Array boolean', function () {        
        let ret = test.fun4(15, [true, true]);
        assert.strictEqual(ret, 0);
    });
});

// function fun5(v: string, v1: any[]): number;
describe('Any fun5', function () {
    it('test fun5 any string', function () {
        let ret = test.fun5('aaa',['aaa', 'bbb']);
        assert.strictEqual(ret, 0);
    });

    it('test fun5 any number', function () {
        let ret = test.fun5('aaa',[15, 18]);
        assert.strictEqual(ret, 0);
    });

    it('test fun5 any boolean', function () {
        let ret = test.fun5('aaa',[true, true]);
        assert.strictEqual(ret, 0);
    });
});

// function $fun6(v: boolean, param: Array<any>): number;
describe('Any fun6', function () {
    it('test fun6 array string', function () {
        let ret = test.$fun6(true,['aaa', 'bbb']);
        assert.strictEqual(ret, 0);
    });

    it('test fun6 array number', function () {
        let ret = test.$fun6(true,[15, 18]);
        assert.strictEqual(ret, 0);
    });
    
    it('test fun6 array boolean', function () {
        let ret = test.$fun6(true,[true, true]);
        assert.strictEqual(ret, 0);
    });    
});

// function fun8(v1: string[], v?: any): number;
describe('Any fun8', function () {
    it('test fun8 option any null', function () {
        let ret = test.fun8(['aaa','bbb']);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any number string', function () {
        let ret = test.fun8(['aaa','bbb'],"1");
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any number', function () {
        let ret = test.fun8(['aaa','bbb'],45678);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any boolean', function () {
        let ret = test.fun8(['aaa','bbb'],true);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any array string', function () {
        let ret = test.fun8(['aaa','bbb'],['11', '22', '33']);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any array number', function () {
        let ret = test.fun8(['aaa','bbb'],[1, 2, 3]);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any array boolean', function () {
        let ret = test.fun8(['aaa','bbb'],[true, true, false]);
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any map string', function () {
        let ret = test.fun8(['aaa','bbb'],{ "test": "okay", "test1": "res" });
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any map number', function () {
        let ret = test.fun8(['aaa','bbb'],{ "test": 15, "test1": 18 });
        assert.strictEqual(ret, 0);
    });

    it('test fun8 option any map boolean', function () {
        let ret = test.fun8(['aaa','bbb'],{ "test": true, "test1": false });
        assert.strictEqual(ret, 0);
    });

    it('test fun8  option any string', function () {  
        let ret = test.fun8(['aaa','bbb'],'guding');
        assert.strictEqual(ret, 0);
    });
});
