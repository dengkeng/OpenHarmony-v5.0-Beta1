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
const { fun1,fun2, fun3, fun4, fun5, fun6, fun7, fun8, fun9, TestInterfaceBB} = require("./out/build/Release/napitest")
var assert = require("assert");

describe('interface_no_name', function () {    
    let fp2 = {
        anchor:"abc",
        align:"testfun2", 
        left:{
            test1:"fun2", 
            test2: "t2"
        }
    }
    let value = {
        xOffset: 100, 
        animation: { 
            duration: 20,
            curve: "tst"
        }
    }

    // function fun1(mancc: {name: string, age: number}): string;
    it('test interface_no_name fun1', function () {        
        let ret = fun1({"name":"abc","age":20});
        assert.strictEqual(ret, '');
    });

    // function fun2(fp2: TestInterface): string;
    it('test interface_no_name fun2', function () {        
        let ret = fun2(fp2);
        //assert.strictEqual(ret, '');
    });    
    
    // function fun3(name : string, fp3: {nm: string, age: number}): string;
    it('test interface_no_name fun3', function () {        
        let ret = fun3("fun3p1", {nm:"abc",age:20});
        //assert.strictEqual(ret, '');
    });
    
    // function fun4(input: string): { read: number; written: number };
    it('test interface_no_name fun4', function () {        
        let ret = fun4("name");
        //assert.strictEqual(ret.read, 0);
    });
    
    // function fun5(value: {xOffset: number, animation: { duration: number, curve: string}});
    it('test interface_no_name fun5', function () {
        fun5(value);   
        //let ret = fun5(value);
        //assert.strictEqual(ret, void);
    });

    // function fun6(nm: string, value: {xOffset: number, animation: { duration: number, curve: string}});
    it('test interface_no_name fun6', function () {     
        fun6("name", value);

    });

    // function fun7(nm: string, value: {xOffset: number; animation: { duration: number; curve: string}});
    it('test interface_no_name fun7', function () {
        fun7("name", value);
    });

    // function fun8(from: string): Promise<{result: number; errMsg: string; isT: boolean}>;
    it('test interface_no_name fun8', function () {        
      let ret = fun8("name");
      //assert.strictEqual(ret.read, 0);
    });

    // function fun9(from: string): Promise<{result: number, errMsg: string, isT: boolean}>;
    it('test interface_no_name fun9', function () {        
        let ret = fun9("name");
        //assert.strictEqual(ret.read, 0);
    });
});

describe('TestInterfaceBB', function () {    
    // func1(name : string, fp3: {nm: string, age: number}): string;
    it('test interface_no_name func1', function () {
      let tc = new TestInterfaceBB()
      let ret = tc.func1("func1p1", {nm:"aaa",age:18,flag:false});
      //assert.strictEqual(ret.read, 0);
    });

    // func2(input: string): { read: number; written: number; flag: boolean };
    it('test interface_no_name func2', function () {
      let tc = new TestInterfaceBB()
      let ret = tc.func2("name");
      //assert.strictEqual(ret.read, 0);
    });
  
    // func3(from: string, to: string): Promise<{result: number, errMsg: string, isT: boolean}>;
    it('test interface_no_name func3', function () {
        let tc = new TestInterfaceBB()
        let ret = tc.func3("from", "to");
        //assert.strictEqual(ret.read, 0);
    });

    // func4(from: string, to: string): Promise<{result: number; errMsg: string; isT: boolean}>;
    it('test interface_no_name func4', function () {
        let tc = new TestInterfaceBB()
        let ret = tc.func4("responeFrom", "responseTo");
        //assert.strictEqual(ret.read, 0);
    });
});

