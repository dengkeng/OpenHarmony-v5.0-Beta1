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
const { fun1, fun2, fun3, fun8, fun9, fun10} = require("./out/build/Release/napitest")
var assert = require("assert");

describe('array_map', function () {
    
    // function fun1(v: Array<{[key: string]:string}>): number;
    it('test fun1', function () {
        let ret = fun1([{"age":"a"}, {"name":"b"}]);
        assert.strictEqual(ret, 0);
    });
    
    // function fun2(v: Array<{[key: string]:number}>): number;
    it('test fun2', function () {
        let ret = fun2([{"age":1}, {"name":2}]);
        assert.strictEqual(ret, 0);
    });

    // function fun3(v: Array<{[key: string]:boolean}>): number;
    it('test fun3', function () {
        let ret = fun3([{"age":true}, {"name":false}]);
        assert.strictEqual(ret, 0);
    });
    
    // function fun8(v: Array<Map<string, string>>): number;
    it('test fun8', function () {
        let ret = fun8([{"age":"a"}, {"name":"b"}]);
        assert.strictEqual(ret, 0);
    });

    // function fun9(v: Array<Map<string, number>>): number;
    it('test fun9', function () {
        let ret = fun9([{"age":1}, {"name":2}]);
        assert.strictEqual(ret, 0);
    });

    // function fun10(v: Array<Map<string, boolean>>): number;
    it('test fun10', function () {
        let ret = fun10([{"age":true}, {"name":false}]);
        assert.strictEqual(ret, 0);
    });

    /*
    it('test fun7', function () {
        let ret = fun7([{"key":'{"code":0,"data":"code0"}'}, {"name":'{"code":1,"data":"code1"}'}]);
        assert.strictEqual(ret, 0);
    }); 
    */  

    /*it('test fun12', function () {
        let ret = fun12([{"key1":'code1'}, {"key2":'code2'}]);
        assert.strictEqual(ret, 0);
    });
    
    it('test fun10', function () {
        let ret = fun12([{"key1":'{"code":0,"data":"code0"}'}, {"key2":'{"code":1,"data":"code1"}'}]);
        assert.strictEqual(ret, 0);
    });
    */
});
