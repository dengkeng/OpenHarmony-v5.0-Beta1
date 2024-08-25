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
const { fun1, fun2, fun4, fun5,fun6 } = require("./out/build/Release/napitest")
var assert = require("assert");

describe('any[]', function () {

    // function fun1(v1: any[]): number;
    it('test fun1', function () {
        let ret = fun1(['a', 'b', 'c', 'd']);
        assert.strictEqual(ret, 0);
    });

    // function fun1(v1: any[]): number;
    it('test fun1', function () {
        let ret = fun1([1, 2, 3, 4]);
        assert.strictEqual(ret, 0);
    });

    // function fun2(v1: Array<any>): number;
    it('test fun2', function () {
        let ret = fun2([true, true, false, false]);
        assert.strictEqual(ret, 0);
    });

    // function fun4(v1: Array<any>, v: number): number;
    it('test fun4 string', function () {
        let ret = fun4(['a', 'b', 'c', 'd'], 0);
        assert.strictEqual(ret, 0);
    });

    // function fun4(v1: Array<any>, v: number): number;
    it('test fun4 number', function () {
        let ret = fun4([1, 2, 3, 4], 0);
        assert.strictEqual(ret, 0);
    });

    it('test fun4 boolean', function () {
        let ret = fun4([true,false,false,true], 0);
        assert.strictEqual(ret, 0);
    });

    // function fun5(v: number, v1: Array<any>): number;
    it('test fun5', function () {
        let ret = fun5(0, ['a', 'b', 'c', 'd']);
        assert.strictEqual(ret, 0);
    });

    // function fun6(v: number, v1: any): number;
    it('test fun6 string', function () {
        let ret = fun6(0, 'd');
        assert.strictEqual(ret, 0);
    });

    // function fun6(v: number, v1: any): number;
    it('test fun6 number', function () {
        let ret = fun6(0, 1);
        assert.strictEqual(ret, 0);
    });

    // function fun6(v: number, v1: any): number;
    it('test fun6 boolean', function () {
        let ret = fun6(0, true);
        assert.strictEqual(ret, 0);
    });
});

