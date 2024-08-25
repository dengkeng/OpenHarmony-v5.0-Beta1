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
const { getProperties, enumParamFunc, NodeSayHello, NodeSayHi, WindowType } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('test_Interface', function () {
    function abc(ret) {
        assert.strictEqual(ret, '');
    }

    // function getProperties(callback: AsyncCallback<WindowProperties>): void;
    it('test getProperties', function () {
        getProperties().then(abc);
    });
});

describe('test_Interface2', function () {
    let tc = new NodeSayHello()
    it('test interfaceFunc', function () {
        // interface NodeSayHello {
        //     interfaceFunc(v0: string, v1: WindowType): boolean;
        // }
        let ret = tc.interfaceFunc('hello', 5);
        assert.strictEqual(ret, false);
    });
});

describe('test_Class', function () {
    let tc1 = new NodeSayHi()

    // export class NodeSayHi {
    //     classFunc(v0: WindowType, v1: number): string;   // Class中的方法参数是枚举
    // }
    it('test classFunc', function () {
        let ret = tc1.classFunc(6, 8);
        assert.strictEqual(ret, '');
    });
});

describe('test_Function', function () {
    it('test enumParamFunc', function () {
        // function enumParamFunc(v0: boolean, v1: WindowType): number;
        let ret = enumParamFunc(true, WindowType.TYPE_APP);
        assert.strictEqual(ret, 0);
    });
});


