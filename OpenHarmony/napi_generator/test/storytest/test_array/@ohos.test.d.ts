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
import { AsyncCallback, Callback } from './../basic';

declare namespace napitest {
    interface Test {
        name: string;
        age: number;
    }

    interface Entry {
        key: Array<number>;
        value: Array<string>;
        isExit: Array<boolean>;
    }

    function fun1(v1: string, v2: AsyncCallback<Array<string>>): void;
    function fun1(v1: string): Promise<Array<string>>;
    function fun2(v1: Array<number>, v2: AsyncCallback<Array<number>>): void;
    function fun2(v1: Array<number>): Promise<Array<number>>;
    function fun3(v1: Array<boolean>, v2: AsyncCallback<Array<boolean>>): void;
    function fun3(v1: Array<boolean>): Promise<Array<boolean>>;
    function testArray(v: Array<string>): Array<string>;
    function testArray1(v: Array<number>): Array<number>;
    function testArray2(v: Array<boolean>): Array<boolean>;
    function fun4(v1: Array<string>, v2: Array<Test>): Array<number>;
    function fun5(v1: Array<number>, v2: Array<Test>): Array<string>;
    function fun6(v1: Array<boolean>, v2: Array<Test>): Array<boolean>;
    function fun7(v0: Array<string>, v1: { [key: string]: Array<string> }): number;
    function fun8(v0: Array<number>, v1: { [key: string]: Array<number> }): number;
    function fun9(v0: Array<boolean>, v1: { [key: string]: Array<boolean> }): number;
    function fun11(v1: Map<string, Array<string>>): number;
    function fun12(v1: Map<string, Array<number>>): string;
    function fun13(v1: Map<string, Array<boolean>>): boolean;
    function fun14(v1: Array<string>, callback: Callback<Array<string>>): void;
    function fun15(v1: Array<number>, callback: Callback<Array<number>>): void;
    function fun16(v1: Array<boolean>, callback: Callback<Array<boolean>>): void;
    function fun17(callback: Callback<Array<Test>>): void;
    function fun21(v: string, v1: Array<Entry>): Array<Entry>;
    /*function fun10(v1: { [key: string]: Array<Test> }): void;*/
}

export default napitest;

