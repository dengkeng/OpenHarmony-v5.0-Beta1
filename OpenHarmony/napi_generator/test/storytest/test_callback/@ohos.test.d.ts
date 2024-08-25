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
    class TestClass1 {
        fun11(cb: Callback<number>): void;
        fun12(cb: Callback<void>): void;
        fun13(cb: AsyncCallback<number>): void;
        fun14(cb: AsyncCallback<void>): void;
        fun15(cb: Callback<number>): string;
        fun16(tt: Function): void;
        fun17(tt: Function): string;

        // 针对不同返回值类型测试
        fun110(cb: (wid: boolean) => string): string;
        fun111(cb: (wid: boolean) => string): boolean;
        fun112(cb: (wid: boolean) => string): number;
        // fun113(cb: (wid: boolean) => string): TestClass2; // 待支持
        // fun114(cb: (wid: boolean) => string): Human; // 待支持

        // 针对回调返回值类型测试
        fun210(cb: (wid: boolean) => string): boolean;
        fun211(cb: (wid: boolean) => boolean): string;
        fun212(cb: (wid: boolean) => number): string;
        // fun213(cb: (wid: boolean) => TestClass2): string;
        // fun214(cb: (wid: boolean) => Human): string;
    }

    interface TestClass2 {
        str: string;

    }

    export class Human {
        name: string;
        age: number;
    }

    function fun1(cb: Callback<number>): void;
    function fun2(cb: Callback<void>): void;
    function fun3(cb: AsyncCallback<number>): void;
    function fun4(cb: AsyncCallback<void>): void;
    function fun5(cb: Callback<number>): string; // to add testcase for return type is not void
    function fun6(tt: Function): void;
    function fun7(tt: Function): string;

    // 以下测试用例待增加测试用例 begin 
    function fun8(cb: (wid: boolean) => void): string;

    // 针对不同返回值类型测试
    function fun10nm(cb: (wid: boolean) => string): string;
    function fun11nm(cb: (wid: boolean) => string): boolean;
    function fun12nm(cb: (wid: boolean) => string): number;
    // function fun13nm(cb: (wid: boolean) => string): TestClass2; // 待支持
    // function fun14nm(cb: (wid: boolean) => string): Human; // 待支持

    // 针对回调返回值类型测试
    function fun20nm(cb: (wid: boolean) => string): boolean;
    function fun21nm(cb: (wid: boolean) => boolean): string;
    function fun22nm(cb: (wid: boolean) => number): string;
    // function fun23nm(cb: (wid: boolean) => TestClass2): string; // 待支持
    // function fun24nm(cb: (wid: boolean) => Human): string; // 待支持

    // // 以下测试用例待支持 
    
    function fun9(cb: (wid: boolean, str: string, tc2:number) => string): string;
    
    // function fun9(cb: (wid: boolean, str: string, tc2:TestClass2) => string): string; // 回调函数参数个数大于1，待支持
}

export default napitest;
