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
        key: number[];
        value: string[];
        isExit: boolean[];
    }

    function testArray(v: string[]): string[];
    function testArray1(v: number[]): number[];
    function testArray2(v: boolean[]): boolean[];
    function fun4(v1: string[], v2: Test[]): number[];
    function fun5(v1: number[], v2: Test[]): string[];
    function fun6(v1: boolean[], v2: Test[]): boolean[];
    function fun21(v: string, v1: Entry[]): Entry[];

    /*  ----以下接口，当前工具不支持，Aarray<>书写方式支持
    function fun1(v1: string[], v2: AsyncCallback<string[]>): void;
    function fun1(v1: string[]): Promise<string[]>;
    function fun2(v1: number[], v2: AsyncCallback<number[]>): void;
    function fun2(v1: number[]): Promise<number[]>;
    function fun3(v1: boolean[], v2: AsyncCallback<boolean[]>): void;
    function fun3(v1: boolean[]): Promise<boolean[]>;
    function fun7(v0: string[], v1: { [key: string]: string[] }): number;
    function fun8(v0: number[], v1: { [key: string]: number[] }): number;
    function fun9(v0: boolean[], v1: { [key: string]: boolean[] }): number;
    function fun10(v1: { [key: string]: Test[] }): void;
    function fun11(v1: Map<string, string[]>): number;
    function fun12(v1: Map<string, number[]>): string;
    function fun13(v1: Map<string, boolean[]>): boolean;
    function fun14(v1: string[], callback: Callback<string[]>): void;
    function fun15(v1: number[], callback: Callback<number[]>): void;
    function fun16(v1: boolean[], callback: Callback<boolean[]>): void;
    function fun17(callback: Callback<Test[]>): void;
    function fun18(v2: AsyncCallback<Test[]>): void;
    function fun18(): Promise<Test[]>;*/
}

export default napitest;