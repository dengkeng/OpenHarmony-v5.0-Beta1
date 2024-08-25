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
    function fun1(v: number): number;
    function fun2(v1: number, v2: number[]): number[];
    function fun3(v1: Array<number>, v2: number): Array<number>;
    function fun4(v: { [key: string]: number }): number;
    function fun5(v1: Map<string, number>, v2: number): number;
    function fun6(v1: number, callback: AsyncCallback<number>): void;
    function fun6(v1: number): Promise<number>;
    function fun7(v: number, v1: AsyncCallback<Array<number>>): void;
    function fun7(v: number): Promise<Array<number>>;
    function fun9(v1: number, callback: Callback<number>): void;
    function fun10(v1: Test): Test;
    interface Test {
        age: number;
        height: number[];
        width: Array<number>;
    }

    /*function fun11(v1: Test1): Test;
    interface Test1 {
        address: { [key: string]: number };
        long: Map<string, number>;
    }
    function fun8(v1: number, callback: AsyncCallback<number[]>): void;
    function fun8(v1: number): Promise<number[]>;*/
}

export default napitest;
