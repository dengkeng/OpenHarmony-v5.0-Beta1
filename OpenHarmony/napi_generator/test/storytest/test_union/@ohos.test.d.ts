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
    interface TestClass1 {
        union1: string | number | boolean;
    }

    function fun1(v: number | string | boolean): string;
    function fun2(v0: string, v: number | string | boolean): string;
    function fun3(v0: string, v: number | string | boolean, no: number): string;
    /*
    function fun2(v?: Object | Array<any>): number;   -- 待实现
    function fun3(v: Array<string | number | boolean>): number;  -- 待实现
    function fun4(v: { [key: string]: number | string | boolean }): number;   -- 待实现
    function fun5(v: { [key: string]: Test | Array<string | number | boolean> })  -- 待实现
    function fun6(v: Test | string): number;    -- 待实现
    function fun7(v: ResponseCode | string): number;    -- 待实现
    function fun8(v: string, v1: { name: string | boolean | number, age: number }): number;  -- 待实现
    function fun9(v: string, v1: AsyncCallback<string | boolean | number | Test>): void;  -- 待实现
    function fun9(key: string): Promise<string | boolean | number | Test>;
    function fun9(v: string, v1: AsyncCallback< Array<string | number | boolean>>): void;  -- 待实现
    function fun9(key: string): Promise<Array<string | number | boolean>>;*/
}

export default napitest;