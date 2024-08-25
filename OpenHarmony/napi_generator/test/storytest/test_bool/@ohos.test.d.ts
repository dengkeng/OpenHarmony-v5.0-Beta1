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
        age: boolean;
        height: boolean[];
        width: Array<boolean>;
    }
    function fun1(v: boolean): boolean;
    function fun2(v1: boolean, v2: boolean[]): boolean[];
    function fun3(v1: Array<boolean>, v2: boolean): Array<boolean>;
    function fun4(v: { [key: string]: boolean }): boolean;
    function fun5(v1: Map<string, boolean>, v2: boolean): boolean;
    function fun6(v1: number, callback: AsyncCallback<boolean>): void;
    function fun6(v1: number): Promise<boolean>;
    function fun7(v: number, v1: AsyncCallback<Array<boolean>>): void;
    function fun7(v: number): Promise<Array<boolean>>;
    function fun9(v1: number, callback: Callback<boolean>): void;
    function fun10(v1: Test): Test;
    /*function fun8(v1: number, callback: AsyncCallback<boolean[]>): void;
    function fun8(v1: number): Promise<boolean[]>;
    interface Test1 {
        address: { [key: string]: boolean };
        long: Map<string, boolean>;
    }*/
}

export default napitest;