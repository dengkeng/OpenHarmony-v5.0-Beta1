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
    /*    
    export interface testInerface {
        code: number;
        data: string;
    }
    export interface testMapInerface {
        tset1: map<string, Array<testInerface>>; -- 待实现    }

    function fun7(v: Array<{[key: string]:testInerface}>): number; -- 待实现
    function fun10(v: Array<map<string, testInerface>>): number; -- 待实现
    function fun11(v: Array<map<string, testInerface>>): number; -- 待实现
    function fun17(v: Array<map<string, Array<testInerface>>>): number; -- 待实现

    --not support--
    function fun4(v: Array<{[key: string]:Object}>): number; -- 参数、返回值暂时不支持
    function fun5(v: Array<{[key: string]:[]}>): number; -- ohos中无此类用法，暂不实现
    function fun6(v: Array<{[key: string]:any}>): number; -- 依赖于参数、返回值any类型

    function fun13(v: {[key: string]:any}[]): number; --ohos中无此类用法，暂不实现
    function fun14(v: {[key: string]:any}[]): number; --ohos中无此类用法，暂不实现
    function fun15(v: map<string, string>[]): number; --ohos中无此类用法，暂不实现
    function fun15(v: string): map<string, string>[]; --ohos中返回值类型为 map数组，无此类用法，暂不实现
    */
   
    function fun1(v: Array<{[key: string]:string}>): number;
    function fun2(v: Array<{[key: string]:number}>): number;
    function fun3(v: Array<{[key: string]:boolean}>): number;

    function fun8(v: Array<Map<string, string>>): number;
    function fun9(v: Array<Map<string, number>>): number;
    function fun10(v: Array<Map<string, boolean>>): number;    
}

export default napitest;