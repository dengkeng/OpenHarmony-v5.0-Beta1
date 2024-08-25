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
    // 函数单参数非嵌套场景
    function fun1(mancc: {name: string, age: number}): string;

    interface TestInterfaceAA {
        an: string;
        al: string;
    }  
    interface TestInterface {
        anchor: string;
        align: string;
        // interface域变量场景        
        left: { test1: string, test2: string };      
    } 

    class TestInterfaceBB{
        // 函数多参数非嵌套场景
        func1(name : string, fp3: {nm: string, age: number, flag: boolean}): string;

        // 函数返回值场景
        func2(input: string): { read: number; written: number; flag: boolean };

        // Promise返回值逗号场景
        func3(from: string, to: string): Promise<{result: number, errMsg: string, isT: boolean}>;

        // Promise返回值分号场景
        func4(from: string, to: string): Promise<{result: number; errMsg: string; isT: boolean}>;
    }

    function fun2(fp2: TestInterface): string;
    
    // 函数多参数非嵌套场景   
    function fun3(name : string, fp3: {nm: string, age: number}): string;

    // 函数返回值场景
    function fun4(input: string): { read: number; written: number };
    
    // 函数单参数嵌套场景
    function fun5(value: {xOffset: number, animation: { duration: number, curve: string}});

    // 函数多参数嵌套场景
    function fun6(nm: string, value: {xOffset: number, animation: { duration: number, curve: string}});

    // 暂不支持 分号场景
    function fun7(nm: string, value: {xOffset: number; animation: { duration: number; curve: string}});
    
    // Promise匿名interface返回值场景， 分号场景
    function fun8(from: string): Promise<{result: number; errMsg: string; isT: boolean}>;

    // Promise匿名interface返回值场景, 逗号场景
    function fun9(from: string): Promise<{result: number, errMsg: string, isT: boolean}>;
}

export default napitest;