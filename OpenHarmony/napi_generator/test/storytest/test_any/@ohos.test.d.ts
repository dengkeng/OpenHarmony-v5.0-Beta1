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
declare namespace napitest {
    interface TestClass1 {
        any1: any;
        /*  any类型的可选参数，暂不支持
        focused?: any;
        $def?: any;
        arr?: Array<any>;
        arr1?: any[];
        extraInfo?: { [key: string]: any };
        test?: (data: any, code: number) => void;
        */
    }

    export class Want {
        /*  any类型的可选参数，暂不支持
        parameters?: { [key: string]: any };
        */
        static Prop(propName: string): any;
    }

    function fun1(v: any, v1: string): number;
    function fun2(v: number, v1: TestClass1): number;
    function fun4(v: number, v1: Array<any>): number;
    function fun5(v: string, v1: any[]): number;
    function $fun6(v: boolean, param: Array<any>): number;
    function fun8(v1: string[], v?: any): number;
    
    /*function fun10(v: string, v1?: number | Array<any>): string;
    function fun7(v: string, v1: { [key: string]: any }): number;
    function fun3(v: string): any;
    function fun9(v: string, v1: { name: Array<any>, age: number }): number;*/
}

export default napitest;