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
    interface Human {
        name: string;
        age: number;
        isTrue: boolean;
    }

    interface TestClass1 {
        map1 : {[key: string]: {[key: string]: string}} ;
        map2 : Map<string,Human> ;
        //map3: {[key: string]: Object} // to support
        //map3: {[key: string]: object} // to support
    }

    class TestClass2 {
        fun1(v: {[key: string]: string},v1:string):  number;
        fun2(v: {[key: string]: number}):  number;
        fun3(v: {[key: string]: boolean}):  number;
        fun4(v: {[key: string]: Array<string>}):  number;
        fun5(v: {[key: string]: Array<number>}):  number;
        fun6(v: {[key: string]: Array<boolean>}):  number;
        fun7(v: {[key: string]: {[key: string]: string}}):  number;
        fun8(v: Map<string,Map<string,string>>):  number;
        fun9(v: {[key: string]: Human}):  number;
        fun10(v: Map<string,Human>):  number;
        fun11(v: Map<string,any>):  number;
    }
    
   function fun13(v: {[key: string]: string[]}):  number;   
   function fun18(v: Map<string,string[]>):  number;

   
   /*
   function fun14(v: number): {[key: string]: string[]}; --暂时不支持
   function fun15(v: number):Map<string,string[]> --暂时不支持
   */
   
}
export default napitest;