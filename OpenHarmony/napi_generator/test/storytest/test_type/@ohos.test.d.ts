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
  type Plant = {
    tomato: string;
    tomatoId: number;
    isTomato: boolean;
    // potato?: string;  //不支持可选参数
    // potatoId?: number;
    // isPotato?: boolean;
  }

  type Flower = 
  {
    name: string;
    Id: number;
    isMoreFlower: boolean;
  }

  type MyString = string;
  type MyNumberType = number;
  type MyBool = boolean;
  type MyUnion = string | number | boolean;
  type MyEnumType = 'keyup' | 'keydown';

  class Animal {
    cat: string;
    isCat: boolean;

    catFunc1(v: MyString): MyString;
    catFunc2(v: MyNumberType): MyNumberType;
    catFunc3(v: MyBool): MyBool;
    catFunc4(v: Plant): string;
    catFunc5(v: number): Plant;
  }

  function fun1(v: Plant): number;
  function fun2(v: boolean): Plant;
  function fun3(v0: MyString, v1: MyNumberType, v2: MyBool): boolean;
  function fun4(v: string): MyString;
  function fun5(v: number): MyNumberType;
  function fun6(v: boolean): MyBool;
  function fun7(v: MyUnion): number;
  function fun8(v: MyEnumType): string;
  function fun9(v: Flower): string;

  type OptionalTest = 
  {
    ttt: number;
    param1?: string;
    param2?: number;
    param3?: boolean;
    param4?: Array<number>;
    param5?: string[];
    param6: Array<boolean>;
    param7?: Map<string, string>;
    param8?: {[key: string]: number};
    param9: Map<string, boolean>;
    param10?: boolean | number | string;
  }

  function fun10(v: OptionalTest): string;
}

export default napitest;

