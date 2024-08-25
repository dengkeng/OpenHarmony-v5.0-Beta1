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
    export class Image {
        width: number;
        height: number;
        toDataURL(type?: string, quality?: number): string;
    }

    export class Human {
        name: string;
        age: number;
    }

    // 变换括号位置
    class Man 
    {
        name: string;
        age: number;
    }

    // 有参构造函数的转换,成员变量包含数值型枚举
    export class Woman {
      constructor(name_: string, age_: number, isMarried_: boolean, status_: TestStatus);
      w_name: string;
      w_age: number;
      w_isMarried: boolean;
      w_status: TestStatus;
    }

    // 有参构造函数的转换，成员变量包含字符型枚举
    export class Child {
      constructor(name_: string, age_: number, status_: TestEnumString);
      w_name: string;
      w_age: number;
      w_status: TestEnumString;
    }

    export enum LaunchReason {
        UNKNOWN = 0,
        START_ABILITY = 1,
        CALL = 2,
        CONTINUATION = 3,
    }

    export class TestClass1 {
        ahuman: Human;
        fun1(v: number): number;
        fun2(numcc: Array<number>, mancc: Human): Human;
        fun3: (v: number, v1: string, v2: boolean) => boolean;
        fun4: (mancc: Map<string, string>,v?: string) => Array<number>;
        fun5: (data: Array<Human>) => Human;
        fun6: (v: string[], v1: { [key: string]: boolean }) => string[];
        fun8: () => void;
        fun9(manA: Man): string;
        fun10(v: Image): string;
        
        //参数为enum
        fun11(v: LaunchReason): string;
        fun12(v: TestStatus): string;
        fun13(v: TestEnumString): string;

        // return value is enum type of defined later
        // to support
        // fun14(v: string): ReturnStatus; 
        // fun15(v: string): ReturnEnumString;

        /*fun7: (v: string, v1: LaunchReason) => LaunchReason;  --待支持*/
    }

    // class 定义在使用之后 begin
    function func4(v: TestClassLater): string;

    export class TestClassUse {
        v0: string;
        // v1: testClassLater;
        funceUse(n0: TestClassLater): string;
    }

    export class TestClassLater {
        v0: string;
        v1: number;
        funcLater(n0: number): string;
    }
    // class 定义在使用之后 end

    // 数值型枚举
    export enum TestStatus {
        UNKNOWN = 0,
        START_ABILITY = 1,
        CALL = 2,
        CONTINUATION = 3,
    }

    // 字符型枚举
    export enum TestEnumString {
        ACTION_HOME = 'ohos.want.action.home',
        ACTION_DIAL = 'ohos.want.action.dial',
        ACTION_SEARCH = 'ohos.want.action.search',
        ACTION_WIRELESS_SETTINGS = 'ohos.settings.wireless',
    }

    // 数值型枚举
    export enum ReturnStatus {
        UNKNOWN = 0,
        START_RETURN = 1,
        MIDDLE_RETURN = 2,
        END_RETURN = 3,
    }

    // 字符型枚举
    export enum ReturnEnumString {
        RETURN_HOME = 'ohos.want.return.home',
        RETURN_DIAL = 'ohos.want.return.dial',
        RETURN_SEARCH = 'ohos.want.return.search',
        RETURN_WIRELESS_SETTINGS = 'ohos.settings.return.wireless',
    }

    export class TestClass2 {
        // 函数多参数非嵌套场景
        func1(name : string, fp3: {nm: string, age: number, flag: boolean}): string;

        // 函数返回值场景
        func2(input: string): { read: number; written: number; flag: boolean };

        // Promise返回值逗号场景
        func3(from: string, to: string): Promise<{result: number, errMsg: string, isT: boolean}>;

        // Promise返回值分号场景
        func4(from: string, to: string): Promise<{result: number; errMsg: string; isT: boolean}>;

        // class成员方法隐式推导返回值
        func5(v1: string, v2: number, v3: boolean);
    }

    // class 成员变量包含enum类型，且class成员方法自引用
    export enum Type
    {
        typeA,
        typeB,
        typeC
    }
  
    export class Test {
        type: Type;
        func(param: Type): boolean;
    }
  
    export interface aa {
        abc: string;
        def: number;
    }
  
    export class Demo {
        equals(other: Demo): boolean;
        handleCallback(): void;
  
        intPro: number;
        strPro: string;
        boolPro: boolean;
        inter: aa;
        type: Type;
    }
  
    function funcTest(v: Type): boolean; // enum为参数
    function funcTest2(v: Test): boolean;  // 包含enum成员变量的 class 为参数
}

export default napitest;
