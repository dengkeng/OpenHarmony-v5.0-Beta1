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
    interface DataInfo {
        dataName: string;
        dataIndex: number;
    }

    export enum EOptions {
        OPTION0 = 0,
        OPTION1 = 500,
        OPTION2 = 503,
    }

    class TestClass1 {
        fun10(): Promise<void>;
        fun11(): Promise<number>;
        fun12(): Promise<boolean>;
        fun13(): Promise<string>;
        fun14(v1: number): Promise<DataInfo>;
        fun15(v1: number): Promise<DataInfo>;
        fun16(v1: number): Promise<Array<string>>;

        funX11(v1: number, v2: string, cb: AsyncCallback<string>): void;
        funX11(v1: number, v2: string, ): Promise<string>;

        funX12(v1: number, v2: string, ): Promise<number>;
        funX12(v1: number, v2: string, cb: AsyncCallback<number>): void;
    }

    function fun0(): Promise<void>;
    function fun1(): Promise<number>;
    function fun2(): Promise<boolean>;
    function fun3(): Promise<string>;
    function fun4(v1: number): Promise<DataInfo>;
    function fun5(v1: number): Promise<EOptions>;
    function fun6(v1: number): Promise<Array<string>>;

    function funX1(v1: number, v2: string, cb: AsyncCallback<string>): void;
    function funX1(v1: number, v2: string): Promise<string>;

    function funX2(v1: number, v2: string): Promise<number>;
    function funX2(v1: number, v2: string, cb: AsyncCallback<number>): void;
}

export default napitest;
