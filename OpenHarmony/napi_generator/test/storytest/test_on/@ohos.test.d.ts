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
    class ModelEvent{
        topic: string;
        message: string;
    }

    function on(type: string, callback: Callback<number>): void;
    function off(type: string, callback?: Callback<number>): void;
    function on(type: string, callback: Callback<ModelEvent>): void; // Callback为interface
    function off(type: string, callback?: Callback<ModelEvent>): void;
    function on(type: string, callback: Callback<{topic:string,message:string}>): void; // Callback为匿名interface
    function off(type: string, callback?: Callback<{topic:string,message:string}>): void;
    // function on(type: string, callback: Callback<string>): void; // Callback为string
    function on(type: 'onEvents', callback: (wid: number) => void): void; // 箭头函数支持
    function off(type: 'onEvents', callback?: (wid: number) => void): void;
    function on(type: 'onEventFunc', callback: (wid: number, mol: ModelEvent) => void): void; // 箭头函数支持
    function off(type: 'onEventFunc', callback?: (wid: number, mol: ModelEvent) => void): void;

    class TestClass1 {
        on(type: string, callback: Callback<boolean>): void;
        off(type: string, callback?: Callback<boolean>): void;
    }

    class TestClass2 {
        on(type: string, callback: Callback<ModelEvent>): void; // Callback为interface
        off(type: string, callback?: Callback<ModelEvent>): void;
    }

    class TestClass3 {
        on(type: string, callback: Callback<{topic:string,message:string}>): void; // Callback为匿名interface
        off(type: string, callback?: Callback<{topic:string,message:string}>): void;
    }

    class TestClass4 {
        on(type: 'heartbeat', callback: (wid: boolean) => void): void; // 箭头函数支持
        off(type: 'heartbeat', callback?: (wid: boolean) => void): void; // 固定事件，去注册事件
    }

    class TestClass5 {
        on(type: 'inputStart', callback: (wid: boolean, modeEv: ModelEvent) => void): void; // 回调函数参数个数大于1，支持
        off(type: 'inputStart', callback?: (wid: boolean, modeEv: ModelEvent) => void): void;
    }

    class TestClass6 {
        on(type: string, asyncCallback: AsyncCallback<boolean>): void;
        off(type: string, asyncCallback?: AsyncCallback<boolean>): void;
    }

    class TestClass7 {
        on(type: string, asyncCallback: AsyncCallback<ModelEvent>): void; // Callback为interface
        off(type: string, asyncCallback?: AsyncCallback<ModelEvent>): void;
    }

    class TestClass10 {
        on(type: "heartbeat", callback: Callback<boolean>): void; // 固定事件，回调参数为boolean支持
        off(type: "hearbeat", callback?: Callback<boolean>): void;
        on(type: "enableChange", callback: Callback<ModelEvent>): void; // 固定事件，回调参数为ModelEvent支持
        off(type: "enableChange", callback?: Callback<ModelEvent>): void;
        on(type: string, asyncCallback: AsyncCallback<string>): void;
        off(type: string, asyncCallback?: AsyncCallback<string>): void;
        on(type: string, callback: (wid: number) => void): void; // 箭头函数支持
        off(type: string, callback?: (wid: number) => void): void; 
        // on(type: string, callback: (wid: boolean) => string): void; // 返回值待支持
        on(type: "inputStart", callback: (wid: boolean, modeEv: ModelEvent) => void): void; // 回调函数参数个数大于1，支持
        off(type: "inputStart", callback?: (wid: boolean, modeEv: ModelEvent) => void): void; 
    }

    interface TestClass11 {
        registerTestfunc11(cb: Function);
        unRegisterTestfunc11(cb: Function);

        registerTestfunc12(cb : (wid: number) => string);
        unRegisterTestfunc12(cb : (wid: number) => string);

        registerTestfunc13(cb : Callback<boolean>);
        unRegisterTestfunc13(cb : Callback<boolean>);
    }
    function registerNamespacefunc20(cb: Function);
    function unRegisterNamespacefunc20(cb: Function);

    function registerNamespacefunc21(cb : (wid: number) => string);
    function unRegisterNamespacefunc21(cb : (wid: number) => string);

    function registerNamespacefunc22(cb : Callback<boolean>);

    function unRegisterNamespacefunc22(cb : Callback<boolean>); 
    
    function registerNamespacefunc24(cb : (wid: ModelEvent) => string);
    function unRegisterNamespacefunc24(cb : (wid: ModelEvent) => string);

    export class NodeISayHello
    {
        addSayHelloListener(listener: NodeISayHelloListener);
        sayHello(from: string, to: string, sayType: SayType);
        removeSayHelloListener(listener: NodeISayHelloListener);
    }

    export class NodeISayHelloListener
    {
        onSayHelloStart(info: SayInfo);
        onSayHelloEnd(info: SayInfo);
    }

    export enum SayType
    {
        /** 0  主动说话 */
        kInitiative,
        /** 1  回应对方 */
        kResponse,
    }

    class TestClass12 {
        registerTestfunc14(cb: (wid: SayInfo, test: TestOptional) => void);
        unRegisterTestfunc14(cb: (wid: SayInfo, test: TestOptional) => void);
    }
    function registerNamespacefunc23(cb: (wid: SayInfo, test: TestOptional) => void);
    function unRegisterNamespacefunc23(cb: (wid: SayInfo, test: TestOptional) => void);
    
    export type SayInfo =
    {
        from: string;
        fromId?: number;
        content: string;
        saidTime?: string;
        isEnd?: boolean;
    }

    export interface TestOptional
    {
        v1: string;
        v2?: boolean;
        v3: number;
        v4?: string;
        v5?: number;
    }
}

export default napitest;
