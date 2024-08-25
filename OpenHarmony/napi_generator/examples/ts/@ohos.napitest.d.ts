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
import { AsyncCallback, Callback } from './basic';
declare namespace napitest {

// 测试普通方法
function funcTest(v: boolean): string;

// 测试注册回调与调用回调
export class NodeISayHello
{
    // 注册object回调
    addSayHelloListener(listener: NodeISayHelloListener);
    // 注销object回调
    removeSayHelloListener(listener: NodeISayHelloListener);

    // register注册回调
    registerCallbackfunc(cb : (wid: number) => string);
    // unRegister注销回调
    unRegisterCallbackfunc(cb : (wid: number) => string);

    // 调用注册的object回调
    sayHello(from: string, to: string, sayType: SayType);
    // 调用register注册的回调
    sayHi(from: string, to: string, sayType: SayType);

    // promise回调
    sayHelloWithResponse(from: string, to: string, sayType: SayType): Promise<{result: number, errMsg: string, response: string}>;
    
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

export type SayInfo = 
{
    from: string;
    fromId?: number;
    to: string;
    toId?: number;
    content: string;
    saidTime: string;
    isEnd: boolean;
}
 
}

export default napitest;
