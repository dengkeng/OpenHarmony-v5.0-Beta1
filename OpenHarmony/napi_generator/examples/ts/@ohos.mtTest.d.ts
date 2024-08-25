/*
* Copyright (c) 2023 Shenzhen Kaihong Digital Industry Development Co., Ltd. 
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

  export class A {
    a: string;
  }

  export interface InterfaceA {
    // callFunction: (result: number) => void;
    onCallFunction(res: number): void;
  }

  // export const addByClass: (a: A, b: number, callback: (result: number) => void, c: InterfaceA) => number;

  export interface InterfaceB {
    // register形式注册回调
    registerInterfaceB(callback: (dd: number) => void); 
    // unRegister形式注销回调
    unRegisterInterfaceB(callback: (dd: number) => void); 

    // object注册回调
    addInterfaceAListener(listener: InterfaceA);
    removeInterfaceAListener(listener: InterfaceA);

    // 调用回调 
    gByClass: (a: A, b: number) => number;  
  }
 
}

export default napitest;
