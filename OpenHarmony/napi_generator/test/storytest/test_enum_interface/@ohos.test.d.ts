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
    enum WindowType {
        TYPE_APP,
        TYPE_SYSTEM_ALERT
    }

    interface WindowProperties {
        type: WindowType;
    }

    class NodeSayHello {
        interfaceFunc(v0: string, v1: WindowType): boolean;   // interface中的方法参数是枚举
    }

    export class NodeSayHi {
        classFunc(v0: WindowType, v1: number): string;   // Class中的方法参数是枚举
    }

    function enumParamFunc(v0: boolean, v1: WindowType): number;   // 方法参数是枚举
    function getProperties(callback: AsyncCallback<WindowProperties>): void;
}

export default napitest;