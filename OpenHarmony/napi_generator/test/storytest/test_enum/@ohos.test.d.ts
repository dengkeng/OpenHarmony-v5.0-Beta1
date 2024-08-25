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
    export enum GrantStatus {
        PERMISSION_DEFAULT = "",
        PERMISSION_DENIED = "-1",
        PERMISSION_GRANTED = "2",
        PERMISSION_PASS = "3",
    }

    export enum LaunchReason {
        UNKNOWN = 0,
        START_ABILITY = 1,
        CALL = 2,
        CONTINUATION = 3,
    }

    export enum Action {
        ACTION_HOME = "ohos.want.action.home",
        ACTION_DIAL = "ohos.want.action.dial",
        ACTION_SEARCH = "ohos.want.action.search",
    }

    export enum PlayingState {
        STATE_NOT_PLAYING,
        STATE_PLAYING,
    }

    export enum PlayingTest
    {
        STATE_TEST_START,
        STATE_TEST_END,
    }

    export enum HttpStatus {
        STATUS0 = 0,
        STATUS1 = 500,
        STATUS2 = 503,
    }

    function fun1(v0: string, v1: GrantStatus): GrantStatus;
    function fun2(v0: number, v1: LaunchReason): LaunchReason;
    function fun3(v0: string, v1: Action): Action;
    function fun4(v0: number, v1: PlayingState): PlayingState;
    function fun5(V0: string, callback: Callback<LaunchReason>): void;
    function fun6(v0: string, callback: AsyncCallback<GrantStatus>): void;
    function fun6(v0: string): Promise<GrantStatus>;
    function fun8(v0: string): Promise<PlayingTest>;
    function fun9(v0: PlayingTest): string;
    function fun10(v: TestStatus): string;    
    function fun11(v: EnumString): string;
    function fun12(v: HttpStatus): number;

    /*function fun7(v0: LaunchReason[], v1: LaunchReason): number;  待支持*/

    // 数值型枚举
    export enum TestStatus
    {
        STATE_TEST_PERIOD_ONE,
        STATE_TEST_PERIOD_TWO,
        STATE_TEST_PERIOD_THREE,
        STATE_TEST_PERIOD_FOUR,
        STATE_TEST_PERIOD_FIVE,
        STATE_TEST_PERIOD_SIX,
    }

    // 字符型枚举
    export enum EnumString {
        ENUM_HOME = 'ohos.want.enum.home',
        ENUM_DIAL = 'ohos.want.enum.dial',
        ENUM_SEARCH = 'ohos.want.enum.search',
        ENUM_WIRELESS_SETTINGS = 'ohos.settings.enum.wireless',
    }
}

export default napitest;

