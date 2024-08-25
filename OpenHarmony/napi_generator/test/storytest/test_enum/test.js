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
const { fun1, fun2, fun3 } = require("./out/build/Release/napitest")
const { fun4, fun5, fun6 } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");

describe('enum', function () {
    // function fun1(v0: string, v1: GrantStatus): GrantStatus;
    it('test fun1', function () {
        let ret = fun1('aaaa', test.GrantStatus.PERMISSION_DENIED);
        assert.strictEqual(ret, test.GrantStatus.PERMISSION_DEFAULT);
    });

    // function fun2(v0: number, v1: LaunchReason): LaunchReason;
    it('test fun2', function () {
        let ret = fun2(18, test.LaunchReason.START_ABILITY);
        assert.strictEqual(ret, test.LaunchReason.UNKNOWN);
    });

    // function fun3(v0: string, v1: Action): Action;
    it('test fun3', function () {
        let ret = fun3('ggg', test.Action.ACTION_DIAL);
        assert.strictEqual(ret, '');
    });

    // function fun4(v0: number, v1: PlayingState): PlayingState;
    it('test fun4', function () {
        let ret = fun4(18, test.PlayingState.STATE_PLAYING);
        assert.strictEqual(ret, 0);
    });

    function abc(ret) {
        assert.deepStrictEqual(ret, test.LaunchReason.UNKNOWN);
    }

    // function fun5(V0: string, callback: Callback<LaunchReason>): void;
    it('test fun5', function () {
        fun5('aaa', abc);
    });

    function asynFun1(err, ret) {
        assert.deepStrictEqual(err.code, 0)
        assert.deepStrictEqual(ret, '')
    }

    // function fun6(v0: string, callback: AsyncCallback<GrantStatus>): void;
    it('test fun6_callback', function () {
        fun6('hhh', asynFun1);
        fun6('hhh').then(def1);
    });

    function def1(ret) {
        assert.deepStrictEqual(ret, '');
    }

    // function fun6(v0: string): Promise<GrantStatus>;
    it('test fun6_promise', function () {
        let promiseObj = fun6('hhh');
        promiseObj.then(ret => { def1(ret) });
    });
});

describe('enum second part', function () {
    function def2(ret) {
        assert.deepStrictEqual(ret, 0);
    }

    // function fun8(v0: string): Promise<PlayingTest>;
    it('test fun8_promise', function () {
        let promiseObj = test.fun8('test');
        promiseObj.then(ret => { def2(ret) });
    });

    // function fun9(v0: PlayingTest): string;
    it('test fun9', function () {
        let ret = test.fun9(test.PlayingTest.STATE_TEST_START);
        assert.strictEqual(ret, '');
    });

    // function fun10(v: TestStatus): string;
    it('test fun10', function () {
        let ret = test.fun10(test.PlayingTest.STATE_TEST_START);
        assert.strictEqual(ret, '');
    })

    // function fun11(v: EnumString): string;
    // export enum EnumString {
    //     ENUM_HOME = 'ohos.want.enum.home',
    //     ENUM_DIAL = 'ohos.want.enum.dial',
    //     ENUM_SEARCH = 'ohos.want.enum.search',
    //     ENUM_WIRELESS_SETTINGS = 'ohos.settings.enum.wireless',
    // }    
    it('test fun11', function () {
        let ret = test.fun11(test.EnumString.ENUM_SEARCH);
        assert.strictEqual(ret, '');
    })

    // function fun12(v: HttpStatus): number;
    it('test fun12', function () {
        let ret = test.fun12(test.HttpStatus.STATUS0);
        assert.strictEqual(ret, 0);
    });
});

// Input exception testing
describe('enum third part', function () {
    // function fun1(v0: string, v1: GrantStatus): GrantStatus;
    it('test fun1 exception ', function () {
        let ret2 = false;
        try {
            let ret = fun1('aaaa', "bbbb");
        } catch (err) {
            ret2 = true;
            console.info("err: "+ err)
        }
        assert.strictEqual(ret2, true)
    });

    // function fun2(v0: number, v1: LaunchReason): LaunchReason;
    it('test fun2 exception', function () {
        let ret3 = false;
        try {
            let ret = fun2(18, 9);
        } catch (err) {
            ret3 = true;
            console.info("err: "+ err)
        }
        assert.strictEqual(ret3, true)
    });

    // function fun3(v0: string, v1: Action): Action;
    it('test fun3 exception', function () {
        let ret2 = false;
        try {
            let ret = fun3('ggg', 'ccc');
        } catch (err) {
            ret2 = true;
            console.info("err: "+ err)
        }
        assert.strictEqual(ret2, true)
    });

    // function fun4(v0: number, v1: PlayingState): PlayingState;
    it('test fun4 exception', function () {
        let ret3 = false;
        try {
            let ret = fun4(18, 8);
        } catch (err) {
            ret3 = true;
            console.info("err: "+ err)
        }
        assert.strictEqual(ret3, true)
    });

    // function fun12(v: HttpStatus): number;
    it('test fun12 exception', function () {
        let ret3 = false;
        try {
            let ret = test.fun12(2);
        } catch (err) {
            ret3 = true;
            console.info("err: "+ err)
        }
        assert.strictEqual(ret3, true)
    });

})

