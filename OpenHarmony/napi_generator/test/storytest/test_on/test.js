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
const { TestClass1, TestClass2, ModelEvent, TestClass3, on, off, TestClass4, TestClass5,
  TestClass6, TestClass7, TestClass10, TestClass11, TestClass12} = require("./out/build/Release/napitest")
const testObj = require("./out/build/Release/napitest")
var assert = require("assert");

describe('test 1 on', function () {  
    let ret = false;
    let inter = new ModelEvent({topic:'aa', message:'sit down'});
    function onCallback(val) {
        ret = true;
        console.info('onAsyncCallback val = ' + val)
        console.info('onAsyncCallback ret = ' + ret)
    }

    function onCallback2(inter) {
        ret = true;
        console.info('onCallback inter.topic = ' + inter.topic)
        console.info('onCallback inter.message = ' + inter.message)
    }

    let topic = 'hh';
    let message = 'jjj';
    function onCallbackTest3({topic, message}) {
        ret = true;
        console.info('onCallback topic = ' + topic)
        console.info('onCallback message = ' + message)
    }

    // interface TestClass1 {
    //     on(type: string, callback: Callback<boolean>): void; 
    // }
    let tc1 = new TestClass1(); 
    it('test TestClass1 on', function () {
        ret = false;
        tc1.on('OnEvent', onCallback);
        tc1.off('OnEvent', onCallback);
    });

    // interface ModelEvent{
    //     topic: string;
    //     message: string;
    // }
    // interface TestClass2 {
    //     on(type: string, callback: Callback<ModelEvent>): void; // Callback为interface
    // }
    let tc2 = new TestClass2(); 
    it('test TestClass2 on', function () {
        ret = false;
        tc2.on('OnEvent', onCallback2);
        tc2.off('OnEvent', onCallback2);
    });

    // interface TestClass3 {
    //     on(type: string, callback: Callback<{topic:string,message:string}>): void; // Callback为匿名interface
    // }
    let tc3 = new TestClass3(); 
    it('test TestClass3 on', function () {
        ret = false;
        tc3.on('OnEvent', onCallbackTest3);
        tc3.off('OnEvent', onCallbackTest3);
    });
});

describe('test 2 on', function () {
    let ret = false;
    let inter = new ModelEvent({topic:'aa', message:'sit down'});
    function onCallback(val) {
        ret = true;
        console.info('onCallback err = ' + val)
        console.info('onCallback ret = ' + ret)
    }

    function onCallback2(val, inter) {
        ret = true;
        console.info('onCallback2 val = ' + val)
        console.info('onCallback2 inter.topic = ' + inter.topic)
        console.info('onCallback2 inter.message = ' + inter.message)
    }
    
    // interface TestClass4 {
    //   on(type: "heartbeat", callback: (wid: boolean) => void): void; // 箭头函数支持
    // }
    let tc4 = new TestClass4(); 
    it('test TestClass4 on', function () {
        ret = false;
        tc4.on('heartbeat', onCallback);
        tc4.off('heartbeat', onCallback);
    });

    // interface TestClass5 {
    //   on(type: "inputStart", callback: (wid: boolean, modeEv: ModelEvent) => void): void // 回调函数参数个数大于1，支持
    // }
    let tc5 = new TestClass5(); 
    it('test TestClass5 on', function () {
        ret = false;
        tc5.on('inputStart', onCallback2);
        tc5.off('inputStart', onCallback2);
    });

    // namespace域中有多个on function
    // function on(type: "onEvents", callback: (wid: number) => void): void; // 箭头函数支持
    it('test function on', function () {
      ret = false;
      on('onEvents', onCallback);
      off('onEvents');
      ret = false;
      on('onEventFunc', onCallback2);
      off('onEventFunc', onCallback2);
    });
});

describe('test 3 on', function () {
    let ret = false;
    let inter = new ModelEvent({topic:'aa', message:'sit down'});
    function onCallback(val) {
      ret = true;
      console.info('onCallback val = ' + val)
      console.info('onCallback ret = ' + ret)
    }

    function onCallback2(inter) {
      ret = true;
      console.info('onCallback2 inter.topic = ' + inter.topic)
      console.info('onCallback2 inter.message = ' + inter.message)
    }

    function onCallback3(val, inter) {
      ret = true;
      console.info('onCallback3 val = ' + val)
      console.info('onCallback3 inter.topic = ' + inter.topic)
      console.info('onCallback3 inter.message = ' + inter.message)
    }

    // interface TestClass6 {
    //   on(type: string, asyncCallback: AsyncCallback<boolean>): void;
    // }
    let tc6 = new TestClass6(); 
    it('test TestClass6 on', function () {
        ret = false;
        tc6.on('test1', onCallback);
        tc6.off('test1', onCallback);
    });
  
    // interface TestClass7 {
    //   on(type: string, asyncCallback: AsyncCallback<ModelEvent>): void; // Callback为interface
    // }
    let tc7 = new TestClass7();
    it('test TestClass7 on', function () {
        ret = false;
        tc7.on('test2', onCallback2);
        tc7.off('test2', onCallback2);
    });

    // interface中有多个on
    let tc10 = new TestClass10(); 
    it('test TestClass10 on', function () {
        // on(type: "heartbeat", callback: Callback<boolean>): void;
        ret = false;
        tc10.on('heartbeat', onCallback);
        tc10.off('heartbeat');

        // on(type: "enableChange", callback: Callback<ModelEvent>): void;
        ret = false;
        tc10.on('enableChange', onCallback2);
        tc10.off('enableChange');

        // on(type: string, asyncCallback: AsyncCallback<string>): void;
        ret = false;
        tc10.on('test01', onCallback);
        tc10.off('test01');

        // on(type: string, callback: (wid: number) => void): void;
        ret = false;
        tc10.on('test02', onCallback);
        tc10.off('test02');

        // on(type: "inputStart", callback: (wid: boolean, modeEv: ModelEvent) => void): void 
        ret = false;
        tc10.on('inputStart', onCallback3);
        tc10.off('inputStart');
    });
});

describe('test register/unRegister', function () {
    // function registerNamespacefunc20(cb: Function);
    // function unRegisterNamespacefunc20(cb: Function);

    // function registerNamespacefunc21(cb : (wid: number) => string);
    // function unRegisterNamespacefunc21(cb : (wid: number) => string);

    // function registerNamespacefunc22(cb : Callback<boolean>);
    // function unRegisterNamespacefunc22(cb : Callback<boolean>);   

    // cb: (wid: number) => string
    function onCallbackfun10nm(wid) {
        return 'fun10nm'
    }

    it('test registerNamespacefunc21', function () {        
        testObj.registerNamespacefunc21(onCallbackfun10nm);
    });

    it('test unRegisterNamespacefunc21', function () {        
        testObj.unRegisterNamespacefunc21(onCallbackfun10nm);
    });

    it('test TestClass11 registerTestfunc12', function () {
        let tc11 = new TestClass11();       
        tc11.registerTestfunc12(onCallbackfun10nm);
    });
    
});

// interface TestClass11 {
//     registerTestfunc11(cb: Function);
//     unRegisterTestfunc11(cb: Function);

//     registerTestfunc12(cb : (wid: number) => string);
//     unRegisterTestfunc12(cb : (wid: number) => string);

//     registerTestfunc13(cb : Callback<boolean>);
//     unRegisterTestfunc13(cb : Callback<boolean>);
// }

function callbackTest14(ret1, ret2) {
    console.info("SayInfo.from = " + ret1.from)
    console.info("SayInfo.fromId = " + ret1.fromId)
    console.info("SayInfo.content = " + ret1.content)
    console.info("SayInfo.saidTime = " + ret1.saidTime)
    console.info("SayInfo.isEnd = " + ret1.isEnd)
    console.info("TestOptional.v1 = " + ret2.v1)
    console.info("TestOptional.v2 = " + ret2.v2)
    console.info("TestOptional.v3 = " + ret2.v3)
    console.info("TestOptional.v4 = " + ret2.v4)
    console.info("TestOptional.v5 = " + ret2.v5)
}

// interface TestClass12 {
//   registerTestfunc14(cb: (wid: SayInfo, test: TestOptional) => void);
//   unRegisterTestfunc14(cb: (wid: SayInfo, test: TestOptional) => void);
// }
// function registerNamespacefunc23(cb: (wid: SayInfo, test: TestOptional) => void);
// function unRegisterNamespacefunc23(cb: (wid: SayInfo, test: TestOptional) => void);
describe('test register/unRegister callback interface/type param is optional', function () {
    let tc12 = new TestClass12();      
    it('test TestClass12 registerTestfunc14', function () {
        tc12.registerTestfunc14(callbackTest14);
    });

    it('test TestClass12 unRegisterTestfunc14', function () {
        tc12.unRegisterTestfunc14(callbackTest14);
    });

    it('test function registerNamespacefunc23', function () {
        testObj.registerNamespacefunc23(callbackTest14);
    });

    it('test function unRegisterNamespacefunc23', function () {
        testObj.unRegisterNamespacefunc23(callbackTest14);
    });
    
});

class NodeISayHelloListenerImpl {
    onSayHelloStart(info) {
      console.log('----onSayHelloStart XXX', info);
    }
    onSayHelloEnd(info) {
      console.log('----onSayHelloEnd abc.', info);
    }
}

function onSayHelloStart(info) {
    console.log('----aaa bbb ccc onSayHelloStart xxx', info);
}

describe('test Obj callback', function () {
    let nis = new testObj.NodeISayHello();
    let lis = new NodeISayHelloListenerImpl();
    // 注册回调
    it('test NodeISayHello addSayHelloListener', function () {
        nis.addSayHelloListener(lis);
    });

    it('test NodeISayHello sayHello', function () {
        nis.sayHello("js", "native", testObj.SayType.kInitiative);
    });

    it('test NodeISayHello removeSayHelloListener', function () {
        nis.removeSayHelloListener(lis);
    });

    it('test NodeISayHello sayHello not reg', function () {
        nis.sayHello("js", "native", testObj.SayType.kInitiative);
    });    
});

