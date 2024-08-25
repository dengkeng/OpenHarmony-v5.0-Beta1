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
const { Animal } = require("./out/build/Release/napitest")
const test = require("./out/build/Release/napitest")
var assert = require("assert");
const { consumers } = require("stream");

describe('type function', function () {  
  // function fun1(v: Plant): number;
  it('test fun1', function () {
    let ret = test.fun1({ tomato: 'iutluhkd', tomatoId: 52, isTomato: true });
    assert.deepStrictEqual(ret, 0);
  });

  // function fun2(v: boolean): Plant;
  it('test fun2', function () {
    let ret = test.fun2(true);
    let retJson = JSON.stringify(ret);
    assert.strictEqual(retJson, '{"tomato":"","tomatoId":0,"isTomato":false}');
  });

  // function fun3(v0: MyString, v1: MyNumberType, v2: MyBool): boolean;
  it('test fun3', function () {
    let ret = test.fun3('missssss', 24, false);
    assert.deepStrictEqual(ret, false);
  });

  // function fun4(v: string): MyString;
  it('test fun4', function () {
    let ret = test.fun4('aaa');
    assert.deepStrictEqual(ret, '');
  });

  // function fun5(v: number): MyNumberType;
  it('test fun5', function () {
    let ret = test.fun5(22);
    assert.deepStrictEqual(ret, 0);
  });

  // function fun6(v: boolean): MyBool;
  it('test fun6', function () {
    let ret = test.fun6(true);
    assert.deepStrictEqual(ret, false);
  });

  // function fun7(v: MyUnion): number;
  it('test fun7', function () {
    let ret = test.fun7(true);
    assert.deepStrictEqual(ret, 0);
    let ret2 = test.fun7(16);
    assert.deepStrictEqual(ret2, 0);
    let ret3 = test.fun7('fun7');
    assert.deepStrictEqual(ret3, 0);
  });

  // function fun8(v: MyEnumType): string;
  it('test fun8', function () {
    let ret = test.fun8('keyup');
    assert.deepStrictEqual(ret, '');
    let ret2 = test.fun8('keydown');
    assert.deepStrictEqual(ret2, '');
  });

  // function fun9(v: Flower): string;
  // type Flower = 
  // {
  //   name: string;
  //   Id: number;
  //   isMoreFlower: boolean;
  // }
  it('test fun9', function () {
    let ret = test.fun9({ name: 'mudan', Id: 10, isMoreFlower: true });
    assert.deepStrictEqual(ret, '');
    let ret2 = test.fun9({ name: 'gouweicao', Id: 20, isMoreFlower: false });
    assert.deepStrictEqual(ret2, '');
  });
});

describe('Type Function', function () {
    // type OptionalTest = 
    // {
    //   ttt: number;
    //   param1?: string;
    //   param2?: number;
    //   param3?: boolean;
    //   param4?: Array<number>;
    //   param5?: string[];
    //   param6: Array<boolean>;
    //   param7?: Map<string, string>;
    //   param8?: {[key: string]: number};
    //   param9: Map<string, boolean>;
    //   param10?: boolean | number | string;
    // }
    // function fun10(v: OptionalTest): string;
    it('test fun10', function () {
        let ret = test.fun10(
            { ttt: 11, param1: "param", param2: 20, param3: false,
              param6: [true, false], param9: {'map': false}});
        assert.deepStrictEqual(ret, '');
        let ret2 = test.fun10(
            { ttt: 11, param1: "param", param3: false,
              param6: [true, false], param9: {'map': false}});
        assert.deepStrictEqual(ret2, '');
        let ret3 = test.fun10(
            { ttt: 11, param1: "param",
              param6: [true, false], param9: {'map': false}});
        assert.deepStrictEqual(ret3, '');
        let ret4 = test.fun10({ ttt: 11, param6: [true, false], param9: {'map': false}});
        assert.deepStrictEqual(ret4, '');
        let ret5 = test.fun10(
            { ttt: 11, param6: [true, false], param9: {'map': false},
              param4: [1,2,3], param5: ["aa", "bb", "cc"]});
        assert.deepStrictEqual(ret5, '');
        let ret6 = test.fun10(
            { ttt: 11, param6: [true, false], param9: {'map': false},
              param7: {'map7': 'value7'}, param8: {'map': 8}});
        assert.deepStrictEqual(ret6, '');
        let ret7 = test.fun10(
            { ttt: 11, param6: [true, false], param9: {'map': false},
              param10: 54});
        assert.deepStrictEqual(ret7, '');
    });
});

describe('Interface', function () {
  // catFunc1(v: MyString): MyString;
  it('test Animal catFunc1', function () {
      let tc1 = new Animal();
      let ret = tc1.catFunc1('cat');
      assert.deepStrictEqual(ret, '');
  });

  // catFunc2(v: MyNumberType): MyNumberType;
  it('test Animal catFunc2', function () {
      let tc = new Animal();
      let ret = tc.catFunc2(23);
      assert.deepStrictEqual(ret, 0);
  });

  // catFunc3(v: MyBool): MyBool;
  it('test Animal catFunc3', function () {
      let tc = new Animal();
      let ret = tc.catFunc3(true);
      assert.deepStrictEqual(ret, false);
  });

  // catFunc4(v: Plant): string;
  it('test Animal catFunc4', function () {
      let tc = new test.Animal();
      let ret = tc.catFunc4({ tomato: 'ImageTomato', tomatoId: 12, isTomato: true });
      assert.deepStrictEqual(ret, '');
  });

  // catFunc5(v: number): Plant;
  it('test Animal catFunc5', function () {
    let tc = new test.Animal();
    let ret = tc.catFunc5(66);
    let retJson = JSON.stringify(ret);
    assert.strictEqual(retJson, '{"tomato":"","tomatoId":0,"isTomato":false}');
  });
});




