/*
* Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

import testNapi from 'libentry.so';
import hilog from '@ohos.hilog';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import { TcCJsonSample, cJSON } from '../../../../main/ets/interface/tctcjsonsample';

export default function abilityTestCjson() {
  describe('ActsAbilityTestCjson', () => {
    // let testNapi: testNapi | undefined = undefined;
    // Defines a test suite. Two parameters are supported: test suite name and test suite function.
    beforeAll(() => {
      // Presets an action, which is performed only once before all test cases of the test suite start.
      // This API supports only one parameter: preset action function.
    })
    beforeEach(() => {
      // Presets an action, which is performed before each unit test case starts.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: preset action function.
    })
    afterEach(() => {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
    })
    afterAll(() => {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
    })
    it('assertContain', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let a = 'abc';
      let b = 'b';
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(a).assertContain(b);
      expect(a).assertEqual(a);
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH418_cJSON_Parse', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let value = '"helloworld"'
      let value2 = '1.8'
      let value3 = '["a","b"]'
      let value4 = '{"name":"JohnDoe","age":18}'
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result:cJSON = tccjsonobj.KH418_cJSON_Parse(value);
      let result2: cJSON = tccjsonobj.KH418_cJSON_Parse(value2);
      let result3: cJSON = tccjsonobj.KH418_cJSON_Parse(value3);
      let result4: cJSON = tccjsonobj.KH418_cJSON_Parse(value4);

      console.info("Test NAPI KH418_cJSON_Parse result1: ", JSON.stringify(result))
      console.info("Test NAPI KH418_cJSON_Parse result2: ", JSON.stringify(result2))
      console.info("Test NAPI KH418_cJSON_Parse result3: ", JSON.stringify(result3))
      console.info("Test NAPI KH418_cJSON_Parse result4: ", JSON.stringify(result4))
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH373_cJSON_GetArraySize', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let value: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 0,
        valuestring: '["apple","banana","cherry","pear","strawberry"]',
        valueint: 0,
        valuedouble: 0,
        string: ''
      }
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result: number = tccjsonobj.KH373_cJSON_GetArraySize(value);
      hilog.info(0x0000, "testTag", "Test NAPI KH734_CJSON_GetArraySize: ", result);
      console.info("Test NAPI KH734_CJSON_GetArraySize result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH735_cJSON_Print', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let paramIn: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 16,
        valuestring: 'JohnDoe',
        valueint: 0,
        valuedouble: 0,
        string: 'name'
      }
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result: string = tccjsonobj.KH735_cJSON_Print(paramIn)
      hilog.info(0x0000, "testTag", "Test NAPI  KH735_cJSON_Print: ", result);
      console.info("Test NAPI KH735_cJSON_Print result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH361_cJSON_CreateObject', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result: cJSON = tccjsonobj.KH361_cJSON_CreateObject()
      hilog.info(0x0000, "testTag", "Test NAPI  KH735_cJSON_Print: ", result);
      console.info("Test NAPI KH361_cJSON_CreateObject result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH515_cJSON_CreateString', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let string = "gOtkqDFR0z"
      let result: cJSON = tccjsonobj.KH515_cJSON_CreateString(string)
      hilog.info(0x0000, "testTag", "Test NAPI KH515_cJSON_CreateString: ", JSON.stringify(result));
      console.info("Test NAPI KH515_cJSON_CreateString result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH526_cJSON_AddStringToObject', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let valueObj: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 0,
        valuestring: '',
        valueint: 0,
        valuedouble: 0,
        string: ''
      }
      let name = "name"
      let string = "Anna"
      let result: cJSON = tccjsonobj.KH526_cJSON_AddStringToObject(valueObj, name, string)
      hilog.info(0x0000, "testTag", "Test NAPI KH526_cJSON_AddStringToObject: ", result);
      console.info("Test NAPI KH526_cJSON_AddStringToObject result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH206_cJSON_AddNumberToObject', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let valueObj: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 0,
        valuestring: '',
        valueint: 0,
        valuedouble: 0,
        string: ''
      }
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let name = "age"
      let numberIn = 12
      let result: cJSON = tccjsonobj.KH206_cJSON_AddNumberToObject(valueObj, name, numberIn)
      hilog.info(0x0000, "testTag", "Test NAPI KH206_cJSON_AddNumberToObject: ", result);
      console.info("Test NAPI KH206_cJSON_AddNumberToObject result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH545_cJSON_AddFalseToObject', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let valueObj: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 0,
        valuestring: '',
        valueint: 0,
        valuedouble: 0,
        string: ''
      }
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let name = "is_student"
      let result: cJSON = tccjsonobj.KH545_cJSON_AddFalseToObject(valueObj, name)
      hilog.info(0x0000, "testTag", "Test NAPI KH545_cJSON_AddFalseToObject: ", result);
      console.info("Test NAPI KH545_cJSON_AddFalseToObject result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH180_cJSON_AddItemToObject', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let valueObj: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 0,
        valuestring: '',
        valueint: 0,
        valuedouble: 0,
        string: ''
      }
      let string = "item"
      let valueItem: cJSON = {
        next: null,
        prev: null,
        child: null,
        type: 16,
        valuestring: 'JohnDoe',
        valueint: 0,
        valuedouble: 0,
        string: 'name'
      }
      let result: cJSON = tccjsonobj.KH180_cJSON_AddItemToObject(valueObj, string, valueItem)
      hilog.info(0x0000, "testTag", "Test NAPI KH180_cJSON_AddItemToObject: ", result);
      console.info("Test NAPI KH180_cJSON_AddItemToObject result: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH386_cJSON_CreateArray', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result: cJSON = tccjsonobj.KH386_cJSON_CreateArray()
      hilog.info(0x0000, "testTag", "Test NAPI KH386_cJSON_CreateArray: ", result);
      console.info("Test NAPI KH386_cJSON_CreateArray result: ", JSON.stringify(result))

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH203_cJSON_CreateIntArray', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it KH203_cJSON_CreateIntArray begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let result: cJSON = tccjsonobj.KH386_cJSON_CreateArray()
      console.info("Test NAPI KH203_cJSON_CreateIntArray result: ", JSON.stringify(result))

      let numbers: number[] = [1,0,-1]
      let cJsonInt: cJSON = tccjsonobj.KH203_cJSON_CreateIntArray(numbers, 3);
      console.info("Test NAPI KH203_cJSON_CreateIntArray cJsonInt1: ", JSON.stringify(cJsonInt))

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    // [NAPI_GEN]:输出测试方法，加注释
    it('KH802_cJSON_AddItemToArray', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it KH802_cJSON_AddItemToArray begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      // 创建一个cJSON数组并向cJSON数组中添加数据
      let result: cJSON = tccjsonobj.KH386_cJSON_CreateArray()
      console.info("Test NAPI KH802_cJSON_AddItemToArray result: ", JSON.stringify(result))
      let numbers: number[] = [12,20,24,31]
      let cJsonInt1: cJSON = tccjsonobj.KH203_cJSON_CreateIntArray(numbers, 4);
      console.info("Test NAPI KH802_cJSON_AddItemToArray result cJsonInt1: ", JSON.stringify(cJsonInt1))
      let cjsonResStr: string = tccjsonobj.KH735_cJSON_Print(cJsonInt1);
      console.info("Test NAPI KH802_cJSON_AddItemToArray result cjsonResStr: " + JSON.stringify(cjsonResStr));
      result = tccjsonobj.KH802_cJSON_AddItemToArray(result, cJsonInt1);
      console.info("Test NAPI KH802_cJSON_AddItemToArray result2: ", JSON.stringify(result))
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      // e.g. expect(result).assertEqual(2+3)
    })

    it('cJSON_Sample_test1', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it cJSON_Sample_test1 begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      // 创建一个空对象
      let cjsonObj: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      // 向对象中添加元素
      cjsonObj = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj, "type", "rect");
      cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "height", 1080);
      cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "width", 1920);
      cjsonObj = tccjsonobj.KH545_cJSON_AddFalseToObject(cjsonObj, "interface");
      cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "frame rate", 24);
      console.info("Test NAPI cJSON_Sample_test1 cjsonObjNext: " + JSON.stringify(cjsonObj));
      // {"type":"rect","height":1080,"width":1920,"interface":false,"frame rate":24}
      let cjsonResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj);
      console.info("Test NAPI cJSON_Sample_test1 result cjsonResStr: " + JSON.stringify(cjsonResStr));
      // hilog.info(0x0000, "testTag", "Test NAPI cJSON_Sample_test1 cjsonResStr: ", JSON.stringify(cjsonResStr));
      // {"testObj":{"type":"rect"}}
      let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      let cjsonObj3: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      cjsonObj3 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj3, "type", "rect");
      cjsonObj2 = tccjsonobj.KH180_cJSON_AddItemToObject(cjsonObj2, "testObj", cjsonObj3);
      console.info("Test NAPI cJSON_Sample_test1 result cjsonObj2: ", JSON.stringify(cjsonObj2))
      let cjsonObjResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj2);
      console.info("Test NAPI cJSON_Sample_test1 result cjsonObjResStr: " + JSON.stringify(cjsonObjResStr));
    })

    it('cJSON_Sample_test2', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it cJSON_Sample_test2 begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      let numbers: number[] = [3,1,-2]
      let cJsonInt1: cJSON = tccjsonobj.KH203_cJSON_CreateIntArray(numbers, 3);
      console.info("Test NAPI cJSON_Sample_test2 cJsonInt1: ", JSON.stringify(cJsonInt1))
      // print [3,1,-2]
      let cjsonIntArrResStr: string = tccjsonobj.KH735_cJSON_Print(cJsonInt1);
      console.info("Test NAPI cJSON_Sample_test2 result cjsonIntArrResStr: " + JSON.stringify(cjsonIntArrResStr));

      // print {"testArray":[3,1,-2]}
      let cjsonObj: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      let resultObject: cJSON = tccjsonobj.KH180_cJSON_AddItemToObject(cjsonObj, "testArray", cJsonInt1)
      hilog.info(0x0000, "testTag", "Test NAPI cJSON_Sample_test2: ", resultObject);
      console.info("Test NAPI cJSON_Sample_test2 result: ", JSON.stringify(resultObject))
      let cjsonObjArrResStr: string = tccjsonobj.KH735_cJSON_Print(resultObject);
      console.info("Test NAPI cJSON_Sample_test2 result cjsonObjArrResStr: " + JSON.stringify(cjsonObjArrResStr));
    })

    it('cJSON_Sample_test3', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it cJSON_Sample_test2 begin');
      let cjobj = testNapi.getTestCase(7);
      let tccjsonobj = cjobj as TcCJsonSample;
      // print [{"precision":"zip","Latitude":37.7668},{"precision":"zip","Latitude":37.371991}]
      let resultArray: cJSON = tccjsonobj.KH386_cJSON_CreateArray();
      let cjsonObj1: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      cjsonObj1 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj1, "precision", "zip");
      cjsonObj1 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj1, "Latitude", 37.7668);
      let cjsonObjResStr1: string = tccjsonobj.KH735_cJSON_Print(cjsonObj1);
      console.info("Test NAPI cJSON_Sample_test3 result cjsonObjResStr1: " + JSON.stringify(cjsonObjResStr1));
      resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj1);
      console.info("Test NAPI cJSON_Sample_test3 result resultArray1: " + JSON.stringify(resultArray));
      let cjsonArrResStr1: string = tccjsonobj.KH735_cJSON_Print(resultArray);
      console.info("Test NAPI cJSON_Sample_test3 result cjsonArrResStr1: " + JSON.stringify(cjsonArrResStr1));

      let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
      cjsonObj2 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj2, "precision", "zip2");
      cjsonObj2 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj2, "Latitude", 37.371991);
      let cjsonObjResStr2: string = tccjsonobj.KH735_cJSON_Print(cjsonObj2);
      console.info("Test NAPI cJSON_Sample_test3 result cjsonObjResStr2: " + JSON.stringify(cjsonObjResStr2));
      resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj2);
      console.info("Test NAPI cJSON_Sample_test3 result resultArray2: " + JSON.stringify(resultArray));
      let cjsonArrResStr2: string = tccjsonobj.KH735_cJSON_Print(resultArray);
      console.info("Test NAPI cJSON_Sample_test3 result cjsonArrResStr2: " + JSON.stringify(cjsonArrResStr2));
    })
    
  })
}