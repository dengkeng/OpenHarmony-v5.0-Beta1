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

import hilog from '@ohos.hilog';
import testNapi from 'libentry.so';
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';

interface myObjVal {
  key: string
}

interface myObj {
  key1?: string;
  key2?: number;
  true?: number;
  key3?: boolean;
  key4?: Array<string>;
  key5?: Function;
  key6?: myObjVal;
}
export default function abilityTestJsProperty() {
  describe('ActsAbilityTestJsProperty', () => {
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

    it('testNapiGetPropertyNames', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiGetPropertyNames begin');
      let obj: myObj = {
        key1: "aa",
        key2: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          console.info("This is a function");
        }
      }
      let result = testNapi.testNapiGetPropertyNames(obj);
      hilog.info(0x0000, 'testTag', `napi_get_property_names(${obj}) = ${result}`);
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(JSON.stringify(result)).assertContain('["key1","key2","key3","key4","key5"]');
    })

    it('testNapiGetProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiGetProperty begin');
      let obj: myObj = {
        key1: "value",
        true: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          return "function";
        },
        key6: {key: "value"}
      }
      let result = testNapi.testNapiGetProperty(obj, "key1");
      let result2 = testNapi.testNapiGetProperty(obj, true);
      let result3 = testNapi.testNapiGetProperty(obj, "key3");
      let result4 = testNapi.testNapiGetProperty(obj, "key4");
      let result5 = testNapi.testNapiGetProperty(obj, "key5");
      let result6 = testNapi.testNapiGetProperty(obj, "key6");

      hilog.info(0x0000, 'testTag', `napi_get_property(obj.key1) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_get_property(obj.true) = ${result2}`);
      hilog.info(0x0000, 'testTag', `napi_get_property(obj.0) = ${result3}`);
      hilog.info(0x0000, 'testTag', `napi_get_property(obj.key4) = ${result4}`);
      hilog.info(0x0000, 'testTag', `napi_get_property(obj.key5) = ${result5}`);
      hilog.info(0x0000, 'testTag', `napi_get_property(obj.key6) = ${result6}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(JSON.stringify(result)).assertContain('value');
      expect(JSON.stringify(result2)).assertContain('1');
      expect(JSON.stringify(result3)).assertContain('false');
      expect(JSON.stringify(result4)).assertContain('["a","b","c"]');
      expect(JSON.stringify(result5)).assertContain('function');
      expect(JSON.stringify(result6)).assertContain('{"key":"value"}');
    })

    it('testNapiSetProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiSetProperty begin');
      let obj1: myObj = {};
      let result = testNapi.testNapiSetProperty(obj1, "key1", "value");
      let obj2: myObj = {};
      let result2 = testNapi.testNapiSetProperty(obj2, 0, false);
      let obj3: myObj = {};
      let result3 = testNapi.testNapiSetProperty(obj3, true, 1);
      let obj4: myObj = {};
      let result4 = testNapi.testNapiSetProperty(obj4, "key4", ["a","b","c"]);
      let obj5: myObj = {};
      let func = () => {
        return "this is a function";
      };
      let result5: myObj = testNapi.testNapiSetProperty(obj5, "key5", func);
      let obj6: myObj = {};
      let objVal: myObjVal = {key: "value"};
      let result6 = testNapi.testNapiSetProperty(obj6, "key6", objVal);

      hilog.info(0x0000, 'testTag', `napi_set_property(obj.key1) = ${JSON.stringify(result)}`);
      hilog.info(0x0000, 'testTag', `napi_set_property(obj.0) = ${JSON.stringify(result2)}`);
      hilog.info(0x0000, 'testTag', `napi_set_property(obj.true) = ${JSON.stringify(result3)}`);
      hilog.info(0x0000, 'testTag', `napi_set_property(obj.key4) = ${JSON.stringify(result4)}`);
      hilog.info(0x0000, 'testTag', `napi_set_property(obj.key5) = ${JSON.stringify(typeof result5.key5)}`);
      hilog.info(0x0000, 'testTag', `napi_set_property(obj.key6) = ${JSON.stringify(result6)}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(JSON.stringify(result)).assertContain('"key1":"value"');
      expect(JSON.stringify(result2)).assertContain('"0":false');
      expect(JSON.stringify(result3)).assertContain('"true":1');
      expect(JSON.stringify(result4)).assertContain('"key4":["a","b","c"]');
      expect(JSON.stringify(typeof result5.key5)).assertContain('function');
      expect(JSON.stringify(result6)).assertContain('"key6":{"key":"value"}');
    })

    it('testNapiHasProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiHasProperty begin');
      let obj: myObj = {
        key1: "value",
        true: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          return "function";
        },
        key6: {key: "value"}
      }
      let result = testNapi.testNapiHasProperty(obj, "key1");
      let result2 = testNapi.testNapiHasProperty(obj, true);
      let result3 = testNapi.testNapiHasProperty(obj, "key3");
      let result4 = testNapi.testNapiHasProperty(obj, "key4");
      let result5 = testNapi.testNapiHasProperty(obj, "key5");
      let result6 = testNapi.testNapiHasProperty(obj, "key6");
      let result7 = testNapi.testNapiHasProperty(obj, "key7");

      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key1) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.true) = ${result2}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key3) = ${result3}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key4) = ${result4}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key5) = ${result5}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key6) = ${result6}`);
      hilog.info(0x0000, 'testTag', `napi_has_property(obj.key7) = ${result7}`);
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(result.toString()).assertContain('true');
      expect(result2.toString()).assertContain('true');
      expect(result3.toString()).assertContain('true');
      expect(result4.toString()).assertContain('true');
      expect(result5.toString()).assertContain('true');
      expect(result6.toString()).assertContain('true');
      expect(result7.toString()).assertContain('false');
    })

    it('testNapiDeleteProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiDeleteProperty begin');
      let obj: myObj = {
        key1: "value",
        true: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          return "function";
        },
        key6: {key: "value"}
      }
      let result = testNapi.testNapiDeleteProperty(obj, "key1");
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.key1) = ${JSON.stringify(result)}`);
      expect(JSON.stringify(result)).assertContain('{"true":1,"key3":false,"key4":["a","b","c"],"key6":{"key":"value"}}');

      let result2 = testNapi.testNapiDeleteProperty(obj, true);
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.key3) = ${JSON.stringify(result2)}`);
      expect(JSON.stringify(result2)).assertContain('{"key3":false,"key4":["a","b","c"],"key6":{"key":"value"}}');

      let result3 = testNapi.testNapiDeleteProperty(obj, "key3");
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.true) = ${JSON.stringify(result3)}`);
      expect(JSON.stringify(result3)).assertContain('{"key4":["a","b","c"],"key6":{"key":"value"}}');

      let result4 = testNapi.testNapiDeleteProperty(obj, "key4");
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.key4) = ${JSON.stringify(result4)}`);
      expect(JSON.stringify(result4)).assertContain('{"key6":{"key":"value"}}');

      let result5 = testNapi.testNapiDeleteProperty(obj, "key5");
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.key5) = ${JSON.stringify(result5)}`);
      expect(JSON.stringify(result5)).assertContain('{"key6":{"key":"value"}}');

      let result6 = testNapi.testNapiDeleteProperty(obj, "key6");
      hilog.info(0x0000, 'testTag', `napi_delete_property(obj.key6) = ${JSON.stringify(result6)}`);
      expect(JSON.stringify(result6)).assertContain('{}');
    })


    it('testNapiSetNamedProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiSetNamedProperty begin');
      let obj1: myObj = {};
      let result = testNapi.testNapiSetNamedProperty(obj1, "key1", "value");
      let obj2: myObj = {};
      let result2 = testNapi.testNapiSetNamedProperty(obj2, "key2", false);
      let obj3: myObj = {};
      let result3 = testNapi.testNapiSetNamedProperty(obj3, "key3", 1);
      let obj4: myObj = {};
      let result4 = testNapi.testNapiSetNamedProperty(obj4, "key4", ["a","b","c"]);
      let obj5: myObj = {};
      let func = () => {
        return "this is a function";
      };
      let result5: myObj = testNapi.testNapiSetNamedProperty(obj5, "key5", func);
      let obj6: myObj = {};
      let objVal: myObjVal = {key: "value"};
      let result6 = testNapi.testNapiSetNamedProperty(obj6, "key6", objVal);

      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key1) = ${JSON.stringify(result)}`);
      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key2) = ${JSON.stringify(result2)}`);
      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key3) = ${JSON.stringify(result3)}`);
      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key4) = ${JSON.stringify(result4)}`);
      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key5) = ${JSON.stringify(typeof result5.key5)}`);
      hilog.info(0x0000, 'testTag', `napi_set_named_property(obj.key6) = ${JSON.stringify(result6)}`);
      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(JSON.stringify(result)).assertContain('"key1":"value"');
      expect(JSON.stringify(result2)).assertContain('"key2":false');
      expect(JSON.stringify(result3)).assertContain('"key3":1');
      expect(JSON.stringify(result4)).assertContain('"key4":["a","b","c"]');
      expect(JSON.stringify(typeof result5.key5)).assertContain('function');
      expect(JSON.stringify(result6)).assertContain('"key6":{"key":"value"}');
    })

    it('testNapiGetNamedProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiGetNamedProperty begin');
      let obj: myObj = {
        key1: "value",
        key2: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          return "function";
        },
        key6: {key: "value"}
      }
      let result = testNapi.testNapiGetNamedProperty(obj, "key1");
      let result2 = testNapi.testNapiGetNamedProperty(obj, "key2");
      let result3 = testNapi.testNapiGetNamedProperty(obj, "key3");
      let result4 = testNapi.testNapiGetNamedProperty(obj, "key4");
      let result5 = testNapi.testNapiGetNamedProperty(obj, "key5");
      let result6 = testNapi.testNapiGetNamedProperty(obj, "key6");

      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key1) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key2) = ${result2}`);
      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key3) = ${result3}`);
      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key4) = ${result4}`);
      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key5) = ${result5}`);
      hilog.info(0x0000, 'testTag', `napi_get_named_property(obj.key6) = ${result6}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(JSON.stringify(result)).assertContain('value');
      expect(JSON.stringify(result2)).assertContain('1');
      expect(JSON.stringify(result3)).assertContain('false');
      expect(JSON.stringify(result4)).assertContain('["a","b","c"]');
      expect(JSON.stringify(result5)).assertContain('function');
      expect(JSON.stringify(result6)).assertContain('{"key":"value"}');
    })

    it('testNapiHasNamedProperty', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiHasNamedProperty begin');
      let obj: myObj = {
        key1: "value",
        key2: 1,
        key3: false,
        key4: ["a", "b", "c"],
        key5: () => {
          return "function";
        },
        key6: {key: "value"}
      }
      let result = testNapi.testNapiHasNamedProperty(obj, "key1");
      let result2 = testNapi.testNapiHasNamedProperty(obj, "key2");
      let result3 = testNapi.testNapiHasNamedProperty(obj, "key3");
      let result4 = testNapi.testNapiHasNamedProperty(obj, "key4");
      let result5 = testNapi.testNapiHasNamedProperty(obj, "key5");
      let result6 = testNapi.testNapiHasNamedProperty(obj, "key6");
      let result7 = testNapi.testNapiHasNamedProperty(obj, "key7");

      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key1) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key2) = ${result2}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key3) = ${result3}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key4) = ${result4}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key5) = ${result5}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key6) = ${result6}`);
      hilog.info(0x0000, 'testTag', `napi_has_named_property(obj.key7) = ${result7}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(result.toString()).assertContain('true');
      expect(result2.toString()).assertContain('true');
      expect(result3.toString()).assertContain('true');
      expect(result4.toString()).assertContain('true');
      expect(result5.toString()).assertContain('true');
      expect(result6.toString()).assertContain('true');
      expect(result7.toString()).assertContain('false');
    })

    it('testNapiSetElement', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiSetElement begin');
      let obj1 = [1,2,3];
      let result = testNapi.testNapiSetElement(obj1, 1, 5);
      let obj2 = ["a", "b", "c"];
      let result2 = testNapi.testNapiSetElement(obj2, 4, "d");
      let obj3 = [true, false];
      let result3 = testNapi.testNapiSetElement(obj3, 2, true);
      let obj4 = [0, false, "zz"];
      let result4 = testNapi.testNapiSetElement(obj4, 1, "kk");

      hilog.info(0x0000, 'testTag', `napi_set_element(obj, 1, 5) = ${JSON.stringify(result)}`);
      hilog.info(0x0000, 'testTag', `napi_set_element(obj, 4, "d") = ${JSON.stringify(result2)}`);
      hilog.info(0x0000, 'testTag', `napi_set_element(obj, 2, true) = ${JSON.stringify(result3)}`);
      hilog.info(0x0000, 'testTag', `napi_set_element(obj, 1, "kk") = ${JSON.stringify(result4)}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(result.toString()).assertContain('1,5,3');
      expect(result2.toString()).assertContain('a,b,c,,d');
      expect(result3.toString()).assertContain('true,false,true');
      expect(result4.toString()).assertContain('0,kk,zz');
    })

    it('testNapiGetElement', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiGetElement begin');
      let obj1 = [1,2,3];
      let result = testNapi.testNapiGetElement(obj1, 1);
      let obj2 = ["a", "b", "c"];
      let result2 = testNapi.testNapiGetElement(obj2, 2);
      let obj3 = [true, false];
      let result3 = testNapi.testNapiGetElement(obj3, 1);
      let obj4 = [0, false, "zz"];
      let result4 = testNapi.testNapiGetElement(obj4, 2);

      hilog.info(0x0000, 'testTag', `napi_get_element(obj, 1) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_get_element(obj, 2) = ${result2}`);
      hilog.info(0x0000, 'testTag', `napi_get_element(obj, 1) = ${result3}`);
      hilog.info(0x0000, 'testTag', `napi_get_element(obj, 2) = ${result4}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(result.toString()).assertContain('2');
      expect(result2.toString()).assertContain('c');
      expect(result3.toString()).assertContain('false');
      expect(result4.toString()).assertContain('zz');
    })

    it('testNapiHasElement', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiHasElement begin');
      let obj = [0, false, "zz"];
      let result = testNapi.testNapiHasElement(obj, 2);
      let result2 = testNapi.testNapiHasElement(obj, 4);

      hilog.info(0x0000, 'testTag', `napi_has_element(obj, 2) = ${result}`);
      hilog.info(0x0000, 'testTag', `napi_has_element(obj, 4) = ${result2}`);

      // Defines a variety of assertion methods, which are used to declare expected boolean conditions.
      expect(result.toString()).assertContain('true');
      expect(result2.toString()).assertContain('false');
    })

    it('testNapiDeleteElement', 0, () => {
      // Defines a test case. This API supports three parameters: test case name, filter parameter, and test case function.
      hilog.info(0x0000, 'testTag', '%{public}s', 'it testNapiDeleteElement begin');
      let obj = [0, false, "zz"];
      let result = testNapi.testNapiDeleteElement(obj, 1);
      hilog.info(0x0000, 'testTag', `napi_delete_element(obj, 1) = ${JSON.stringify(result)}`);
      expect(result.toString()).assertContain('0,,zz');
      let result2 = testNapi.testNapiDeleteElement(obj, 0);
      hilog.info(0x0000, 'testTag', `napi_delete_element(obj, 0) = ${JSON.stringify(result2)}`);
      expect(result2.toString()).assertContain(',,zz');
      let result3 = testNapi.testNapiDeleteElement(obj, 2);
      hilog.info(0x0000, 'testTag', `napi_delete_element(obj, 2) = ${JSON.stringify(result3)}`);
      expect(result3.toString()).assertContain(',,');
    })


  })
}
