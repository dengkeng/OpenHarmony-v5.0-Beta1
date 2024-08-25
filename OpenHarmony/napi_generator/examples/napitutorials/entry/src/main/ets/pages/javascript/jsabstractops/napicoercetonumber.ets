/*
 * Copyright (c) 2024 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import image from '@ohos.multimedia.image';
import testNapi from 'libentry.so';
import { TitleBar } from '../../../common/TitleBar';
import hilog from '@ohos.hilog';

const TAG: string = 'napi_coerce_to_number';

@Entry
@Component
struct napicoercetonumber {
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_coerce_to_number() 用于将任意类型的 JavaScript 值'
    + '（例如 boolean 或 string）强制转换为 number。'
    + '如果 API 成功，则返回 napi_ok。'
    + '该 API 实现了 ECMAScript 语言规范的 第 7.1.3 节 中定义的抽象操作 ToNumber()。'
    + '如果传入的值是对象，此函数可能会运行 JS 代码。';
  @State testcont: string = '// 调用 API 对不同类型的输入进行测试 \n'
    + 'const testNumStr2NumResult = addon.testNapiCoerceToNumber(\'-123.456\'); // 数字字符串 -> -123.456 \n'
    + 'const testZeroStr2NumberResult = addon.testNapiCoerceToNumber(\'0\'); // 数字字符串 -> 0 \n'
    + 'const testTextStr2NumResult = addon.testNapiCoerceToNumber(\'test\'); // 非数字字符串 -> NaN \n'
    + 'const testTrueBool2NumberResult = addon.testNapiCoerceToNumber(true); // true -> 1 \n'
    + 'const testFalseBool2NumberResult = addon.testNapiCoerceToNumber(false); // false -> 0 \n'
    + 'const testNull2NumberResult = addon.testNapiCoerceToNumber(null); // null -> 0 \n'
    + 'const testUndef2NumberResult = addon.testNapiCoerceToNumber(undefined); // undefined -> NaN \n'
    + '// 输出强制转换结果 \n'
    + 'console.log(`\'-123.456\' -> ${testNumStr2NumResult}`); \n'
    + 'console.log(`\'0\' -> ${testZeroStr2NumberResult}`); \n'
    + 'console.log(`\'test\' -> ${testTextStr2NumResult}`); \n'
    + 'console.log(`true -> ${testTrueBool2NumberResult}`); \n'
    + 'console.log(`false -> ${testFalseBool2NumberResult}`); \n'
    + 'console.log(`null -> ${testNull2NumberResult}`); \n'
    + 'console.log(`undefined -> ${testUndef2NumberResult}`); \n';
  controller: TextAreaController = new TextAreaController()
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;

  build() {
    Scroll() {
      Column() {
        // 标题
        TitleBar({ title: $r('app.string.napi_coerce_to_number') })

        Column() {
          Column() {
            TextArea({
              text: this.textcont,
              placeholder: '',
            })
              .placeholderFont({ size: 16, weight: 400 })
              .width('90%')
              .margin(10)
              .fontSize(16)
              .fontColor('#182431')
              .backgroundColor('#FFFFFF')
              .enabled(false)

            TextArea({
              text: this.testcont,
              placeholder: '',
            })
              .placeholderFont({ size: 16, weight: 400 })
              .width('90%')
              .margin(10)
              .fontSize(16)
              .fontColor('#ff400336')
              .backgroundColor('#ff985307')
              .enabled(false)
          }
          .width('100%')
          .alignItems(HorizontalAlign.Center)
          .justifyContent(FlexAlign.Start)

          Row() {

            Button($r('app.string.napi_coerce_to_number'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_coerce_to_number')
              .onClick(() => {
                try {
                  // Test coercing string/boolean/null/undefined values to number
                  const testNumStr: string = '-123.456';
                  const testZeroStr: string = '0';
                  const testTextStr: string = 'test'
                  const testTrueBool: boolean = true;
                  const testFalseBool: boolean = false;
                  const testNull: null = null;
                  const testUndef: undefined = undefined;
                  const testNumStr2NumResult = testNapi.testNapiCoerceToNumber(testNumStr);
                  const testZeroStr2NumberResult = testNapi.testNapiCoerceToNumber(testZeroStr);
                  const testTextStr2NumResult = testNapi.testNapiCoerceToNumber(testTextStr);
                  const testTrueBool2NumberResult = testNapi.testNapiCoerceToNumber(testTrueBool);
                  const testFalseBool2NumberResult = testNapi.testNapiCoerceToNumber(testFalseBool);
                  const testNull2NumberResult = testNapi.testNapiCoerceToNumber(testNull);
                  const testUndef2NumberResult = testNapi.testNapiCoerceToNumber(testUndef);

                  // Replace result in testcont
                  this.testcont = this.testcont.replace('${testNumStr2NumResult}', `## ${testNumStr2NumResult} ##`);
                  this.testcont = this.testcont.replace('${testZeroStr2NumberResult}', `## ${testZeroStr2NumberResult} ##`);
                  this.testcont = this.testcont.replace('${testTextStr2NumResult}', `## ${testTextStr2NumResult} ##`);
                  this.testcont = this.testcont.replace('${testTrueBool2NumberResult}', `## ${testTrueBool2NumberResult} ##`);
                  this.testcont = this.testcont.replace('${testFalseBool2NumberResult}', `## ${testFalseBool2NumberResult} ##`);
                  this.testcont = this.testcont.replace('${testNull2NumberResult}', `## ${testNull2NumberResult} ##`);
                  this.testcont = this.testcont.replace('${testUndef2NumberResult}', `## ${testUndef2NumberResult} ##`);

                  // Print the results
                  hilog.info(0x0000, TAG, `(${typeof (testNumStr)})${testNumStr} -> ${testNumStr2NumResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testZeroStr)})${testZeroStr} -> ${testZeroStr2NumberResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testTextStr)})${testTextStr} -> ${testTextStr2NumResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testTrueBool)})${testTrueBool} -> ${testTrueBool2NumberResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testFalseBool)})${testFalseBool} -> ${testFalseBool2NumberResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testNull)})${testNull} -> ${testNull2NumberResult}`);
                  hilog.info(0x0000, TAG, `(${typeof (testUndef)})${testUndef} -> ${testUndef2NumberResult}`);
                } catch (error) {
                  hilog.error(0x0000, TAG, `Catch error testNapiCoerceToNumber: ${error.message}}`)
                }
              })
          }
          .width('100%')
          .height(48)
          .alignItems(VerticalAlign.Center)
          .justifyContent(FlexAlign.SpaceBetween)
        }
        .width('100%')
      }
    }
    .width('100%')
    .height('100%')
    .align(Alignment.Top)
    .backgroundColor($r('app.color.background_shallow_grey'))
  }
}
