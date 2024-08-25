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

const TAG: string = 'napi_coerce_to_object';

@Entry
@Component
struct napicoercetoobject {
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_coerce_to_object() 用于将任意类型的 JavaScript 值'
    + '（例如 boolean、number 或 string）强制转换为 object。'
    + '如果 API 成功，则返回 napi_ok。'
    + '该 API 实现了 ECMAScript 语言规范的 第 7.1.13 节 中定义的抽象操作 ToObject()。';
  @State testcont: string = '// 调用 API 对不同类型的输入进行测试 \n'
    + 'const testBool2ObjResult = addon.addonCoerceToObject(true);\n'
    + 'const testNum2ObjResult = addon.testNapiCoerceToObject(-123.456);\n'
    + 'const testStr2ObjResult = addon.testNapiCoerceToObject(\'test\');\n'
    + 'const testNull2ObjResult = addon.testNapiCoerceToObject(null); // null -> undefined\n'
    + 'const testUndef2ObjResult = addon.testNapiCoerceToObject(undefined); // undefined -> undefined\n'
    + '// 输出强制转换结果 \n'
    + 'console.log(`true -> ${testBool2ObjResult}`) \n'
    + 'console.log(`-123.456 -> ${testNum2ObjResult}`) \n'
    + 'console.log(`\'test\' -> ${testStr2ObjResult}`) \n'
    + 'console.log(`null -> ${testNull2ObjResult}`) \n'
    + 'console.log(`undefined -> ${testUndef2ObjResult}`) \n';
  controller: TextAreaController = new TextAreaController()
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;

  build() {
    Scroll() {
      Column() {
        // 标题
        TitleBar({ title: $r('app.string.napi_coerce_to_object') })

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

            Button($r('app.string.napi_coerce_to_object'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_coerce_to_object')
              .onClick(() => {
                try {
                  // Test coercing boolean/number/string/null/undefined values to object
                  const testBool: boolean = true;
                  const testNum: number = -123.456;
                  const testStr: string = 'test'
                  const testNull: null = null;
                  const testUndef: undefined = undefined;
                  const testBool2ObjResult = testNapi.testNapiCoerceToObject(testBool);
                  const testNum2ObjResult = testNapi.testNapiCoerceToObject(testNum);
                  const testStr2ObjResult = testNapi.testNapiCoerceToObject(testStr);
                  const testNull2ObjResult = testNapi.testNapiCoerceToObject(testNull);
                  const testUndef2ObjResult = testNapi.testNapiCoerceToObject(testUndef);

                  // Replace result in testcont
                  this.testcont = this.testcont.replace('${testBool2ObjResult}',
                    `## (${typeof testBool2ObjResult})${testBool2ObjResult} ##`);
                  this.testcont = this.testcont.replace('${testNum2ObjResult}',
                    `## (${typeof testNum2ObjResult})${testNum2ObjResult} ##`);
                  this.testcont = this.testcont.replace('${testStr2ObjResult}',
                    `## (${typeof testStr2ObjResult})${testStr2ObjResult} ##`);
                  this.testcont = this.testcont.replace('${testNull2ObjResult}',
                    `## (${typeof testNull2ObjResult})${testNull2ObjResult} ##`);
                  this.testcont = this.testcont.replace('${testUndef2ObjResult}',
                    `## (${typeof testUndef2ObjResult})${testUndef2ObjResult} ##`);

                  // Print the results
                  hilog.info(0x0000, TAG, `(${typeof testBool})${testBool} -> `
                    + `(${typeof testBool2ObjResult})${testBool2ObjResult}`);
                  hilog.info(0x0000, TAG, `(${typeof testNum})${testNum} -> `
                    + `(${typeof testNum2ObjResult})${testNum2ObjResult}`);
                  hilog.info(0x0000, TAG, `(${typeof testStr})${testStr} -> `
                    + `(${typeof testStr2ObjResult})${testStr2ObjResult}`);
                  hilog.info(0x0000, TAG, `(${typeof testNull})${testNull} -> `
                    + `(${typeof testNull2ObjResult})${testNull2ObjResult}`);
                  hilog.info(0x0000, TAG, `(${typeof testUndef})${testUndef} -> `
                    + `(${typeof testUndef2ObjResult})${testUndef2ObjResult}`);
                } catch (error) {
                  hilog.error(0x0000, TAG, `Catch error testNapiCoerceToObject: ${error.message}}`)
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