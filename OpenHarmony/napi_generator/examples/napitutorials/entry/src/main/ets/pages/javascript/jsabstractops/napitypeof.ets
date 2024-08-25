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

const TAG: string = 'napi_typeof';

@Entry
@Component
struct napitypeoftypeof {
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = '此 API 表示类似于在 ECMAScript 语言规范的 第 12.5.5 节 中定义的对象上调用 typeof 运算符的行为。但是，存在一些差异：'
    + '1. 它支持检测外部值。'
    + '2. 它将 null 检测为单独的类型，而 ECMAScript typeof 将检测 object。'
    + '如果 API 成功，则返回 napi_ok。'
    + '如果 value 的类型无效，则返回错误。'
    + '如果 value 的类型不是已知的 ECMAScript 类型并且 value 不是外部值，则为 napi_invalid_arg。';
  @State testcont: string = '// 调用 API 对不同类型的输入进行测试 \n'
    + 'const testUndefResult = addon.testNapiTypeof(undefined); \n'
    + 'const testNullResult = addon.testNapiTypeof(null); \n'
    + 'const testBoolResult = addon.testNapiTypeof(true); \n'
    + 'const testNumResult = addon.testNapiTypeof(-123.456); \n'
    + 'const testStrResult = addon.testNapiTypeof(\'test\'); \n'
    + 'const testSymResult = addon.testNapiTypeof(Symbol()); \n'
    + 'const testObjResult = addon.testNapiTypeof({}); \n'
    + 'const testFuncResult = addon.testNapiTypeof(()=>{}); \n'
    + '// 输出强制转换结果 \n'
    + 'console.log(`undefined -> ${testUndefResult}`) \n'
    + 'console.log(`null -> ${testNullResult}`) \n'
    + 'console.log(`true -> ${testBoolResult}`) \n'
    + 'console.log(`-123.456 -> ${testNumResult}`) \n'
    + 'console.log(`\'test\' -> ${testStrResult}`) \n'
    + 'console.log(`Symbol() -> ${testSymResult}`) \n'
    + 'console.log(`{} -> ${testObjResult}`) \n'
    + 'console.log(`()=>{} -> ${testFuncResult}`) \n';
  controller: TextAreaController = new TextAreaController()
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;

  build() {
    Scroll() {
      Column() {
        // 标题
        TitleBar({ title: $r('app.string.napi_typeof') })

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

            Button($r('app.string.napi_typeof'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_typeof')
              .onClick(() => {
                try {
                  // Test querying types
                  const testUndef: undefined = undefined;
                  const testNull: null = null;
                  const testBool: boolean = true;
                  const testNum: number = -123.456;
                  const testStr: string = 'test';
                  // const testSym: symbol = Symbol();
                  // const testObj = {};
                  const testFunc = () => {
                  };
                  // const testBigInt = 1n;
                  const testUndefResult = testNapi.testNapiTypeof(testUndef);
                  const testNullResult = testNapi.testNapiTypeof(testNull);
                  const testBoolResult = testNapi.testNapiTypeof(testBool);
                  const testNumResult = testNapi.testNapiTypeof(testNum);
                  const testStrResult = testNapi.testNapiTypeof(testStr);
                  // const testSymResult = testNapi.testNapiTypeof(testSym);
                  // const testObjResult = testNapi.testNapiTypeof(testObj);
                  const testFuncResult = testNapi.testNapiTypeof(testFunc);

                  // Replace result in testcont
                  this.testcont = this.testcont.replace('${testUndefResult}', `## ${testUndefResult} ##`);
                  this.testcont = this.testcont.replace('${testNullResult}', `## ${testNullResult} ##`);
                  this.testcont = this.testcont.replace('${testBoolResult}', `## ${testBoolResult} ##`);
                  this.testcont = this.testcont.replace('${testNumResult}', `## ${testNumResult} ##`);
                  this.testcont = this.testcont.replace('${testStrResult}', `## ${testStrResult} ##`);
                  // this.testcont = this.testcont.replace('${testSymResult}', `## ${testSymResult} ##`);
                  // this.testcont = this.testcont.replace('${testObjResult}', `## ${testObjResult} ##`);
                  this.testcont = this.testcont.replace('${testFuncResult}', `## ${testFuncResult} ##`);

                  // Print the results
                  hilog.info(0x0000, TAG, `${typeof testUndef} -> ${testUndefResult}`);
                  hilog.info(0x0000, TAG, `${typeof testNull} -> ${testNullResult}`);
                  hilog.info(0x0000, TAG, `${typeof testBool} -> ${testBoolResult}`);
                  hilog.info(0x0000, TAG, `${typeof testNum} -> ${testNumResult}`);
                  hilog.info(0x0000, TAG, `${typeof testStr} -> ${testStrResult}`);
                  // hilog.info(0x0000, TAG, `${typeof testSym} -> ${testSymResult}`);
                  // hilog.info(0x0000, TAG, `${typeof testObj} -> ${testObjResult}`);
                  hilog.info(0x0000, TAG, `${typeof testFunc} -> ${testFuncResult}`);
                } catch (error) {
                  hilog.error(0x0000, TAG, `Catch error testNapiTypeof: ${error.message}}`)
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