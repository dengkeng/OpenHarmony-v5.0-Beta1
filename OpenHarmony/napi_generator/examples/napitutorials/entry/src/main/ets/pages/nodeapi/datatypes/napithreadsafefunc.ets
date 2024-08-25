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

import router from '@ohos.router';
import image from '@ohos.multimedia.image';
import Logger from '../../../util/Logger';
import testNapi from 'libentry.so';
import { TitleBar } from '../../../common/TitleBar'
import hilog from '@ohos.hilog';

const TAG: string = 'napi_threadsafefunc';

@Entry
@Component
struct napithreadsafefunc {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_call_threadsafe_function 是 Node.js N-API 中的一个函数，'
  + '用于在另一个线程中异步调用一个线程安全（thread-safe）的 JavaScript 函数。这个函数允许你在一个独立的线程中执行 JavaScript 函数，'
  + '而不会阻塞主线程。'
  @State testcont: string = ' // napi_call_threadsafe_function 调用 JS 回调 \n'
    + "try { \n"
    + ' const instance = addon.testNapiThreadsafefunc((res: string) => { \n'
    + '   this.callback(res) \n'
    + "   console.log(myData) \n"
    + '  }) \n'
    + "} catch (error) { \n"
    + "  console.log(`Catch eror of testNapiThreadsafefunc is: ${error.message}`); \n"
    + "}; \n";

  controller: TextAreaController = new TextAreaController()

  callback(res: string) {
    hilog.info(0x0000, 'testTag', `callback input param ${res} `);
  }

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_threadsafe_function') })

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

          Button($r('app.string.napi_threadsafe_function'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_threadsafe_function')
            .onClick(() => {
              try {
                testNapi.testNapiThreadsafefunc((res: string) => {
                  this.callback(res)
                  this.testcont = this.testcont.replace('log(myData)', 'log(## '+res+' ##)');
                })
              } catch (error) {
                console.log(`Catch eror of testNapiThreadsafefunc is: ${error.message}`);
                this.testcont = this.testcont.replace('${error.message}', '(## '+error.message+' ##)');
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
    .height('100%')
    .width('100%')
    .backgroundColor($r('app.color.background_shallow_grey'))
  }
}
