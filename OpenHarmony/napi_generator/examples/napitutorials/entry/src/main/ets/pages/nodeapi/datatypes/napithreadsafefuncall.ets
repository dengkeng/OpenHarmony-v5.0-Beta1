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

const TAG: string = 'napi_threadsafefuncall';

@Entry
@Component
struct napithreadsafefuncall {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_threadsafe_function_call_mode 是 N-API 中用于设置线程安全函数对象调用模式的枚举类型。'
    + '在 N-API 中，线程安全函数对象（Thread-safe Function Objects）允许在不同的线程中安全地调用 JavaScript 回调函数。'
    + 'napi_threadsafe_function_call_mode 枚举类型定义了线程安全函数对象的调用模式，可以影响线程安全函数对象的行为和执行方式。'
    + '以下是 napi_threadsafe_function_call_mode 枚举类型的可能取值：\n'
    + 'napi_tsfn_nonblocking：\n'
    + '表示线程安全函数对象以非阻塞方式进行调用。这意味着调用线程将不会阻塞等待 JavaScript 回调函数的执行完成，而是立即返回并继续执行后续代码。\n'
    + 'napi_tsfn_blocking：\n'
    + "表示线程安全函数对象以阻塞方式进行调用。在这种模式下，调用线程会等待 JavaScript 回调函数执行完成后再继续执行后续代码。\n"
    + "通过选择适当的调用模式，可以控制线程安全函数对象的执行方式，以满足具体的需求和场景。根据实际情况，"
    + "可以灵活地选择非阻塞或阻塞模式来调用线程安全函数对象，以实现更高效和灵活的线程交互。"

  @State testcont: string = ' // napi_threadsafe_function_call_mode 调用 JS 回调 \n'
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
      TitleBar({ title: $r('app.string.napi_threadsafe_function_call_mode') })

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

          Button($r('app.string.napi_threadsafe_function_call_mode'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_threadsafe_function_call_mode')
            .onClick(() => {
              try {
                testNapi.testNapiThreadsafefuncall((res: string) => {
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
