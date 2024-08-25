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
import testNapi, { testNapiEnv } from 'libentry.so';
import { TitleBar } from '../../../common/TitleBar'
import hilog from '@ohos.hilog';

const TAG: string = 'napi_threadsafefuncrel';

@Entry
@Component
struct napithreadsafefuncrel {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_threadsafe_function_release_mode 是 N-API 中的一个函数，'
    + '用于指定线程安全函数对象的释放模式。该函数用于设置线程安全函数对象在何时释放内存。'
    + 'napi_threadsafe_function_release_mode 函数有以下几种释放模式：\n'
    + 'NAPI_TSFN_RELEASE：在调用线程安全函数对象的 release 方法时释放内存。\n'
    + 'NAPI_TSFN_ABORT：不要释放内存，当调用 abort 方法时调用错误回调函数。\n'
    + '通过选择适当的释放模式，可以确保线程安全函数对象在适当的时间释放内存，从而避免内存泄漏或访问已释放内存的情况。'
    + '需要注意的是，具体如何使用这些释放模式取决于你的具体应用场景和需求。在使用 napi_threadsafe_function_release_mode 函数时，'
    + '请确保理解每种模式的含义，并根据实际情况进行选择。'
  @State testcont: string = ' // napi_threadsafe_function_release_mode 调用 JS 回调 \n'
    + "try { \n"
    + ' const instance = addon.testNapiThreadsafefunc((res: string) => { \n'
    + '   this.callback(res) \n'
    + "   this.testcont = this.testcont.replace('log(myData)', 'log(## '+res+' ##)'); \n"
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
      TitleBar({ title: $r('app.string.napi_threadsafe_function_release_mode') })

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

          Button($r('app.string.napi_threadsafe_function_release_mode'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_threadsafe_function_release_mode')
            .onClick(() => {
              try {
                testNapi.testNapiThreadsafefuncrel((res: string) => {
                  this.callback(res)
                  this.testcont = this.testcont.replace('log(myData)', 'log(## ' + res + ' ##)');
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
