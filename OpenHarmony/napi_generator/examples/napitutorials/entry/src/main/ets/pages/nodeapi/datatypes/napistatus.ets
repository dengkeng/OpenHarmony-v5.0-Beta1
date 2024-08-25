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

const TAG: string = 'napi_roi';

@Entry
@Component
struct napistatus {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = '指示 Node-API 调用成功或失败的完整状态代码。目前支持以下状态码。'
    + '如果 API 返回失败状态时需要额外的信息，可以通过调用 napi_get_last_error_info 获取。'
  @State testcont: string = ' // 获取导出的 N-API 实例对象 \n'
    + " const addon = require('./build/Release/module_name'); \n"
    + ' // 使用实例对象进行操作 \n'
    + ' const result = addon.add(5, 1); \n'
    + ' // 成功案例 \n'
    + ' console.log(`The result of the addition is: ${result}`); \n'
    + ' // 失败案例，设置 > 10 报错 \n'
    + ' try { \n'
    + '   const result = addon.add(5, 10); \n'
    + ' } catch (error) { \n'
    + "   console.error('An error occurred in the addon:', error.message); \n"
    + ' } \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_status') })

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

          Button($r('app.string.napi_status'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napstatus')
            .onClick(() => {
              let result = testNapi.testNapiStatus(5, 1);
              console.log(`The result of the testNapiStatus is: ${result}`);
              this.testcont = this.testcont.replace('${result}', 'log(## '+result+' ##)');
              try {
                let result1 = testNapi.testNapiStatus(5, 10);
              } catch (error) {
                console.log(`Catch eror of testNapiStatus is: ${error.message}`);
                this.testcont = this.testcont.replace('error.message', 'log(## '+error.message+' ##)');
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
