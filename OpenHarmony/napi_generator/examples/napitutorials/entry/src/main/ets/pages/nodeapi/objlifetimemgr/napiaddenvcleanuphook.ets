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

const TAG: string = 'napi_value';

@Entry
@Component
struct napi_add_env_cleanup_hook {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_value 这是一个用于表示 JavaScript 值的不透明指针。'
  @State testcont: string = ' // 获取 N-API value \n'
    + '  const myData = addon.testNapiValue(); \n'
    + ' // 使用获取的自定义数据 \n'
    + ' console.log(myData); // 输出自定义数据 \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_add_env_cleanup_hook') })

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

          Button($r('app.string.napi_add_env_cleanup_hook'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_add_env_cleanup_hook')
            .onClick(() => {
              let res = testNapi.testNapiValue();
              hilog.info(0x0000, 'testTag', `testNapiValue = ${res} `);
              this.testcont = this.testcont.replace('log(myData)', 'log(## '+res+' ##)');
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
