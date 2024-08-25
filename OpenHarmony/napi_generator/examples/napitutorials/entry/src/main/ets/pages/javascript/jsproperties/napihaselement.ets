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
import testNapi, { testNapiValue } from 'libentry.so';
import { TitleBar } from '../../../common/TitleBar'
import hilog from '@ohos.hilog';

const TAG: string = 'napi_has_element';

@Entry
@Component
struct napiGetPropertyNames {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  private textcont: Resource = $r('app.string.napi_has_element_description');
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State testcont: string = ' // 测试 N-API napi_has_element \n'
    + ' let obj = [0, false, "zz"]; \n'
    + ' const myData = testNapi.testNapiHasElement(obj, 2); \n'
    + ' console.log(myData); // 输出自定义数据 \n'
    + ' const myData2 = testNapi.testNapiHasElement(obj, 4); \n'
    + ' console.log(myData2); // 输出自定义数据 \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_has_element') })

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
            .fontColor($r('app.color.sub_title_color'))
            .backgroundColor($r('app.color.white'))
            .enabled(false)

          TextArea({
            text: this.testcont,
            placeholder: '',
          })
            .placeholderFont({ size: 16, weight: 400 })
            .width('90%')
            .margin(10)
            .fontSize(16)
            .fontColor($r('app.color.textarea_font_color'))
            .backgroundColor($r('app.color.textarea_background_color'))
            .enabled(false)
        }
        .width('100%')
        .alignItems(HorizontalAlign.Center)
        .justifyContent(FlexAlign.Start)

        Row() {

          Button($r('app.string.napi_has_element'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_has_element')
            .onClick(() => {
              let obj = [0, false, "zz"];
              let ret = testNapi.testNapiHasElement(obj, 2);
              this.testcont = this.testcont.replace('log(myData)', 'log(## '+JSON.stringify(ret)+' ##)');
              let ret2 = testNapi.testNapiHasElement(obj, 4);
              this.testcont = this.testcont.replace('log(myData2)', 'log(## '+JSON.stringify(ret2)+' ##)');
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
