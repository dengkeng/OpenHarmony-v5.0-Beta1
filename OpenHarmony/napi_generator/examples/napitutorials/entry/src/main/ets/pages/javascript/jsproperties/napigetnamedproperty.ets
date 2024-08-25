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

const TAG: string = 'napi_get_named_property';

interface myObjVal {
  key: string
}

interface myObj {
  key1: string;
  key2: number;
  key3: boolean;
  key4: Array<string>;
  key5: Function;
  key6: myObjVal;
}

@Entry
@Component
struct napiGetPropertyNames {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  private textcont: Resource = $r('app.string.napi_get_named_property_description');
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State testcont: string = ' // 测试 N-API napi_get_named_property \n'
    + 'let obj = {key1: "value",key2: 1,key3: false,key4: ["a", "b", "c"],key5: function () { return "function" },key6: {key: "value"}} \n'
    + '  const myData = testNapi.testNapiGetNamedProperty(obj, "key1"); \n'
    + ' // 使用获取的自定义数据 \n'
    + ' console.log(myData); // 输出自定义数据 \n'
    + ' const myData2 = testNapi.testNapiGetNamedProperty(obj, "key2"); \n'
    + ' console.log(myData2); // 输出自定义数据 \n'
    + ' const myData3 = testNapi.testNapiGetNamedProperty(obj, "key3"); \n'
    + ' console.log(myData3); // 输出自定义数据 \n'
    + ' const myData4 = testNapi.testNapiGetNamedProperty(obj, "key4"); \n'
    + ' console.log(myData4); // 输出自定义数据 \n'
    + ' const myData5 = testNapi.testNapiGetNamedProperty(obj, "key5"); \n'
    + ' console.log(myData5); // 输出自定义数据 \n'
    + ' const myData6 = testNapi.testNapiGetNamedProperty(obj, "key6"); \n'
    + ' console.log(myData6); // 输出自定义数据 \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_get_named_property') })

      Scroll() {
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

            Button($r('app.string.napi_get_named_property'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_get_named_property')
              .onClick(() => {
                let obj: myObj = {
                  key1: "value",
                  key2: 1,
                  key3: false,
                  key4: ["a", "b", "c"],
                  key5: () => {
                    return "function";
                  },
                  key6: { key: "value" }
                }
                let ret = testNapi.testNapiGetNamedProperty(obj, "key1");
                this.testcont = this.testcont.replace('log(myData)', 'log(## ' + ret + ' ##)');
                let ret2 = testNapi.testNapiGetNamedProperty(obj, "key2");
                this.testcont = this.testcont.replace('log(myData2)', 'log(## ' + ret2 + ' ##)');
                let ret3 = testNapi.testNapiGetNamedProperty(obj, "key3");
                this.testcont = this.testcont.replace('log(myData3)', 'log(## ' + ret3 + ' ##)');
                let ret4 = testNapi.testNapiGetNamedProperty(obj, "key4");
                this.testcont = this.testcont.replace('log(myData4)', 'log(## ' + ret4 + ' ##)');
                let ret5 = testNapi.testNapiGetNamedProperty(obj, "key5");
                this.testcont = this.testcont.replace('log(myData5)', 'log(## ' + ret5 + ' ##)');
                let ret6 = testNapi.testNapiGetNamedProperty(obj, "key6");
                this.testcont = this.testcont.replace('log(myData6)', 'log(## ' + JSON.stringify(ret6) + ' ##)');
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
    .height('100%')
    .width('100%')
    .backgroundColor($r('app.color.background_shallow_grey'))
  }
}
