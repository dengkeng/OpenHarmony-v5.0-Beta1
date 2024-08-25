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

const TAG: string = 'napi_set_named_property';

interface myObjVal {
  key: string
}

interface myObj {
  key1?: string;
  key2?: number;
  key3?: boolean;
  key4?: Array<string>;
  key5?: Function;
  key6?: myObjVal;
}

@Entry
@Component
struct napiGetPropertyNames {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  private textcont: Resource = $r('app.string.napi_set_named_property_description');
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State testcont: string = ' // 测试 N-API napi_set_named_property \n'
    + '  let obj = {}; \n'
    + '  const myData = testNapi.testNapiSetNamedProperty(obj, "key1", "value"); \n'
    + ' // 使用获取的自定义数据 \n'
    + ' console.log(myData); // 输出自定义数据 \n'
    + ' const myData2 = testNapi.testNapiSetNamedProperty(obj, "key2", false); \n'
    + ' console.log(myData2); // 输出自定义数据 \n'
    + ' const myData3 = testNapi.testNapiSetNamedProperty(obj, "key3", 1); \n'
    + ' console.log(myData3); // 输出自定义数据 \n'
    + ' const myData4 = testNapi.testNapiSetNamedProperty(obj, "key4", ["a","b","c"]); \n'
    + ' console.log(myData4); // 输出自定义数据 \n'
    + ' let func = function () {return "this is a function"} \n'
    + ' const myData5 = testNapi.testNapiSetNamedProperty(obj, "key5", func); \n'
    + ' console.log(myData5); // 输出自定义数据 \n'
    + ' let objVal = {key: "value"}; \n'
    + ' const myData6 = testNapi.testNapiSetNamedProperty(obj, "key6", objVal); \n'
    + ' console.log(myData6); // 输出自定义数据 \n'

  controller: TextAreaController = new TextAreaController()

  build() {

    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_set_named_property') })

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

            Button($r('app.string.napi_set_named_property'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_set_named_property')
              .onClick(() => {
                let obj: myObj = {};
                let ret = testNapi.testNapiSetNamedProperty(obj, "key1", "value");
                this.testcont = this.testcont.replace('log(myData)', 'log(## ' + JSON.stringify(ret) + ' ##)');
                let ret2 = testNapi.testNapiSetNamedProperty(obj, "key2", false);
                this.testcont = this.testcont.replace('log(myData2)', 'log(## ' + JSON.stringify(ret2) + ' ##)');
                let ret3 = testNapi.testNapiSetNamedProperty(obj, "key3", 1);
                this.testcont = this.testcont.replace('log(myData3)', 'log(## ' + JSON.stringify(ret3) + ' ##)');
                let ret4 = testNapi.testNapiSetNamedProperty(obj, "key4", ["a", "b", "c"]);
                this.testcont = this.testcont.replace('log(myData4)', 'log(## ' + JSON.stringify(ret4) + ' ##)');
                let func = () => {
                  return "this is a function";
                };
                let ret5: myObj = testNapi.testNapiSetNamedProperty(obj, "key5", func);
                this.testcont = this.testcont.replace('log(myData5)', 'log(## ' + JSON.stringify(typeof ret5.key5) + ' ##)');
                let objVal: myObjVal = { key: "value" };
                let ret6 = testNapi.testNapiSetNamedProperty(obj, "key6", objVal);
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
