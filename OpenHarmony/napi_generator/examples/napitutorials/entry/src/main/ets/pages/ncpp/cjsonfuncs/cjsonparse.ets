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
import { TcCJsonSample, cJSON } from '../../../interface/tctcjsonsample';

const TAG: string = 'napi_cjsoncase';

@Entry
@Component
struct cjsonfuncs {
  private btnFontColor: Resource = $r('app.color.white');
  @State isSetInstance: Boolean = false;
  @State textcont: string = 'CJSON 测试集合，采用TCP三方仓的CJSON代码编译生成。'
  @State testcont: string = ' // 获取 CJSON 方法测试 \n'
    + ' let value = ""helloworld"" \n'
    + ' const cjsonparse1 =  testNapi.KH418_cJSON_Parse(value)); \n'
    + ' hilog.info(cjson parse string = %{cjsonparse1}s); \n'
    + ' let value2 = "1.8" \n'
    + ' const cjsonparse2 =  testNapi.KH418_cJSON_Parse(value2)); \n'
    + ' hilog.info(cjson parse string = %{cjsonparse2}s); \n'
    + ' let value3 = "["a","b"]" \n'
    + ' const cjsonparse3 =  testNapi.KH418_cJSON_Parse(value3)); \n'
    + ' hilog.info(cjson parse string = %{cjsonparse3}s); \n'
    + ' let value4 = "{"name":"JohnDoe","age":18}" \n'
    + ' const cjsonparse4 =  testNapi.KH418_cJSON_Parse(value4)); \n'
    + ' hilog.info(cjson parse string = %{cjsonparse4}s); \n'

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.cjson_management') })

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

            Button($r('app.string.cjson_management'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_jsoncase')
              .onClick(() => {
                let cjobj = testNapi.getTestCase(7);
                let tccjsonobj = cjobj as TcCJsonSample;
                let value = '"helloworld"'
                let value2 = '1.8'
                let value3 = '["a","b"]'
                let value4 = '{"name":"JohnDoe","age":18}'
                let cjsonparse1: cJSON = tccjsonobj.KH418_cJSON_Parse(value);
                hilog.info(0x0000, 'testTag', 'cjson parse = %{public}s', JSON.stringify(cjsonparse1));
                this.testcont = this.testcont.replace('%{cjsonparse1}s', JSON.stringify(cjsonparse1))
                let cjsonparse2: cJSON = tccjsonobj.KH418_cJSON_Parse(value2);
                hilog.info(0x0000, 'testTag', 'cjson parse = %{public}s', JSON.stringify(cjsonparse2));
                this.testcont = this.testcont.replace('%{cjsonparse2}s', JSON.stringify(cjsonparse2))
                let cjsonparse3: cJSON = tccjsonobj.KH418_cJSON_Parse(value3);
                hilog.info(0x0000, 'testTag', 'cjson parse = %{public}s', JSON.stringify(cjsonparse3));
                this.testcont = this.testcont.replace('%{cjsonparse3}s', JSON.stringify(cjsonparse3))
                let cjsonparse4: cJSON = tccjsonobj.KH418_cJSON_Parse(value4);
                hilog.info(0x0000, 'testTag', 'cjson parse = %{public}s', JSON.stringify(cjsonparse4));
                this.testcont = this.testcont.replace('%{cjsonparse4}s', JSON.stringify(cjsonparse4))
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
