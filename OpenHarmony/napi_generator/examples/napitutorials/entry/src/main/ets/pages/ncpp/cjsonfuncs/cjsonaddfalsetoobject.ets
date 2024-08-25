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
    + ' let valueObj: cJSON = {next: null,prev: null,child: null,type: 0,valuestring: "",valueint: 0,valuedouble: 0,string: ""} \n'
    + ' let name = "is_student" \n'
    + ' let cjsonaddfalsetoobj: cJSON = tccjsonobj.KH545_cJSON_AddFalseToObject(valueObj, name) \n'
    + ' hilog.info(cjson add false to object = %{cjsonaddfalsetoobj}s); \n'

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
                let valueObj: cJSON = {
                  next: null,
                  prev: null,
                  child: null,
                  type: 0,
                  valuestring: '',
                  valueint: 0,
                  valuedouble: 0,
                  string: ''
                }
                let name = "is_student"
                let cjsonaddfalsetoobj: cJSON = tccjsonobj.KH545_cJSON_AddFalseToObject(valueObj, name)
                hilog.info(0x0000, 'testTag', 'cjson add false to object = %{public}s', JSON.stringify(cjsonaddfalsetoobj));
                this.testcont = this.testcont.replace('%{cjsonaddfalsetoobj}s', JSON.stringify(cjsonaddfalsetoobj))
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
