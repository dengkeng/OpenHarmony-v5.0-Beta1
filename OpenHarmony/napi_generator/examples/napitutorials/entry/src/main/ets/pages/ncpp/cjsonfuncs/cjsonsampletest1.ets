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
    + ' 一、 {"type":"rect","height":1080,"width":1920,"interface":false,"frame rate":24} 类型 \n'
    + ' 1. 创建cJSON对象 \n'
    + ' let cjsonObj: cJSON = tccjsonobj.KH361_cJSON_CreateObject(); \n'
    + ' 2. 向cJSON对象中添加数据 \n'
    + ' cjsonObj = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj, "type", "rect");\n'
    + ' hilog.info(cjson add string to object = %{cjsonaddstringtoobj}s); \n'
    + ' cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "height", 1080);\n'
    + ' cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "width", 1920);\n'
    + ' hilog.info(cjson add number to object = %{cjsonaddnumbertoobj}s); \n'
    + ' cjsonObj = tccjsonobj.KH545_cJSON_AddFalseToObject(cjsonObj, "interface"); \n'
    + ' hilog.info(cjson add false to object = %{cjsonaddfalsetoobj}s); \n'
    + ' cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "frame rate", 24);\n'
    + ' hilog.info(cjsonObj = %{cjsonObj}s); \n'
    + ' 3. 打印cJSON对象 \n'
    + ' let cjsonResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj); \n'
    + ' hilog.info(cjson print cjsonObj = %{cjsonResStr}s); \n\n'
    + ' 二、 {"testObj":{"type":"rect"}} 类型 \n'
    + ' 1. 创建cJSON对象 \n'
    + ' let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject(); \n'
    + ' 2. 向cJSON对象中添加数据 \n'
    + ' let cjsonObj3: cJSON = tccjsonobj.KH361_cJSON_CreateObject(); \n'
    + ' cjsonObj3 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj3, "type", "rect"); \n'
    + ' cjsonObj2 = tccjsonobj.KH180_cJSON_AddItemToObject(cjsonObj2, "testObj", cjsonObj3); \n'
    + ' hilog.info(cjson cjsonObj2 = %{cjsonObj2}s); \n'
    + ' 3. 打印cJSON对象 \n'
    + ' let cjsonObjResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj2); \n'
    + ' hilog.info(cjson print cjsonObj2 = %{cjsonObjResStr}s);  \n'

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
                // {"type":"rect","height":1080,"width":1920,"interface":false,"frame rate":24}
                // 创建一个空对象
                let cjsonObj: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
                // 向对象中添加元素
                cjsonObj = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj, "type", "rect");
                hilog.info(0x0000, 'testTag', 'cjson add string to object = %{public}s', JSON.stringify(cjsonObj));
                this.testcont = this.testcont.replace('%{cjsonaddstringtoobj}s', JSON.stringify(cjsonObj))
                cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "height", 1080);
                cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "width", 1920);
                hilog.info(0x0000, 'testTag', 'cjson add number to object = %{public}s', JSON.stringify(cjsonObj));
                this.testcont = this.testcont.replace('%{cjsonaddnumbertoobj}s', JSON.stringify(cjsonObj))
                cjsonObj = tccjsonobj.KH545_cJSON_AddFalseToObject(cjsonObj, "interface");
                hilog.info(0x0000, 'testTag', 'cjson add false to object = %{public}s', JSON.stringify(cjsonObj));
                this.testcont = this.testcont.replace('%{cjsonaddfalsetoobj}s', JSON.stringify(cjsonObj))
                cjsonObj = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj, "frame rate", 24);
                hilog.info(0x0000, 'testTag', 'cjsonObj = %{public}s', JSON.stringify(cjsonObj));
                this.testcont = this.testcont.replace('%{cjsonObj}s', JSON.stringify(cjsonObj))
                let cjsonResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj);
                console.info("Test NAPI cJSON_Sample_test1 result cjsonResStr: " + JSON.stringify(cjsonResStr));
                hilog.info(0x0000, 'testTag', 'cjson print cjsonObj = %{public}s', JSON.stringify(cjsonResStr));
                this.testcont = this.testcont.replace('%{cjsonResStr}s', JSON.stringify(cjsonResStr))
                // {"testObj":{"type":"rect"}}
                let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
                let cjsonObj3: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
                cjsonObj3 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj3, "type", "rect");
                cjsonObj2 = tccjsonobj.KH180_cJSON_AddItemToObject(cjsonObj2, "testObj", cjsonObj3);
                console.info("Test NAPI cJSON_Sample_test1 result cjsonObj2: ", JSON.stringify(cjsonObj2))
                hilog.info(0x0000, 'testTag', 'cjson add item to object = %{public}s', JSON.stringify(cjsonObj2));
                this.testcont = this.testcont.replace('%{cjsonObj2}s', JSON.stringify(cjsonObj2))
                let cjsonObjResStr: string = tccjsonobj.KH735_cJSON_Print(cjsonObj2);
                console.info("Test NAPI cJSON_Sample_test1 result cjsonObjResStr: " + JSON.stringify(cjsonObjResStr));
                hilog.info(0x0000, 'testTag', 'cjson print cjsonObj2 = %{public}s', JSON.stringify(cjsonObjResStr));
                this.testcont = this.testcont.replace('%{cjsonObjResStr}s', JSON.stringify(cjsonObjResStr))
              })
          }
          .width('100%')
          .height(48)
          .alignItems(VerticalAlign.Center)
          .justifyContent(FlexAlign.SpaceBetween)
        }
        .width('100%')
        .margin({bottom: '10%'})
      }

    }
    .height('100%')
    .width('100%')
    .backgroundColor($r('app.color.background_shallow_grey'))
  }
}
