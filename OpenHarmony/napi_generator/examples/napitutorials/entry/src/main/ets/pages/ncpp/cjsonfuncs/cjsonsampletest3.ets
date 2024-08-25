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
    + ' 1. 创建cJSON数组对象 \n'
    + ' let resultArray: cJSON = tccjsonobj.KH386_cJSON_CreateArray(); \n'
    + ' 2. 向cJSON数组对象中添加数据 \n'
    + ' let cjsonObj1: cJSON = tccjsonobj.KH361_cJSON_CreateObject();\n'
    + ' cjsonObj1 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj1, "precision", "zip"); \n'
    + ' cjsonObj1 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj1, "Latitude", 37.7668);\n'
    + ' resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj1);\n'
    + ' let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject(); \n'
    + ' cjsonObj2 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj2, "precision", "zip2"); \n'
    + ' cjsonObj2 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj2, "Latitude", 37.371991); \n'
    + ' resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj2);\n'
    + ' hilog.info(cjson resultArray = %{resultArray}s); \n'
    + ' 3. 打印cJSON数组对象 \n'
    + ' let cjsonArrResStr2: string = tccjsonobj.KH735_cJSON_Print(resultArray); \n'
    + ' hilog.info(cjson print cjsonArrResStr2 = %{cjsonArrResStr2}s); \n\n'

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

                // print [{"precision":"zip","Latitude":37.7668},{"precision":"zip","Latitude":37.371991}]
                let resultArray: cJSON = tccjsonobj.KH386_cJSON_CreateArray();
                let cjsonObj1: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
                cjsonObj1 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj1, "precision", "zip");
                cjsonObj1 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj1, "Latitude", 37.7668);
                let cjsonObjResStr1: string = tccjsonobj.KH735_cJSON_Print(cjsonObj1);
                console.info("Test NAPI cJSON_Sample_test3 result cjsonObjResStr1: " + JSON.stringify(cjsonObjResStr1));
                resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj1);
                console.info("Test NAPI cJSON_Sample_test3 result resultArray1: " + JSON.stringify(resultArray));
                let cjsonArrResStr1: string = tccjsonobj.KH735_cJSON_Print(resultArray);
                console.info("Test NAPI cJSON_Sample_test3 result cjsonArrResStr1: " + JSON.stringify(cjsonArrResStr1));
                let cjsonObj2: cJSON = tccjsonobj.KH361_cJSON_CreateObject();
                cjsonObj2 = tccjsonobj.KH526_cJSON_AddStringToObject(cjsonObj2, "precision", "zip2");
                cjsonObj2 = tccjsonobj.KH206_cJSON_AddNumberToObject(cjsonObj2, "Latitude", 37.371991);
                let cjsonObjResStr2: string = tccjsonobj.KH735_cJSON_Print(cjsonObj2);
                console.info("Test NAPI cJSON_Sample_test3 result cjsonObjResStr2: " + JSON.stringify(cjsonObjResStr2));
                resultArray = tccjsonobj.KH802_cJSON_AddItemToArray(resultArray, cjsonObj2);
                hilog.info(0x0000, 'testTag', 'cjson add item to array resultArray = %{public}s', JSON.stringify(resultArray));
                this.testcont = this.testcont.replace('%{resultArray}s', JSON.stringify(resultArray))
                let cjsonArrResStr2: string = tccjsonobj.KH735_cJSON_Print(resultArray);
                hilog.info(0x0000, 'testTag', 'cjson print resultArray = %{public}s', JSON.stringify(cjsonArrResStr2));
                this.testcont = this.testcont.replace('%{cjsonArrResStr2}s', JSON.stringify(cjsonArrResStr2))
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
