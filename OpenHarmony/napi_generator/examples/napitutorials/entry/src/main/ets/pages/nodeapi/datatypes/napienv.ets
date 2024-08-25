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

const TAG: string = 'napi_env';

@Entry
@Component
struct napienv {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = 'napi_env 用于表示底层 Node-API 实现可用于持久化 VM 特定状态的上下文。此结构在调用时传递给原生函数，'
    + '并且在进行 Node-API 调用时必须传回。具体来说，调用初始原生函数时传入的相同 napi_env 必须传递给任何后续的嵌套 Node-API 调用。'
    + '出于一般重用的目的缓存 napi_env，以及在不同 Worker 线程上运行的同一插件的实例之间传递 napi_env 是不允许的。当卸载原生插件的实例时，'
    + 'napi_env 变得无效。此事件的通知通过给 napi_add_env_cleanup_hook 和 napi_set_instance_data 的回调传递。'
  @State testcont: string = ' // 测试 N-API env对象 \n'
    + '  const myData = addon.testNapiEnv(); \n'
    + ' // 使用获取的自定义数据 \n'
    + ' console.log(myData); // 输出自定义数据 \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_env') })

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

          Button($r('app.string.napi_env'), { type: ButtonType.Capsule })
            .backgroundColor(Color.Blue)
            .width('80%')
            .height(48)
            .fontSize(16)
            .fontWeight(500)
            .fontColor(this.btnFontColor)
            .margin({ left: 24 })
            .id('napi_env')
            .onClick(() => {
              let ret = testNapi.testNapiEnv();
              this.testcont = this.testcont.replace('log(myData)', 'log(## '+ret+' ##)');
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
