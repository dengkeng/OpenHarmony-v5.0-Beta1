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
import { TcBaseSample } from '../../../interface/tctsample'
import hilog from '@ohos.hilog';
import { TcNADataType } from '../../../interface/tctnadatatype';
import { TCTYPE } from '../../../interface/tctbase';
import { TcCJsonSample } from '../../../interface/tctcjsonsample';
// import Benchmark from '../../../../js/benchmark/index';

const TAG: string = 'napi_roi';

@Entry
@Component
struct napisetinstancedata {
  private btnFontColor: Resource = $r('app.color.white');
  private pixelMapFormat: image.PixelMapFormat = 3;
  @State isSetInstance: Boolean = false;
  @State imagePixelMap: PixelMap | undefined = undefined;
  @State textcont: string = '一个 Node.js 环境对应一个 ECMAScript Agent。在主进程中，启动时创建一个环境，'
    + '可以在单独的线程上创建额外的环境作为 工作线程。当 Node.js 嵌入到另一个应用中时，应用的主线程也可能在应用的生命周期'
    + '中多次构造和销毁 Node.js 环境，使得应用创建的每个 Node.js 环境可能，在 反过来，在其生命周期中创建和销毁额外的环境作为工作线程。'
    + '从原生插件的角度来看，这意味着它提供的绑定可以从多个上下文中多次调用，甚至可以同时从多个线程中调用。'
    + '原生插件可能需要分配它们在 Node.js 环境的生命周期中使用的全局状态，以便该状态对于插件的每个实例都是唯一的。'
    + '为此，Node-API 提供了一种关联数据的方法，使其生命周期与 Node.js 环境的生命周期相关联。'
  @State testcont: string = ' // 获取导出的 N-API 实例对象 \n'
    + ' const instance = addon.instance; \n'
    + ' // 使用实例对象进行操作 \n'
    + ' console.log(instance); // 输出 N-API 实例对象 \n'
    + ' // 获取与实例对象关联的自定义数据 \n'
    + '  const myData = addon.getInstanceData(instance); \n'
    + ' // 使用获取的自定义数据 \n'
    + ' console.log(myData); // 输出自定义数据 \n';

  controller: TextAreaController = new TextAreaController()

  build() {
    Column() {
      // 标题
      TitleBar({ title: $r('app.string.napi_set_instance_data') })

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
            Button($r('app.string.napi_set_instance_data'), { type: ButtonType.Capsule })
              .backgroundColor(Color.Blue)
              .width('80%')
              .height(48)
              .fontSize(16)
              .fontWeight(500)
              .fontColor(this.btnFontColor)
              .margin({ left: 24 })
              .id('napi_set_instance_data')
              .onClick(() => {
                let addres = testNapi.add(5, 8);
                hilog.info(0x0000, 'testTag', `addres : ${addres}`);
                let baseobj = testNapi.getTestCase(1);
                hilog.info(0x0000, 'testTag', `baseobj : ${baseobj.name}`);
                let tcbaseobj = baseobj as TcBaseSample;
                hilog.info(0x0000, 'testTag', `baseobj.add : ${tcbaseobj.add(1, 2)}`);
                // let type : TCTYPE = TCTYPE.TCT_NADATATYPE;
                let naobj = testNapi.getTestCase(2);
                hilog.info(0x0000, 'testTag', `naobj : ${naobj.name}`);
                let tcnadatatypeobj = naobj as TcNADataType;
                hilog.info(0x0000, 'testTag', `tcnadatatypeobj.testNapiStatus : ${tcnadatatypeobj.testNapiStatus(1, 2)}`);
                let cjobj = testNapi.getTestCase(7);
                hilog.info(0x0000, 'testTag', `cjobj : ${cjobj.name}`);
                let tccjsonobj = cjobj as TcCJsonSample;
                hilog.info(0x0000, 'testTag', `tccjsonobj.cjson_version : ${tccjsonobj.cjson_version()}`);
                let instanceobj: Object = testNapi.instance;
                let ret1 = `instance ${instanceobj} `
                let ret2 = ' ld.lld: error: undefined symbol: napi_set_instance_data '
                hilog.info(0x0000, 'testTag', ret1);

                // let benversion = Benchmark.version;
                // hilog.info(0x0000, 'testTag', `benchmark version : ${benversion}`);
                // hilog.info(0x0000, 'testTag', `instance ${instanceobj.testint32} `);
                this.testcont = this.testcont.replace('log(instance)', 'log(## '+ret1+' ##)');
                this.testcont = this.testcont.replace('log(myData)', 'log(## '+ret2+' ##)');
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
