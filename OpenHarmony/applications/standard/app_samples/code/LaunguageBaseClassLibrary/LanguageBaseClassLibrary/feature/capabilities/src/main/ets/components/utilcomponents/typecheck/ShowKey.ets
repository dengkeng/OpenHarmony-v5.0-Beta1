/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

@Component
export struct ShowKey {
  @State result: string = ' ';
  @Link checkResult: string;
  @Link presetValue: Array<Int8Array | Number | String | Boolean>;

  build() {
    Button() {
      Text($r('app.string.show'))
        .fontColor(Color.Black)
        .fontSize(20)
        .textAlign(TextAlign.Center)
        .width('85%')
    }
    .key('displayPresetValue')
    .type(ButtonType.Capsule)
    .backgroundColor('#0D9FFB')
    .padding(5)
    .margin({ top: 10 })
    .onClick(() => {
      this.checkResult = `numberVal = ${this.presetValue[0]}\n`
      +`stringVal = ${this.presetValue[1]}\n`
      +`booleanVal = ${this.presetValue[2]}\n`
      +`int8Array = ${this.presetValue[3]}`;
    })
  }
}