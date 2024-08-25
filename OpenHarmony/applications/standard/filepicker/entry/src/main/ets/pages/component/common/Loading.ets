/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
export struct Loading {
  @Prop isLoading: boolean
  iconWidth: number = 60
  iconHeight: number = 60
  color: Resource = $r('sys.color.ohos_id_color_text_secondary')
  title: Resource = $r('app.string.loading')
  containerHeight: number | string = '100%'

  build() {
    Column() {
      LoadingProgress()
        .width(this.iconWidth)
        .height(this.iconHeight)
        .color(this.color)

      Text(this.title)
        .fontSize($r('sys.float.ohos_id_text_size_body2'))
        .fontColor($r('sys.color.ohos_id_color_text_secondary'))
        .margin({ top: 5 })
    }
    .width('100%')
    .height(this.containerHeight)
    .alignItems(HorizontalAlign.Center)
    .justifyContent(FlexAlign.Center)
    .visibility(this.isLoading ? Visibility.Visible : Visibility.None)
  }
}