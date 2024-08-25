/**
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

const MODULE_TAG = 'ExtWallpaper : ';

@Entry
@Component
struct Index {
  @StorageLink('slPixelData') pixelData: any = [];

  build() {
    Flex({direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Center}) {
      Image(this.pixelData);
    }
    .width('100%')
    .height('100%');
  }

  aboutToAppear() {
    console.info(MODULE_TAG + 'index page about to  appear');
  }

  onPageShow() {
    console.info(MODULE_TAG + 'index page show');
  }
}
