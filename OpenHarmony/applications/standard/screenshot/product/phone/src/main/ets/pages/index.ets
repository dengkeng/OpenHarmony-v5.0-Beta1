/*
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

import Log from '../../../../../../common/src/main/ets/default/Log';
import Constants from '../common/constants';
import ViewModel from '../vm/ViewModel';

const TAG = 'ScreenShot-Index';

@Entry
@Component
struct Index {
  @StorageLink('captureImage') captureImage: string = '';
  @StorageLink('imageFilename') imageFilename: string = '';

  build() {
    Stack({ alignContent: Alignment.Bottom }) {
      Column() {
        Image(this.captureImage)
          .border({ color: Color.White, radius: 8, width: 8 });
      }
      .width(Constants.FULL_CONTAINER_WIDTH)
      .height(Constants.FULL_CONTAINER_HEIGHT)
      .onClick(() => {
        ViewModel.StartPhotosAbility(this.imageFilename);
      });
    }
    .width(Constants.FULL_CONTAINER_WIDTH)
    .height(Constants.FULL_CONTAINER_HEIGHT);
  }

  aboutToAppear() {
    Log.showInfo(TAG, 'aboutToAppear');
    setTimeout(ViewModel.CloseShotScreen, Constants.interval);
  }
}