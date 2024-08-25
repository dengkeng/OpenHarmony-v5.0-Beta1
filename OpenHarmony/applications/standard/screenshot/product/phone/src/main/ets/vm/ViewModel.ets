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
import ShotScreenModel from '../../../../../../features/screenshot/src/main/ets/com/ohos/model/screenShotModel';
import Want from '@ohos.app.ability.Want';

const TAG = 'ScreenShot-ViewModel';
const GALLERY_BUNDLE = 'com.ohos.photos';
const GALLERY_ABILITY = 'com.ohos.photos.MainAbility';

export class ViewModel {
  constructor() {
    this.ViewModelInit();
  }

  ViewModelInit(): void {
    Log.showInfo(TAG, 'ViewModelInit');
  }

  StartPhotosAbility(imageFileName: string): void {
    Log.showInfo(TAG, `StartPhotosAbility imageFileName:${imageFileName}`);
    const wantData: Want = {
      bundleName: GALLERY_BUNDLE,
      abilityName: GALLERY_ABILITY,
      parameters: {
        uri: imageFileName
      }
    };
    ShotScreenModel.openAbility(wantData);
    //close window
    ShotScreenModel.dismiss();
  }

  CloseShotScreen(): void {
    //close window
    ShotScreenModel.dismiss();
  }
}

let viewModel = new ViewModel();

export default viewModel as ViewModel;