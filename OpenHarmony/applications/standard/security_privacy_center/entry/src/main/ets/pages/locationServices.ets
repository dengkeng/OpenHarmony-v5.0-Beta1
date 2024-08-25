/**
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

import ViewModel from '../model/locationServicesImpl/LocationViewModel';
import Logger from '../common/utils/Logger';
import HeadComponent from '../common/components/headComponent';
import HiSysEventUtil from '../common/utils/HiSysEventUtil';

const TAG: string = 'LocationServicesPage'

/**
 * LocationServices
 */
@Entry
@Component
struct LocationServices {
  @StorageLink('LocationServiceStatus') locationServiceStatus: boolean = false;

  build() {
    Column() {
      GridRow({ columns: { sm: 4, md: 6, lg: 8 }, gutter: 12 }) {
        GridCol({ span: { sm: 4, md: 6, lg: 8 }, offset: { sm: 0, md: 1, lg: 2 } }) {
          Column() {
            HeadComponent({ headName: $r('app.string.locationServicesTab'), isActive: true });

            Flex({
              direction: FlexDirection.Row,
              justifyContent: FlexAlign.SpaceBetween,
              alignItems: ItemAlign.Center
            }) {
              Text($r('app.string.positionInformation'))
                .fontColor($r('app.color.font_color_182431'))
                .fontStyle(FontStyle.Normal)
                .fontSize($r('app.float.location_font_size'))
                .margin({ left: $r('app.float.distance_12') })

              Toggle({ type: ToggleType.Switch, isOn: this.locationServiceStatus })
                .margin({ right: $r('app.float.padding_or_margin_s') })
                .width('36vp')
                .height('20vp')
                .selectedColor('#007DFF')
                .onChange((isOn: boolean) => {
                  Logger.info(TAG, 'location service status is :' + this.locationServiceStatus);
                  if (isOn) {
                    ViewModel.enableLocation();
                    HiSysEventUtil.reportLocationFlagClick(1)
                  } else {
                    ViewModel.disableLocation();
                    HiSysEventUtil.reportLocationFlagClick(0)
                  }
                });
            }
            .margin({ top: $r('app.float.padding_or_margin_m') })
            .height($r('app.float.wh_value_56'))
            .backgroundColor($r('app.color.white_bg_color'))
            .borderRadius($r('sys.float.ohos_id_corner_radius_default_l'))
          }
        }
      }
      .margin({ left: $r('app.float.grid_row_margin'), right: $r('app.float.grid_row_margin') })
    }
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))
    .width('100%')
    .height('100%')
  }

  aboutToAppear(): void {
    Logger.info(TAG, 'location service about to appear');
    ViewModel.initViewModel();
  }

  aboutToDisappear(): void {
    Logger.info(TAG, 'location service about to disappear');
  }
}