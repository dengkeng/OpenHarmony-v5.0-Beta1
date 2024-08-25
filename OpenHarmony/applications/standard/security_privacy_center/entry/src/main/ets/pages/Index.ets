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

import Logger from '../common/utils/Logger';
import common from '@ohos.app.ability.common';
import BundleInfoModel from '../model/bundleInfo/BundleInfoModel';
import bundleManager from '@ohos.bundle.bundleManager';
import { StringUtil } from '../common/utils/StringUtil';
import Constants from '../common/constants/ComConstant';
import { BusinessError } from '@ohos.base';
import TitleBar from '../common/components/TitleBarComponent';
import PrivacyProtectionListView from '../view/privacy/PrivacyProtectionListView';
import router from '@ohos.router';
import ResourceUtil from '../common/utils/ResourceUtil';
import HiSysEventUtil from '../common/utils/HiSysEventUtil';
import HiSysEventConstant from '../common/constants/HiSysEventConstant';
import { AutoMenuClickIntent, AutoMenuRefreshIntent } from '../main/auto_menu/AutoMenuIntent';
import { AutoMenuViewModel } from '../main/auto_menu/AutoMenuViewModel';
import MenuInfo from '../common/bean/MenuInfo';

const TAG: string = 'Index';
const autoMenuViewModel: AutoMenuViewModel = new AutoMenuViewModel();
let storage = LocalStorage.getShared();

@Entry(storage)
@Component
struct Index {
  @State startTime: number = 0;
  private context = getContext(this) as common.UIAbilityContext;
  @State isSplitMode: boolean = false;
  scroller: Scroller = new Scroller();
  @State windowWidth: number = 0;

  @Styles
  PressedStyles() {
    .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  }

  @Styles
  normalStyles() {
    .backgroundColor($r('sys.color.ohos_id_color_list_card_bg'))
  }

  onPageShow() {
    this.startTime = new Date().getTime();
    autoMenuViewModel.processIntent(new AutoMenuRefreshIntent(this.context));
    this.getBundleInfo();
  }

  //  Get all package information
  getBundleInfo() {
    BundleInfoModel.getAllBundleInfoByFunctionAccess()
      .then(async (data: bundleManager.BundleInfo[]) => {
        //   filter blank icon and text label resources
        let initAppInfoList: bundleManager.ApplicationInfo[] = [];
        for (let i = 0; i < data.length; i++) {
          let info = data[i]
          if (StringUtil.isNotEmpty(info.appInfo.icon)) {
            initAppInfoList = initAppInfoList.concat(info.appInfo);
          }
        }
        if (initAppInfoList?.length) {
          AppStorage.setOrCreate(Constants.INIT_APP_INFO_LIST, initAppInfoList)
        }
      })
  }

  build() {
    Column() {
      TitleBar({
        title: JSON.stringify($r('app.string.EntryAbility_label')),
        isSplitMode: this.isSplitMode,
      }).padding({
        left: $r('sys.float.ohos_id_default_padding_start'),
        right: $r('sys.float.ohos_id_default_padding_end')
      })

      Scroll(this.scroller) {
        Column() {
          //   Function access' list 'component
          PrivacyProtectionListView({
            menuViewState: autoMenuViewModel.getViewState(),
            itemClickEvent: ((menuInfo: MenuInfo) => {
              autoMenuViewModel.processIntent(new AutoMenuClickIntent(menuInfo));
            })
          })
          //  Location information component
          Row() {
            Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
              Text($r('app.string.locationServicesTab'))
                .fontColor($r('sys.color.ohos_id_color_text_primary'))
                .textAlign(TextAlign.Start)
                .fontFamily('HarmonyHeiTi')
                .fontWeight(FontWeight.Medium)
                .fontSize($r('sys.float.ohos_id_text_size_body1'))
              Row() {
                Image($r('app.media.ic_settings_arrow'))
                  .width($r('app.float.width_height_xs'))
                  .height($r('app.float.width_height_m'))
                  .align(Alignment.End)
                  .fillColor($r('sys.color.ohos_id_color_fourth'))
                  .draggable(false)
              }
              .padding({
                top: $r('app.float.function_access_inside_list_padding'),
                bottom: $r('app.float.function_access_inside_list_padding'),
                left: $r('app.float.function_access_list_padding_top'),
                right: $r('app.float.function_access_list_padding_top')
              })
              .margin({
                left: $r('sys.float.ohos_id_text_margin_horizontal'),
              })
            }
            .stateStyles({
              pressed: this.PressedStyles,
              normal: this.normalStyles
            })
            .padding({
              top: $r('app.float.book_mark_padding'),
              bottom: $r('app.float.book_mark_padding'),
              left: $r('app.float.function_access_inside_list_padding'),
              right: $r('app.float.function_access_inside_list_padding')
            })
            .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
            .hoverEffect(HoverEffect.Highlight)
            .borderRadius(ResourceUtil.getFloatNumber($r('sys.float.ohos_id_corner_radius_default_l')) - 4)
            .onClick(async () => {
              // Positioning service management
              HiSysEventUtil.reportLocationClick('LOCATION')

              router.pushUrl({
                url: 'pages/locationServices'
              }, router.RouterMode.Standard).then(() => {
                Logger.info(TAG, 'succeeded in jumping to the locationServices page.')
              }).catch((err: BusinessError) => {
                Logger.error(TAG, `Failed to jump to the locationServices page.code is ${err.code}.message is ${err.message}`);
              })
            })
          }
          .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
          .borderRadius($r('sys.float.ohos_id_corner_radius_default_l'))
          .padding($r('app.float.function_access_list_padding'))
          .backgroundColor($r('sys.color.ohos_id_color_list_card_bg'))
        }
      }
      .height(Constants.WIDTH_HEIGHT_FULL_SCREEN)
      .scrollable(ScrollDirection.Vertical)
      .edgeEffect(EdgeEffect.Spring)
      .margin({
        bottom: $r('app.float.index_margin_bottom')
      })
      .padding({
        left: $r('sys.float.ohos_id_default_padding_start'),
        right: $r('sys.float.ohos_id_default_padding_end')
      })
      .align(Alignment.Top)
    }
    .height(Constants.WIDTH_HEIGHT_FULL_SCREEN)
    .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
    .backgroundColor($r('sys.color.ohos_id_color_sub_background'))

  }
}