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

import Constants from '../../common/constants/ComConstant';
import ResourceUtil from '../../common/utils/ResourceUtil';
import { AutoMenuViewState } from '../../main/auto_menu/AutoMenuViewState';
import MenuInfo from '../../common/bean/MenuInfo';

@Component
export default struct PrivacyProtectionListView {
  // Function access list data
  @Prop menuViewState: AutoMenuViewState;
  private itemClickEvent = (menuInfo: MenuInfo) => {
  };

  build() {
    Column() {
      List({ space: Constants.DEFAULT_SPACE }) {
        ForEach(this.menuViewState.listMenuList, (item: MenuInfo) => {
          ListItem() {
            PrivacyProtectionItem({ menuInfo: item, itemClickEvent: this.itemClickEvent })
              .visibility(item !== undefined && item !== null ? Visibility.Visible : Visibility.None)
          }
        }, (item: MenuInfo) => JSON.stringify(item))
      }
      .borderRadius($r('sys.float.ohos_id_corner_radius_card'))
      .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
      .margin({
        top: this.menuViewState.cardMenuList.length === 0 ? 0 : $r('app.float.function_access_list_default_margin_top'),
        bottom: $r('app.float.function_access_list_margin_bottom')
      })
    }
    .visibility(this.menuViewState.listMenuList.length !== 0 ? Visibility.Visible : Visibility.None)
  }
}

@Component
struct PrivacyProtectionItem {
  @Prop menuInfo: MenuInfo;
  @State isTouched: boolean = false;
  private itemClickEvent = (menuInfo: MenuInfo) => {
  }

  build() {
    Row() {
      Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
        Text(this.menuInfo.titleString)
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
        })
        .margin({
          left: $r('sys.float.ohos_id_text_margin_horizontal'),
        })
      }
      .hoverEffect(HoverEffect.Highlight)
      .onClick(() => {
        this.itemClickEvent(this.menuInfo)
      })
      .backgroundColor(this.isTouched ? $r('sys.color.ohos_id_color_click_effect') : $r('sys.color.ohos_id_color_list_card_bg'))
      .onTouch((event?: TouchEvent | undefined) => {
        if (event?.type === TouchType.Down) {
          this.isTouched = true;
        }
        if (event?.type === TouchType.Up) {
          this.isTouched = false;
        }
      })
      .padding({
        left: $r('app.float.function_access_inside_list_padding'),
        top: $r('app.float.function_access_list_padding_top'),
        right: $r('app.float.function_access_inside_list_padding'),
        bottom: $r('app.float.function_access_list_padding_top'),
      })
      .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
      .borderRadius(ResourceUtil.getFloatNumber($r('sys.float.ohos_id_corner_radius_default_l')) - 4)
    }
    .width(Constants.WIDTH_HEIGHT_FULL_SCREEN)
    .borderRadius($r('sys.float.ohos_id_corner_radius_default_l'))
    .padding($r('app.float.function_access_list_padding'))
    .backgroundColor($r('sys.color.ohos_id_color_list_card_bg'))
    .enabled(this.menuInfo.isClickable === 1)
    .visibility(this.menuInfo.isSupport ? Visibility.Visible : Visibility.None)
  }
}





