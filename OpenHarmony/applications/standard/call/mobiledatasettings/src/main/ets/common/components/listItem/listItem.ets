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
import publiccontent from '../publiccontent'
import router from '@system.router';
import call from '@ohos.telephony.call';
import {
  enableCellularDataRoamingCardOne,
  enableCellularDataRoamingCardTwo,
  disableCellularDataRoamingCardOne,
  disableCellularDataRoamingCardTwo,
  enableImsSwitchCardOne,
  enableImsSwitchCardTwo,
  disableImsSwitchCardOne,
  disableImsSwitchCardTwo
} from '../../../model/mobileDataStatus';
import LogUtils from '../../utils/LogUtils'

const TAG = 'ListItem'

@Component
export default struct listItem {
  @Prop isCard: boolean;
  @Prop isBtn: boolean;
  @Prop isDisabled: boolean;
  @Prop cardType: number;
  @Link controlSwitch: boolean;
  @State title: Resource = $r('app.string.mobile_data_dataRoaming');
  @State describe: Resource = $r('app.string.mobile_data_enableDataWhileRoaming');
  @Prop isSupport: boolean;
  @State titleopacity: boolean = false;
  @Prop isCon: number;
  @State ceshi: boolean = true;
  dialogTitle: string = '';
  radio_state_enable5g = 'RADIO_STATE_ENABLE5G';
  recordTypeDialog: CustomDialogController = new CustomDialogController({
    builder: dataRomingDialog({ isCon: this.isCon, isMsg: $controlSwitch, cardType: this.cardType }),
    alignment: DialogAlignment.Bottom,
    autoCancel: false,
    offset: { dx: 0, dy: -16 }
  })

  clickHandle() {
    if (this.isCon == 6) {
      router.push({
        uri: 'pages/senior'
      })
    };
    if (this.isCon === 5) {
      router.push({
        uri: 'pages/availableNetwork'
      })
    };
    if (this.isCon == 2) {
      router.push({
        uri: 'pages/apnPages'
      })
    };
  };

  aboutToDisappear() {
    this.recordTypeDialog = null;
  }

  build() {
    Column() {
      Row() {
        Flex({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center }) {
          Column() {
            Text(this.title)
              .fontFamily('HarmonyHeiTi')
              .fontSize($r('sys.float.ohos_id_text_size_body1'))
              .fontWeight(FontWeight.Medium)
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .opacity(this.controlSwitch ? 0.9 : 0.6)
              .visibility(this.isSupport ? Visibility.None : Visibility.Visible)
              .letterSpacing(1)
              .lineHeight(22)
              .textAlign(TextAlign.Start)
            Text(this.describe)
              .margin({ top: 2 })
              .fontFamily('HarmonyHeiTi')
              .fontWeight(FontWeight.Regular)
              .fontSize($r('sys.float.ohos_id_text_size_body2'))
              .fontColor($r('sys.color.ohos_id_color_text_secondary'))
              .opacity(0.6)
              .lineHeight(19)
              .letterSpacing(1)
              .visibility(this.describe == $r('app.string.mobile_empty_string') ? Visibility.None : Visibility.Visible)
          }
          .width('100%')
          .alignItems(HorizontalAlign.Start)
          .margin({ right: 26 })
          .onClick(() => {
            LogUtils.i(TAG, 'onclick clickHandle')
            this.clickHandle();
          })
          .enabled(this.isDisabled)

          Toggle({ type: ToggleType.Switch, isOn: this.controlSwitch })
            .width(36)
            .height(20)
            .enabled(this.isDisabled)
            .onChange((isOn: boolean) => {
              this.controlSwitch = !this.controlSwitch;
              LogUtils.i(TAG, 'onclick cardType is :' + JSON.stringify(this.cardType) + 'switcher is:' + JSON.stringify(this.isCon) + 'Switch status:' + this.controlSwitch);
              if (this.controlSwitch && this.isCon === 0) {
                this.recordTypeDialog.open();
              } else if (this.controlSwitch == false && this.isCon === 0) {
                  this.cardType === 0 ? disableCellularDataRoamingCardOne() : disableCellularDataRoamingCardTwo();
              }
              if (this.isCon === 22 && this.controlSwitch) {
                  this.cardType === 0 ? enableImsSwitchCardOne() : enableImsSwitchCardTwo();
              } else if (this.isCon === 22 && this.controlSwitch === false) {
                  this.cardType === 0 ? disableImsSwitchCardOne() : disableImsSwitchCardTwo();
              }
            })
            .visibility(this.isBtn ? Visibility.Visible : Visibility.None)
        }.visibility(this.isSupport ? Visibility.None : Visibility.Visible)
      }
    }
    .backgroundColor($r('sys.color.ohos_id_color_foreground_contrary'))
    .opacity(this.isDisabled ? 1 : 0.4)
    .margin({ top: 8, bottom: this.isSupport ? 5 : 11 })
    .onClick(() => {
      if (!this.isDisabled) {
        return;
      } else {
        this.clickHandle();
      }
    })
  }
}

@CustomDialog
struct dataRomingDialog {
  controller: CustomDialogController;
  isCon: number;
  @Link isMsg: boolean;
  cardType: number;

  build() {
    Column() {
      Column() {
        Text($r('app.string.mobile_data_tips'))
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontFamily('HarmonyHeiTi')
          .height(56)
          .align(Alignment.Center)
        Text($r('app.string.mobile_data_turn_on_data_roaming'))
          .fontSize($r('sys.float.ohos_id_text_size_body1'))
          .fontWeight(FontWeight.Regular)
          .textAlign(TextAlign.Start)
          .fontFamily('HarmonyHeiTi')
          .letterSpacing(3)
          .visibility(this.isCon == 0 ? Visibility.Visible : Visibility.None)
      }
      .alignItems(HorizontalAlign.Start)

      Flex({ justifyContent: FlexAlign.SpaceAround }) {
        Text(publiccontent.strings.cancel)
          .fontWeight(FontWeight.Medium)
          .fontFamily('HarmonnyHeiTi')
          .height(21)
          .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
          .fontSize($r('sys.float.ohos_id_text_size_button1'))
          .onClick(() => {
            LogUtils.i(TAG, 'dataRomingDialog onclick cancel');
            this.controller.close();
            this.isMsg = false;
          })
        Divider().vertical(true).height(1).strokeWidth(1).lineCap(LineCapStyle.Round).opacity(0.5)

        Text(publiccontent.strings.confirm)
          .fontWeight(FontWeight.Medium)
          .fontFamily('HarmonnyHeiTi')
          .height(21)
          .fontColor($r('sys.color.ohos_id_color_text_primary_activated'))
          .fontSize($r('sys.float.ohos_id_text_size_button1'))
          .onClick(() => {
            LogUtils.i(TAG, 'dataRomingDialog onclick confim toggletype: ' + JSON.stringify(this.isCon) + ' for cardtype:' + JSON.stringify(this.cardType));
            this.controller.close();
            this.isMsg = true;
            this.cardType == 0 ? enableCellularDataRoamingCardOne() : enableCellularDataRoamingCardTwo();
          })
      }
      .margin({ top: 8 })
      .height(56)
      .padding({top: 12})
    }
    .padding({ left: 24, right: 24 })
    .borderRadius(20)
  }
}

