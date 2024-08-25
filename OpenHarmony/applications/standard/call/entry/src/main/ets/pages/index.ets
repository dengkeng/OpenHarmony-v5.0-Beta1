/**
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

import { addAirPlaneModeListener, removeAirPlaneModeListener, turnOffAirPlaneMode } from '../common/utils/AirplaneMode';
import ConfirmDialogEx from './dialog/ConfirmDialogEx';
import EnvironmentProp from './dialog/EnvironmentProp';
import mediaQuery from '@ohos.mediaquery';
import wantAgent from '@ohos.wantAgent';
import ContactCard from '../common/components/ContactCard';
import FuncBtnGroup from '../common/components/FuncBtnGroup';
import BottomBtn from '../common/components/BottomBtn';
import Keyboard from '../common/components/Keyboard';
import IncomingCom from '../common/components/IncomingCom';
import CallStateConst from '../common/constant/CallStateConst';
import LogUtils from '../common/utils/LogUtils';
import byTrace from '@ohos.bytrace'
import NotificationManager from '../model/NotificationManager';
import CallManager from '../model/CallManager';
import backgroundTaskManager from '@ohos.backgroundTaskManager';
import * as Constants from '../common/utils/Constants';
import CallDataManager from '../model/CallDataManager';
import MultiContactCard from '../common/components/MultiContactCard';
import DefaultCallData from '../common/struct/TypeUtils'
import CallListStruct from '../common/struct/CallListStruct'
import CallTimeListStruct from '../common/struct/CallTimeListStruct'

const AIRPLANE_MODE = 1;
const TAG = 'Index';

/**
 * @file: Main interface
 */
@Entry
@Component
struct Index {
  @State callData: DefaultCallData = new DefaultCallData();
  @State isShowKeyboard: boolean = false;
  @State callList: Array<CallListStruct> = [];
  @State callTimeList: Array<CallTimeListStruct> = [];
  private notificationManager: NotificationManager;
  private mCallDataManager: CallDataManager;
  @State curBp: string = 'md';
  @State incomingData: DefaultCallData = new DefaultCallData();
  @State mHangup: boolean = false;
  private smListener: mediaQuery.MediaQueryListener;
  private mdListener: mediaQuery.MediaQueryListener;
  private lgListener: mediaQuery.MediaQueryListener;
  private isNeedCallAgain: boolean = false;

  airplaneModeDialogController: CustomDialogController = new CustomDialogController({
    //Components shared by the TIP for creating or updating a contact by mistake and the TIP for deleting a contact
    builder: ConfirmDialogEx({
      cancel: () => {
        this.airplaneModeDialogController.close();
        LogUtils.i(TAG, 'dial airplaneModeDialogController cancel');
        this.mCallDataManager.clearCall(this.callData);
      },
      confirm: () => {
        LogUtils.i(TAG, 'dial airplaneModeDialogController confirm');
        this.airplaneModeDialogController.close();
        this.isNeedCallAgain = true;
        turnOffAirPlaneMode();
      },
      title: $r('app.string.turn_off_airplane_and_calls'),
      cancelText: $r('app.string.cancel'),
      confirmText: $r('app.string.shutDown')
    }),
    autoCancel: false,
    alignment: (EnvironmentProp.isTablet() ? DialogAlignment.Center : DialogAlignment.Bottom),
    offset: { dx: 0, dy: -16 }
  });

  isBreakpointSM = (mediaQueryResult) => {
    if (mediaQueryResult.matches) {
      this.curBp = 'sm'
      AppStorage.SetOrCreate('curBp', this.curBp)
    }
  }
  isBreakpointMD = (mediaQueryResult) => {
    if (mediaQueryResult.matches) {
      this.curBp = 'md'
      AppStorage.SetOrCreate('curBp', this.curBp)
    }
  }
  isBreakpointLG = (mediaQueryResult) => {
    if (mediaQueryResult.matches) {
      this.curBp = 'lg'
      AppStorage.SetOrCreate('curBp', this.curBp)
    }
  }

  aboutToAppear(): void {
    LogUtils.i(TAG, 'aboutToAppear')
    byTrace.startTrace('aboutToAppear', 0);
    this.notificationManager = new NotificationManager();
    CallManager.getInstance()?.init(this);
    AppStorage.SetOrCreate<NotificationManager>('notificationManager', this.notificationManager);
    this.mCallDataManager = CallDataManager.getInstance();
    byTrace.finishTrace('aboutToAppear', 0);
    this.smListener = mediaQuery.matchMediaSync('(320vp<width<=520vp)');
    this.smListener?.on('change', this.isBreakpointSM);
    this.mdListener = mediaQuery.matchMediaSync('(520vp<width<=840vp)');
    this.mdListener?.on('change', this.isBreakpointMD);
    this.lgListener = mediaQuery.matchMediaSync('(840vp<width)');
    this.lgListener?.on('change', this.isBreakpointLG);
    this.initAirPlaneMode();
  }

  onPageShow() {
    LogUtils.i(TAG, 'onPageShow');
    byTrace.startTrace('onPageShow', 1);
    globalThis.appInactiveState = false;
    this.stopBackgroundRunning();
    this.notificationManager?.cancelNotification();
    this.notificationManager?.sendCapsuleNotification(this.incomingData ? this.callData : this.incomingData, false);
    byTrace.finishTrace('onPageShow', 1);
    LogUtils.i(TAG, 'onPageShow end');
  }

  initAirPlaneMode() {
    LogUtils.i(TAG, 'initAirPlaneMode');
    try {
      addAirPlaneModeListener((data) => {
        LogUtils.i(TAG, 'initAirPlaneMode callback');
        if (data == AIRPLANE_MODE) {
          this.airplaneModeDialogController.open();
          AppStorage.SetOrCreate('AirplaneMode', true);
        } else if (this.isNeedCallAgain) {
          this.isNeedCallAgain = false;
          AppStorage.SetOrCreate('AirplaneMode', false);
          this.mCallDataManager.clearCall(this.callData);
        }
      });
    } catch(err) {
      LogUtils.e(TAG, `initAirPlaneMode err = ${JSON.stringify(err)}`);
    }
  }

  onPageHide() {
    LogUtils.i(TAG, 'onPageHide');
    if (!this.mHangup) {
      globalThis.appInactiveState = true;
      this.updateNotification();
    }
    LogUtils.i(TAG, 'onPageHide end');
  }

  updateNotification() {
    const {callState, callId} = this.callData;
    if (callState !== CallStateConst.callStateObj.CALL_STATUS_DISCONNECTED && callId) {
      if (this.mCallDataManager.hasAliveCall()) {
        this.startBackgroundRunning();
      }
      this.notificationManager?.sendNotification(this.incomingData ? this.callData : this.incomingData);
      this.notificationManager?.sendCapsuleNotification(this.incomingData ? this.callData : this.incomingData, true);
    }
  }

  aboutToDisappear() {
    LogUtils.i(TAG, 'aboutToDisappear');
    this.stopBackgroundRunning();
    this.smListener?.off('change', this.isBreakpointSM);
    this.mdListener?.off('change', this.isBreakpointMD);
    this.lgListener?.off('change', this.isBreakpointLG);
    removeAirPlaneModeListener();
    this.airplaneModeDialogController = null;
  }

  onBackPress() {
    LogUtils.i(TAG, 'onBackPress');
  }

  private stopBackgroundRunning() {
    backgroundTaskManager.stopBackgroundRunning(globalThis.calluiAbilityContext).then(() => {
      LogUtils.i(TAG, 'stopBackgroundRunning succeeded');
    }).catch((err) => {
      LogUtils.i(TAG, 'stopBackgroundRunning failed');
    });
  }

  private startBackgroundRunning() {
    let wantAgentInfo = {
      wants: [{
        bundleName: Constants.CALL_BUNDLE_NAME,
        abilityName: Constants.CALL_ABILITY_NAME,
      }],
      requestCode: 0,
      operationType: wantAgent.OperationType.START_ABILITY,
      wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
    };
    wantAgent.getWantAgent(wantAgentInfo).then((wantAgentObj) => {
      backgroundTaskManager.startBackgroundRunning(globalThis.calluiAbilityContext,
        backgroundTaskManager.BackgroundMode.VOIP, wantAgentObj).then(() => {
        LogUtils.i(TAG, 'startBackgroundRunning succeeded')
      }).catch((err) => {
        LogUtils.i(TAG, 'startBackgroundRunning failed cause:' + JSON.stringify(err))
      });
    });
  }

  /**
   * method to control the display of DTMF keyboard
   *
   * parent component pass by value child component
   */
  public showKeyboard() {
    this.isShowKeyboard = !this.isShowKeyboard;
  }

  /**
   * Call status
   *
   * @return {number} -  callState
   */
  private callState() {
    LogUtils.i(TAG, 'callState : ' + this.callData.callState)
    return this.callData.callState;
  }

  /**
   * is Triple Call
   *
   * @return {boolean} - isTripleCall
   */
  private isTripleCall() {
    return (this.callData.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING
      || this.callData.callState === CallStateConst.callStateObj.CALL_STATUS_INCOMING)
      && this.callList.length === 3;
  }

  pageTransition() {
    PageTransitionEnter({ duration: 0 });
    PageTransitionExit({ duration: 0 });
  }

  getBtnCallState() {
    if (this.callList.length > 1) {
      let btnState = true;
      this.callList.forEach((v) => {
        if (v.callState === CallStateConst.callStateObj.CALL_STATUS_WAITING || v.callState === CallStateConst.callStateObj.CALL_STATUS_INCOMING) {
          btnState = false;
        }
      });
      return btnState;
    } else {
      return this.callState() !== CallStateConst.callStateObj.CALL_STATUS_WAITING
      && this.callState() !== CallStateConst.callStateObj.CALL_STATUS_INCOMING
    }
  }

  build() {
    Flex({
      direction: FlexDirection.Column,
      alignItems: ItemAlign.Center,
      justifyContent: FlexAlign.SpaceBetween
    }) {
      if (this.callList.length > 1) {
        MultiContactCard({
          callData: $callData,
          isShowKeyboard: this.isShowKeyboard,
          callList: $callList,
          incomingData: $incomingData
        })
          .margin({ top: this.isShowKeyboard ? 0 : 56 })
          .layoutWeight(this.isShowKeyboard ? 1 : 0)
      } else {
        ContactCard({
          callData: $callData,
          isShowKeyboard: this.isShowKeyboard,
          callList: $callList
        })
          .margin({ top: this.isShowKeyboard ? 0 : 56 })
          .layoutWeight(this.isShowKeyboard ? 1 : 0)
      }

      if (this.getBtnCallState()) {
        Column() {
          if (!this.isShowKeyboard) {
            FuncBtnGroup({ callData: $callData, callList: $callList })
              .margin({ bottom: 32 })
          } else {
            Keyboard({ callData: $callData })
              .margin({ bottom: 32 })
          }
          BottomBtn({
            callData: $callData,
            callList: $callList,
            hangup: $mHangup,
            onItemClick: () => {
              this.showKeyboard()
            }
          })
        }
      } else {
        Column() {
          IncomingCom({
            callList: $callList,
            callData: $callData,
            hangup: $mHangup})

          if (this.isTripleCall()) {
            Column() {
              Text($r('app.string.end_holding_call'))
                .fontColor('#FFFFFF')
                .fontSize(14)
                .height(19)
                .lineHeight(19)
            }
            .margin({ top: 16 })
          }
        }
      }
    }
    .padding({ bottom: this.isTripleCall() ? 71 : 106 })
    .width('100%')
    .height('100%')
    .backgroundImage('assets/picture/wallpaper.png', ImageRepeat.NoRepeat)
    .backgroundImageSize(ImageSize.Cover)
  }
}
