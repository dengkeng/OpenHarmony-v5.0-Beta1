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

/**
 * @file: notification manager
 */

import wantAgent from '@ohos.wantAgent';
import notification from '@ohos.notification';
import commonEvent from '@ohos.commonEvent';
import callStateConst from '../common/constant/CallStateConst';
import LogUtils from '../common/utils/LogUtils';
import * as Constants from '../common/utils/Constants';

const TAG = 'NotificationManager';
const ID = 0;

const notificationRequest = {
  content: {
    contentType: notification.ContentType.NOTIFICATION_CONTENT_LONG_TEXT,
    longText: {
      title: '',
      text: '',
      longText: '',
      briefText: '',
      expandedTitle: ''
    }
  },
  id: ID,
  wantAgent: null,
  actionButtons: [],
  slotType: notification.SlotType.OTHER_TYPES,
  deliveryTime: new Date().getTime()
};

const textMap =
  {
    'answer': $r('app.string.answer'),
    'reject': $r('app.string.reject'),
    'hangUp': $r('app.string.hangUp'),
    'mute': $r('app.string.mute'),
    'callHold': $r('app.string.callHold'),
  };

export default class NotificationManager {
  /**
   * Send notification
   *
   * @param { Object } text - text info
   *
   * @param { Object } callData - call data
   *
   * @param { FUnction } $t - i18n format
   */
  async sendNotification(callData) {
    const {callState, accountNumber, contactName, callId} = callData;
    const actionBtnKeys = this.getMapObj(callState) || [];
    const {START_ABILITY, SEND_COMMON_EVENT} = wantAgent.OperationType;
    const wantAgentObj = await this.getWantAgent(callData, START_ABILITY);
    let titleName = ' ';
    let expandedName = ' ';
    if (contactName) {
      titleName = contactName;
      expandedName = accountNumber;
    } else {
      titleName = accountNumber;
      expandedName = ' ';
    }
    notificationRequest.wantAgent = wantAgentObj;
    notificationRequest.actionButtons = [];

    if (actionBtnKeys.length) {
      for (const key of actionBtnKeys) {
        const data = {
          callId, btnType: key
        };
        LogUtils.i(TAG, 'sendNotification getResourceManager key:' + JSON.stringify(key));
        const wantAgentObj = await this.getWantAgent(data, SEND_COMMON_EVENT);
        const title = globalThis.calluiAbilityContext?.resourceManager.getStringSync(textMap[key]);
        LogUtils.i(TAG, 'sendNotification getResourceManager textMap[key].id:' + JSON.stringify(title));
        notificationRequest.actionButtons.push({
          title: title,
          wantAgent: wantAgentObj
        });
        LogUtils.i(TAG, 'sendNotification getResourceManager notificationRequest.actionButtons.push:' + JSON.stringify(notificationRequest.actionButtons));
      }
    }
    Object.assign(notificationRequest.content.longText, {
      title: titleName,
      text: expandedName,
      expandedTitle: titleName,
      longText: expandedName
    });
    notification.publish(notificationRequest).then((data) => {
      LogUtils.i(TAG, 'sendNotification publish success')
    }).catch((err) => {
      LogUtils.i(TAG, 'sendNotification public err' + JSON.stringify(err))
    });
    LogUtils.i(TAG, 'sendNotification end :')
  }

  /**
   * Get call status
   * @param callState
   */
  getMapObj(callState) {
    if (callState === callStateConst.CALL_STATUS_INCOMING) {
      return ['answer', 'reject']
    }
    if (callState === callStateConst.CALL_STATUS_ACTIVE) {
      return ['hangUp']
    }
    if (callState === callStateConst.CALL_STATUS_HOLDING) {
      return ['hangUp']
    }
    if (callState === callStateConst.CALL_STATUS_ALERTING) {
      return ['hangUp']
    }
    if (callState === callStateConst.CALL_STATUS_DIALING) {
      return ['hangUp']
    }
    if (callState === callStateConst.CALL_STATUS_WAITING) {
      return ['answer', 'reject']
    }
  }

  /**
   * get want agent
   *
   * @param { object } data - call data
   *
   * @param { number } operationType - type
   */
  getWantAgent(data, operationTypes) {
    if (!wantAgent) {
      LogUtils.i(TAG, 'wantAgent is not exist');
      return;
    }
    return wantAgent.getWantAgent({
      wants: [{
                deviceId: '',
                bundleName: Constants.CALL_BUNDLE_NAME,
                abilityName: Constants.CALL_ABILITY_NAME,
                uri: '',
                type: 'phone',
                action: 'callui.event.click',
                parameters: data,
                entities: []
              }],
      requestCode: 0,
      operationType: operationTypes,
      wantAgentFlags: [wantAgent.WantAgentFlags.ONE_TIME_FLAG]
    });
  }

  /**
   * Cancel notice
   */
  cancelNotification() {
    LogUtils.i(TAG, 'cancelNotification')
    notification.cancel(ID).then((res) => {
      LogUtils.i(TAG, 'notify.cancel res data : %s' + JSON.stringify(res))
    }).catch((err) => {
      LogUtils.i(TAG, 'notify.cancel err data : %s' + JSON.stringify(err))
    });
  }

  /**
   * send capsule notification
   *
   * @param {Object} callData - call data
   *
   * @param {boolean} isBackground - is background
   */
  sendCapsuleNotification(callData, isBackground) {
    LogUtils.i(TAG, 'sendCapsuleNotification isBackground : ' + JSON.stringify(isBackground))
    LogUtils.i(TAG, 'sendCapsuleNotification callData.startTime :')
    const {callState, startTime} = callData;
    let commonEventPublishData = {
      bundleName: 'com.ohos.systemui',
      isOrdered: false,
      subscriberPermissions: ['ohos.permission.GET_TELEPHONY_STATE'],
      data: JSON.stringify({
        callState,
        startTime: startTime * 1000,
        isBackground,
        wantBundleName: Constants.CALL_BUNDLE_NAME,
        wantAbilityName: Constants.CALL_ABILITY_NAME
      })
    }

    commonEvent.publish('CAPSULE_EVENT_CALL_UI', commonEventPublishData, (err, data) => {
      if (err) {
        LogUtils.i(TAG, 'sendCapsuleNotification publish launcher err:' + JSON.stringify(err))
      } else {
        LogUtils.i(TAG, 'sendCapsuleNotification publish launcher success:' + JSON.stringify(data))
      }
    })
  }
}