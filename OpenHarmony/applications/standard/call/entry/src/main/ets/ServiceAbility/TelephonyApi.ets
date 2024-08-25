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
 * @file: Voice call API interface call
 */

import call from '@ohos.telephony.call';
import LogUtils from '../common/utils/LogUtils';

const prefixLog = 'callui service:@ohos.telephony.call:';
const TAG = 'TelephonyApi';

export default class TelephonyApi {

  /**
   * register call state callback
   *
   * @param { Function } callBack - inject an Function
   */
  public registerCallStateCallback(callBack) {
    try {
      call.on('callDetailsChange', (data) => {
        if (!data) {
          LogUtils.i(TAG, prefixLog + 'call.on registerCallStateCallback')
          return;
        }
        LogUtils.i(TAG, prefixLog + 'call.on registerCallStateCallback callState: ' + JSON.stringify(data.callState))
        callBack(data);
      });
    } catch (err) {
      LogUtils.i(TAG, 'call.on registerCallStateCallback catch:' + JSON.stringify(err));
    }
  }

  /**
   * onRegister call state callback
   */
  public unRegisterCallStateCallback() {
    try {
      call.off('callDetailsChange', (data) => {
        if (!data) {
          LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallStateCallback')
          return;
        }
        LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallStateCallback')
      });
    } catch (err) {
      LogUtils.i(TAG, 'call.off unRegisterCallStateCallback catch:' + JSON.stringify(err));
    }
  }

  /**
   * accept call
   *
   * @param { number } callId - call id
   */
  public acceptCall = function (callId) {
    call.answerCall(callId).then((res) => {
      LogUtils.i(TAG, prefixLog + 'call.answerCall callId: ' + JSON.stringify(callId))
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'call.answerCall catch : ' + JSON.stringify(err))
    })
  }

  /**
   * reject call
   *
   * @param { number } callId - call id
   *
   * @param { boolean } isSendSms - is send sms
   *
   * @param { string } msg - message string
   */
  public rejectCall = function (callId, isSendSms = false, msg = '') {
    const rejectCallPromise = isSendSms ? call.rejectCall(callId, {
      messageContent: msg
    }) : call.rejectCall(callId);
    rejectCallPromise.then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:rejectCall')
    })
      .catch((err) => {
        LogUtils.i(TAG, prefixLog + 'catch:rejectCall : ' + JSON.stringify(err))
      });
  };

  /**
   * hang up Call
   *
   * @param { number } callId - call id
   *
   * @return { Object } promise object
   */
  public hangUpCall = (callId) => new Promise((resolve, reject) => {
    call.hangUpCall(callId).then((res) => {
      resolve(res);
      LogUtils.i(TAG, prefixLog + 'then:hangUpCall : %s' + JSON.stringify(callId))
    }).catch((err) => {
      reject(err);
      LogUtils.i(TAG, prefixLog + 'catch:hangUpCall : %s' + JSON.stringify(err))
    });
  });
}


