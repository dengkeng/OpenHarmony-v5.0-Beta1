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

/**
 * The code here is the voice call interface and the sim card interface,
 * as well as the interface piling test simulation,
 * which is convenient for development, so I will leave it for now.
 */

import commonEvent from '@ohos.commonEvent';
import call from '@ohos.telephony.call';
import LogUtils from '../common/utils/LogUtils';

const TAG = 'CallServiceProxy';
const prefixLog = 'callUI app:@ohos.telephony.call:';

/**
 * dial call
 * @param { string } phoneNumber - phone number
 * @param { number } accountId - account id
 * @param { number } videoState - video state
 * @param { number } dialScene - dial scene
 * @return { Object } promise object
 */
export default class CallServiceProxy {
  private static sCallServiceProxy: CallServiceProxy;

  public static getInstance(): CallServiceProxy {
    if (!CallServiceProxy.sCallServiceProxy) {
      CallServiceProxy.sCallServiceProxy = new CallServiceProxy();
    }
    return CallServiceProxy.sCallServiceProxy;
  }

  /**
   * Make a phone call
   */
  public dialCall(phoneNumber, accountId = 0, videoState = 0, dialScene = 0) {
    LogUtils.i(TAG, 'dialCall phoneNumber :');
    return call.dial(phoneNumber, {
      accountId,
      videoState,
      dialScene
    });
  }

  /**
   * Stops the ringtone.
   */
  public muteRinger() {
    LogUtils.i(TAG, 'muteRinger')
    call.muteRinger((err) => {
      LogUtils.e(TAG, `muteRinger callback: err->${JSON.stringify(err)}`);
    });
  }

  /**
   * accept call
   *
   * @param { number } callId - call id
   */
  public acceptCall = function (callId) {
    call.answerCall(callId).then((res) => {
      LogUtils.i(TAG, prefixLog + 'call.answerCall : %s' + JSON.stringify(callId))
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'call.answerCall catch : %s' + JSON.stringify(err))
    });
  };

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
      LogUtils.i(TAG, prefixLog + 'then:rejectCall');
    })
      .catch((err) => {
        LogUtils.i(TAG, prefixLog + 'catch:rejectCall : %s' + JSON.stringify(err));
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

  /**
   * hold call
   *
   * @param { number } callId - call id
   *
   * @return { Object } promise object
   */
  public holdCall = (callId) => new Promise((resolve, reject) => {
    call.holdCall(callId).then((res) => {
      resolve(res);
      LogUtils.i(TAG, prefixLog + 'then:holdCall : %s' + JSON.stringify(callId));
    })
      .catch((err) => {
        reject(err);
        LogUtils.i(TAG, prefixLog + 'catch:holdCall : %s' + JSON.stringify(err));
      });
  });

  /**
   * un hold call
   *
   * @param { number } callId - call id
   *
   * @return { Object } promise object
   */
  public unHoldCall = (callId) => new Promise((resolve, reject) => {
    call.unHoldCall(callId).then((res) => {
      resolve(res);
      LogUtils.i(TAG, prefixLog + 'then:unholdCall : %s' + JSON.stringify(callId));
    })
      .catch((err) => {
        reject(err);
        LogUtils.i(TAG, prefixLog + 'catch:unHoldCall : %s' + JSON.stringify(err));
      });
  });

  /**
   * set call mute
   */
  public setMuted() {
    call.setMuted().then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:setMute');
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'catch:setMute : %s' + JSON.stringify(err));
    });
  };

  /**
   * cancel call mute
   */
  public cancelMuted() {
    call.cancelMuted().then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:cancelMuted');
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'catch:cancelMuted : %s' + JSON.stringify(err))
    });
  };

  /**
   * switch call
   *
   * @param { number } callId - call id
   *
   * @return { Object } promise object
   */
  public switchCall = (callId) => new Promise((resolve, reject) => {
    call.switchCall(callId).then((res) => {
      resolve(res);
      LogUtils.i(TAG, prefixLog + 'then:switchCall : %s' + JSON.stringify(callId))
    })
      .catch((err) => {
        reject(err);
        LogUtils.i(TAG, prefixLog + 'catch:switchCall : %s' + JSON.stringify(err))
      });
  });

  /**
   * register call state callback
   *
   * @param { Function } callBack - inject an Function
   */
  public registerCallStateCallback(callBack) {
    call.on('callDetailsChange', (data) => {
      if (!data) {
        LogUtils.i(TAG, prefixLog + 'call.on registerCallStateCallback')
        return;
      }
      LogUtils.i(TAG, prefixLog + 'call.on registerCallStateCallback callState')
      callBack(data);
    });
  }

  /**
   * onRegister call state callback
   */
  public unRegisterCallStateCallback() {
    call.off('callDetailsChange', (data) => {
      if (!data) {
        LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallStateCallback')
        return;
      }
      LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallStateCallback')
    });
  }

  /**
   * register call event callback
   */
  public registerCallEventCallback() {
    call.on('callEventChange', (data) => {
      if (!data) {
        LogUtils.i(TAG, prefixLog + 'call.on callEventChange')
      } else {
        LogUtils.i(TAG, prefixLog + 'call.on callEventChange')
      }
    });
  }

  /**
   * unRegister call event callback
   */
  public unRegisterCallEventCallback() {
    call.off('callEventChange', (data) => {
      if (!data) {
        LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallEventCallback : %s')
      } else {
        LogUtils.i(TAG, prefixLog + 'call.off unRegisterCallEventCallback : %s')
      }
    });
  }

  /**
   * start DTMF
   *
   * @param { number } callId - call id
   *
   * @param { string } str - str char
   */
  public startDTMF = (callId = 1, str = '1') => {
    call.startDTMF(callId, str).then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:startDtmf : %s' + JSON.stringify(callId) + JSON.stringify(str))
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'catch:startDtmf : %s' + JSON.stringify(err))
    });
  };

  /**
   * stop DTMF
   *
   * @param { number } callId - call id
   */
  public stopDTMF = (callId = 1) => {
    call.stopDTMF(callId).then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:stopDtmf : %s' + JSON.stringify(callId))
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'then:startDtmf : %s' + JSON.stringify(err))
    });
  };

  /**
   * combine conference
   *
   * @param { number } callId - call id
   */
  public combineConference = (callId) => {
    call.combineConference(callId).then((res) => {
      LogUtils.i(TAG, prefixLog + 'then:combineConference : %s' + JSON.stringify(callId))
    }).catch((err) => {
      LogUtils.i(TAG, prefixLog + 'catch:combineConference : %s' + JSON.stringify(err))
    });
  };

  public publish(data) {
    LogUtils.i(TAG, prefixLog + 'callui.event.callEvent publish')
    commonEvent.publish('callui.event.callEvent', {
      bundleName: 'com.ohos.callui',
      isOrdered: false,
      subscriberPermissions: ['ohos.permission.GET_TELEPHONY_STATE'],
      data: JSON.stringify(data)
    }, (res) => {
      LogUtils.i(TAG, prefixLog + 'callui.event.callEvent success')
    });
    LogUtils.i(TAG, prefixLog + 'callui.event.callEvent publish end')
  }
}

