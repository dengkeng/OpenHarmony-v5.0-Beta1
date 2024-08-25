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

import type Want from '@ohos.application.Want';
import ServiceExtension from '@ohos.app.ability.ServiceExtensionAbility';
import CallManagerService from './CallManagerService';
import rpc from '@ohos.rpc';
import LogUtils from '../common/utils/LogUtils';
import DefaultCallData from '../common/struct/TypeUtils';
import CallManager from '../model/CallManager';

const TAG = 'ServiceAbility';

export default class ServiceAbility extends ServiceExtension {
  callManagerService: CallManagerService;

  onCreate(want): void {
    LogUtils.i(TAG, 'onCreate callUI service');
    this.callManagerService = CallManagerService.getInstance();
    this.callManagerService.init(this.context);
  }

  onConnect(want: Want): Stub {
    LogUtils.i(TAG, 'onConnect callUI service');
    let callData: DefaultCallData = new DefaultCallData();
    callData.accountNumber = want.parameters?.accountNumber;
    callData.videoState = want.parameters?.videoState;
    callData.callType = want.parameters?.callType;
    callData.callState = want.parameters?.callState;
    callData.callId = want.parameters?.callId;
    callData.startTime = want.parameters?.startTime;
    callData.accountId = want.parameters?.accountId;
    callData.isEcc = want.parameters?.isEcc;
    callData.conferenceState = want.parameters?.conferenceState;
    this.callManagerService.getCallData(callData);
    CallManager.getInstance().setServiceConnected(true);
    return new Stub('ServiceAbility');
  }

  onDisconnect(): void {
    LogUtils.i(TAG, 'onDisconnect callUI service');
    CallManager.getInstance().setServiceConnected(false);
    this.callManagerService.onDisconnected();
  }

  onRequest(want: Want, startId: number): void {
    LogUtils.i(TAG, 'onRequest callUI service');
  }

  onDestroy(): void {
    LogUtils.i(TAG, 'onDestroy callUI service');
    this.callManagerService.removeRegisterListener();
  }
}

class Stub extends rpc.RemoteObject {
  onRemoteRequest(code, date, reply, option): boolean {
    LogUtils.i(TAG, 'Stub onRemoteRequest code:' + code);
    return true;
  }
  
  constructor(descriptor) {
    super(descriptor);
  }
}