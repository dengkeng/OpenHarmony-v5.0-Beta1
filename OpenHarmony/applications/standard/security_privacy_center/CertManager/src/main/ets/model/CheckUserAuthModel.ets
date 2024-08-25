/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import userAuth from '@ohos.userIAM.userAuth';
import { BusinessError } from '@ohos.base';

export class CheckUserAuthModel {
  public isAuthTypeSupported(authType: userAuth.UserAuthType): boolean {
    try {
      userAuth.getAvailableStatus(authType, userAuth.AuthTrustLevel.ATL1);
      console.log('[CMa&CheckUserAuthModel]: ' + 'userAuthType' + authType + 'is supported');
      return true;
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      console.error(`[CMa&CheckUserAuthModel]: userAuthType ${authType} is not supported, message is ${err?.message}`);
      return false;
    }
  }

  public auth(titleStr: string, callback: (authResult: boolean) => void): void {
    let fingerPrint: boolean = this.isAuthTypeSupported(userAuth.UserAuthType.FINGERPRINT);
    let pin: boolean = this.isAuthTypeSupported(userAuth.UserAuthType.PIN);
    let authTypeArray = [userAuth.UserAuthType.FINGERPRINT];
    if (fingerPrint) {
      authTypeArray = [userAuth.UserAuthType.FINGERPRINT];
      if (pin) {
        authTypeArray = [userAuth.UserAuthType.FINGERPRINT, userAuth.UserAuthType.PIN];
      }
    } else if (pin) {
      authTypeArray = [userAuth.UserAuthType.PIN];
    } else {
      /* The user does not set identity authentication. */
      callback(true);
    }

    const authParam: userAuth.AuthParam = {
      challenge: new Uint8Array([49, 49, 49, 49, 49, 49]),
      authType: authTypeArray,
      authTrustLevel: userAuth.AuthTrustLevel.ATL1
    }
    const widgetParam: userAuth.WidgetParam = {
      title: titleStr
    };

    try {
      let userAuthInstance = userAuth.getUserAuthInstance(authParam, widgetParam);
      console.log('[CMa&CheckUserAuthModel]: get userAuth instance success');
      userAuthInstance.start();

      userAuthInstance.on('result', {
        onResult(result) {
          if (result.result === userAuth.UserAuthResultCode.SUCCESS) {
            callback(true);
          } else if (result.result === userAuth.UserAuthResultCode.CANCELED) {
            /* User cancels authentication. */
            callback(false);
          } else {
            /* User authentication failed. */
            callback(false);
          }
        }
      })
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      console.error(`[CMa&CheckUserAuthModel]: auth catch error. code is ${err?.code}, message is ${err?.message}`);
    }
  }
}

let checkUserAuthModel = new CheckUserAuthModel();

export default checkUserAuthModel as CheckUserAuthModel;