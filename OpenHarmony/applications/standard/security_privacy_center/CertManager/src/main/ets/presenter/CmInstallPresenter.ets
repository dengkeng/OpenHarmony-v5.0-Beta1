/**
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

import certManagerModel from '../model/CertMangerModel';
import FileIoModel from '../model/FileIoModel';
import { CMModelErrorCode, CMModelOptType } from '../model/CertMangerModel';
import router from '@ohos.router';
import { GlobalContext } from '../common/GlobalContext';
import promptAction from '@ohos.promptAction';
import { BusinessError } from '@ohos.base';

const TAG = 'CMInstallPresenter: ';
const DURATION = 2000;
const gridCountNum: number = 4;
const bottomNum: number = 100;

export default class CmInstallPresenter {
  private static sInstance: CmInstallPresenter;
  private optType: CMModelOptType = CMModelOptType.CM_MODEL_OPT_UNKNOWN;

  public static getInstance(): CmInstallPresenter {
    if (CmInstallPresenter.sInstance == null) {
      CmInstallPresenter.sInstance = new CmInstallPresenter();
    }
    return CmInstallPresenter.sInstance;
  }

  onAboutToAppear(): void {

  }

  aboutToDisappear(): void {
    this.optType = CMModelOptType.CM_MODEL_OPT_UNKNOWN;
    AppStorage.setOrCreate('installUserCred',false);
    AppStorage.setOrCreate('installSystemCred',false);
  }

  updateCertFileType(suffix: string): void {
    console.debug(TAG + 'updateCertFileType suffix: ' + suffix);
    if ((suffix === 'cer') || (suffix === 'pem')) {
      this.optType = CMModelOptType.CM_MODEL_OPT_USER_CA;
    } else if (((suffix === 'p12') || (suffix === 'jks') || (suffix === 'pfx')) &&
      AppStorage.get('installUserCred') === true) {
      this.optType = CMModelOptType.CM_MODEL_OPT_APP_CRED;
    } else if (((suffix === 'p12') || (suffix === 'jks') || (suffix === 'pfx')) &&
      AppStorage.get('installSystemCred') === true) {
      this.optType = CMModelOptType.CM_MODEL_OPT_SYSTEM_CRED;
    } else {
      console.debug(TAG, 'The file type is not supported. suffix: ' + suffix);
    }
  }

  getFileDataFromUri(uri: string, callback: Function): void {
    FileIoModel.getMediaFileData(uri, (data: Uint8Array) => {
      callback(data);
    });
  }

  AuthenticationPassword(uri: string, suffix: string, pwd: string): Promise<number> {
    return new Promise((resolve) => {
      this.updateCertFileType(suffix);
      this.getFileDataFromUri(uri, (data: Uint8Array) => {
        certManagerModel.checkPassword(data, pwd, (err: CMModelErrorCode) => {
          if (err === CMModelErrorCode.CM_MODEL_ERROR_EXCEPTION) {
            resolve(err)
          } else {
            resolve(0)
          }
        })
      })
    })
  }

  checkCertNameLength(uri: string, alias: string, suffix: string, pwd: string): Promise<number> {
    return new Promise((resolve) => {
      this.updateCertFileType(suffix);
      this.getFileDataFromUri(uri, (data: Uint8Array) => {
        certManagerModel.installCertOrCred(this.optType, alias, data, pwd, (errCode: CMModelErrorCode) => {
          if (errCode === CMModelErrorCode.CM_MODEL_ERROR_ALIAS_LENGTH_REACHED_LIMIT) {
            resolve(errCode)
          } else {
            resolve(0)
          }
        })
      })
    })
  }

  installSuccessTips(): void {
    try {
      promptAction.showToast({
        message: this.optType === CMModelOptType.CM_MODEL_OPT_USER_CA ?
        $r('app.string.Install_Cert_Success') : $r('app.string.Install_Cred_Success'),
        duration: DURATION,
        bottom: bottomNum
      })
    } catch (err) {
      let e: BusinessError = err as BusinessError;
      console.error(TAG, 'show result failed, message: ' + e.message + ', code: ' + e.code)
    }
  }

  errorFormatTips(): void {
    AlertDialog.show({
      message: $r('app.string.Install_ERROR_INCORRECT_FORMAT'),
      autoCancel: true,
      alignment: DialogAlignment.Bottom,
      offset: {
        dx: $r('app.float.wh_value_0'), dy: $r('app.float.wh_value_0')
      },
      gridCount: gridCountNum,
      primaryButton: {
        value: $r('app.string.OK'),
        action: () => {
        }
      },
    })
  }

  maxQuantityReachedTips(): void {
    AlertDialog.show({
      message: $r('app.string.Install_Error_MAX_QUANTITY_REACHED'),
      autoCancel: true,
      alignment: DialogAlignment.Bottom,
      offset: {
        dx: $r('app.float.wh_value_0'), dy: $r('app.float.wh_value_0')
      },
      gridCount: gridCountNum,
      primaryButton: {
        value: $r('app.string.OK'),
        action: () => {
          router.back({
            url: 'pages/certManagerFa'
          })
        }
      },
    })
  }

  installFailedTips(): void {
    try {
      promptAction.showToast({
        message: this.optType === CMModelOptType.CM_MODEL_OPT_USER_CA ?
        $r('app.string.Install_Cert_Failed') : $r('app.string.Install_Cred_Failed'),
        duration: DURATION,
        bottom: bottomNum
      })
    } catch (err) {
      let e: BusinessError = err as BusinessError;
      console.error(TAG, 'show result failed, message: ' + e.message + ', code: ' + e.code)
    }
  }

  installCert(uri: string, alias: string, suffix: string): void {
    this.updateCertFileType(suffix);
    this.getFileDataFromUri(uri, (data: Uint8Array) => {
      certManagerModel.installCertOrCred(this.optType, alias, data,
        GlobalContext.getContext().getPwdStore().getCertPwd(), (errCode: CMModelErrorCode) => {
        console.info(TAG + 'installCertOrCred result: ' + JSON.stringify(errCode));
        GlobalContext.getContext().getPwdStore().clearCertPwd();
        switch (errCode) {
          case CMModelErrorCode.CM_MODEL_ERROR_SUCCESS:
            this.installSuccessTips();
            break;

          case CMModelErrorCode.CM_MODEL_ERROR_INCORRECT_FORMAT:
            this.errorFormatTips();
            break;

          case CMModelErrorCode.CM_MODEL_ERROR_MAX_QUANTITY_REACHED:
            this.maxQuantityReachedTips();
            break;

          default:
            this.installFailedTips();
            break;
        }
        router.clear();
        router.replaceUrl({
          url: 'pages/certManagerFa'
        });
      });
    });
  }
}