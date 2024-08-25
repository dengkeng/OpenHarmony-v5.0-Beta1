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
import bundleModel from '../model/BundleModel';
import { CMModelErrorCode, CMModelOptType } from '../model/CertMangerModel';
import { CredentialAbstractVo } from '../model/CertManagerVo/CredentialAbstractVo';
import { CredentialVo } from '../model/CertManagerVo/CredentialVo';
import { AppAuthorVo } from '../model/CertManagerVo/AppAuthorVo';
import { AppInfoVo } from '../model/CertManagerVo/AppInfoVo';
import { BusinessError } from '@ohos.base';

export default class CmShowAppCredPresenter {
  private static sInstance: CmShowAppCredPresenter;
  public credList: CredentialAbstractVo[] = [];
  public appInfoList: AppAuthorVo[] = [];
  public credInfo: CredentialVo = new CredentialVo('', '', '', 0, 0, new Uint8Array());

  public static getInstance(): CmShowAppCredPresenter {
    if (CmShowAppCredPresenter.sInstance == null) {
      CmShowAppCredPresenter.sInstance = new CmShowAppCredPresenter();
    }
    return CmShowAppCredPresenter.sInstance;
  }

  aboutToDisappear(): void {
    this.credList = [];
    this.credInfo = new CredentialVo('', '', '', 0, 0, new Uint8Array());
    this.appInfoList = [];
  }

  updateAppCredListCallback(callback: Function): void {
    certManagerModel.getCertOrCredList(CMModelOptType.CM_MODEL_OPT_APP_CRED,
      (errCode: CMModelErrorCode, credList: Array<CredentialAbstractVo>) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        credList.sort((certAbs, certAbsOther): number => {
          let certAlias = certAbs.alias;
          let certAliasOther = certAbsOther.alias;
          if (certAlias <= certAliasOther) {
            return -1;
          } else {
            return 1;
          }
        });
        this.credList = credList;
        callback();
      } else {
        console.error('updateAppCredList error :' + JSON.stringify(errCode));
        this.credList = [];
        callback();
      }
    });
  }

  updateAppCredList(): void {
    certManagerModel.getCertOrCredList(CMModelOptType.CM_MODEL_OPT_APP_CRED,
      (errCode: CMModelErrorCode, credList: Array<CredentialAbstractVo>) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        credList.sort((certAbs, certAbsOther): number => {
          let certAlias = certAbs.alias;
          let certAliasOther = certAbsOther.alias;
          if (certAlias <= certAliasOther) {
            return -1;
          } else {
            return 1;
          }
        });
        this.credList = credList;
      } else {
        console.error('updateAppCredList error :' + JSON.stringify(errCode));
        this.credList = [];
      }
    });
  }

  getAppCred(uri: string, callback: Function): void {
    certManagerModel.getCertOrCred(CMModelOptType.CM_MODEL_OPT_APP_CRED, uri,
      (errCode: CMModelErrorCode, credInfo: CredentialVo) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        this.credInfo = credInfo;
      } else {
        console.error('getAppCred error :' + JSON.stringify(errCode));
        this.credInfo.clearCredentialVo();
      }
      callback();
    });
  }

  deleteAppCred(uri: string): void {
    certManagerModel.deleteCertOrCred(CMModelOptType.CM_MODEL_OPT_APP_CRED, uri, (errCode: CMModelErrorCode) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        this.updateAppCredList();
      } else {
        console.error('deleteAppCred error :' + JSON.stringify(errCode));
      }
    });
  }

  getAuthorizedAppList(uri: string): void {
    this.appInfoList = [];
    certManagerModel.getAuthAppList(CMModelOptType.CM_MODEL_OPT_APP_CRED, uri,
      (errCode: CMModelErrorCode, appUidList: Array<string>) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        for (let i = 0; i < appUidList.length; i++) {
          bundleModel.getAppInfoList(Number(appUidList[i]), (errCode: CMModelErrorCode, appInfo: AppInfoVo) => {
            if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
              this.appInfoList.push(
                new AppAuthorVo(String(appInfo.appImage), String(appUidList[i]), String(appInfo.appName), true));
            }
          });
        }
      } else {
        console.error('getAuthorizedAppList error :' + JSON.stringify(errCode));
        this.appInfoList = [];
      }
    });
  }

  async removeGrantedAppList(uri: string): Promise<void> {
    console.log('enter removeGrantedAppList');
    for (let i = 0; i < this.appInfoList.length; i++) {
      if (!this.appInfoList[i].status) {
        try {
          let res = await certManagerModel.setAppAuthPromise(CMModelOptType.CM_MODEL_OPT_APP_CRED, uri,
            this.appInfoList[i].uid, false);
          console.log('removeGrantedAppList succeed' + JSON.stringify(res));
        } catch (error) {
          let e: BusinessError = error as BusinessError;
          console.error('removeGrantedAppList error, message: ' + e.message + ', code: ' + e.code);
        }
      }
    }
    console.log('leave removeGrantedAppList');
  }
}