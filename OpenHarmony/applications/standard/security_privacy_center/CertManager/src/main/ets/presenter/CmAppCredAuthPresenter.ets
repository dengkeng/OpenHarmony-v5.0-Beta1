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
import BundleModel from '../model/BundleModel';
import { CMModelErrorCode, CMModelOptType } from '../model/CertMangerModel';
import { CredentialAbstractVo } from '../model/CertManagerVo/CredentialAbstractVo';
import router from '@ohos.router';
import { GlobalContext } from '../common/GlobalContext';
import { AppInfoVo } from '../model/CertManagerVo/AppInfoVo';
import { BusinessError } from '@ohos.base';
import Common from '@ohos.app.ability.common'

const TAG = 'CMAppCredAuthPresenter Presenter: ';
const SUCCESS = 0;
const FAIL = -1;

export default class CmAppCredAuthPresenter {
  private static sInstance: CmAppCredAuthPresenter;
  public credList: CredentialAbstractVo[] = [];
  public appName: string = '';

  public static getInstance(): CmAppCredAuthPresenter {
    if (CmAppCredAuthPresenter.sInstance == null) {
      CmAppCredAuthPresenter.sInstance = new CmAppCredAuthPresenter();
    }
    return CmAppCredAuthPresenter.sInstance;
  }

  onAboutToAppear(): void {

  }

  aboutToDisappear(): void {
    this.credList = [];
  }

  updateAppNameFromUid(uid: string): void {
    try {
      BundleModel.getAppInfoList(Number(uid), (errCode: CMModelErrorCode, appInfo: AppInfoVo) => {
        if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
          this.appName = appInfo.appName;
          console.log('getAppNameFromUid success, appName = ' + this.appName);
        } else {
          console.error('getAppNameFromUid fail, uid = ' + uid);
        }
      });
    } catch (err) {
      let e: BusinessError = err as BusinessError;
      console.error('updateAppNameFromUid failed with err, message: ' + e.message + ', code: ' + e.code);
    }
  }

  updateAppCredList(): void {
    certManagerModel.getCertOrCredList(CMModelOptType.CM_MODEL_OPT_APP_CRED,
      (errCode: CMModelErrorCode, credList: Array<CredentialAbstractVo>) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        this.credList = credList;
        console.log('updateAppCredList success.');
      } else {
        console.error('updateAppCredList failed');
      }
    });
  }

  requestAuthorize(uri: string, appUid: string): void {
    let want = GlobalContext.getContext().getAbilityWant();
    certManagerModel.setAppAuth(CMModelOptType.CM_MODEL_OPT_APP_CRED, uri, appUid,
      true, (errCode: CMModelErrorCode, result: string) => {
      router.clear();
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        console.log('requestAuthorize success result: ' + result);
        if (want.parameters != undefined) {
          want.parameters.authUri = result;
          let ret1: Common.AbilityResult = {
            resultCode: SUCCESS,
            want: want
          };
          GlobalContext.getContext().getCmContext().terminateSelfWithResult(ret1);
        } else {
          let ret2: Common.AbilityResult = {
            resultCode: FAIL,
            want: want
          };
          console.error(TAG + 'requestAuthorize failed, undefined');
          GlobalContext.getContext().getCmContext().terminateSelfWithResult(ret2);
        }
      } else {
        console.error('requestAuthorize fail');
        let ret3: Common.AbilityResult = {
          resultCode: FAIL,
          want: want
        };
        GlobalContext.getContext().getCmContext().terminateSelfWithResult(ret3);
      }
    });
  }

  cancelProcess(): void {
    console.log('cancelProcess start');
    router.clear();
    let ret: Common.AbilityResult = {
      resultCode: FAIL,
      want: GlobalContext.getContext().getAbilityWant()
    };
    GlobalContext.getContext().getCmContext().terminateSelfWithResult(ret);
  }
}