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
import { CMModelErrorCode, CMModelOptType } from '../model/CertMangerModel';
import { CertAbstractVo } from '../model/CertManagerVo/CertAbstractVo';
import { CertInfoVo } from '../model/CertManagerVo/CertInfoVo';

const TAG = 'CMFaShowUserCa Presenter: ';

export default class CmShowUserCaPresenter {
  private static sInstance: CmShowUserCaPresenter;
  public certList: CertAbstractVo[] = [];
  public certInfo: CertInfoVo = new CertInfoVo('', '', false, '', '', '', '', '', '',
    new Uint8Array(), new Map(), new Map(), new Map());

  public static getInstance(): CmShowUserCaPresenter {
    if (CmShowUserCaPresenter.sInstance == null) {
      CmShowUserCaPresenter.sInstance = new CmShowUserCaPresenter();
    }
    return CmShowUserCaPresenter.sInstance;
  }

  onAboutToAppear(): void {

  }

  aboutToDisappear(): void {
    this.certList = [];
    this.certInfo = new CertInfoVo('', '', false, '', '', '', '', '', '',
      new Uint8Array(), new Map(), new Map(), new Map());
  }

  updateUserTrustedCertificateList(): void {
    certManagerModel.getCertOrCredList(CMModelOptType.CM_MODEL_OPT_USER_CA,
      (errCode: CMModelErrorCode, certList: Array<CertAbstractVo>) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        certList.sort((certAbs, certAbsOther): number => {
          let certAlias = certAbs.certAlias;
          let certAliasOther = certAbsOther.certAlias;
          if (certAlias <= certAliasOther) {
            return -1;
          } else {
            return 1;
          }
        });
        this.certList = certList;
      } else {
        console.error(TAG + 'updateUserTrustedCertificateList fail,errCode is ' + errCode);
        this.certList = [];
      }
    });
  }

  getUserTrustedCertificate(uri: string, callback: Function): void {
    certManagerModel.getCertOrCred(CMModelOptType.CM_MODEL_OPT_USER_CA, uri,
      (errCode: CMModelErrorCode, certInfo: CertInfoVo) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        console.info(TAG + 'getUserTrustedCertificate success, errCode is ' + errCode);
        this.certInfo = certInfo;
        callback();
      } else {
        console.error(TAG + 'getUserTrustedCertificate fail, errCode is ' + errCode);
        this.certInfo.clearCertInfoVo();
        callback();
      }
    });
  }

  setUserCertificateStatus(uri: string, status: boolean): void {
    certManagerModel.setCertStatus(CMModelOptType.CM_MODEL_OPT_USER_CA, uri, status, (errCode: CMModelErrorCode) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        this.getUserTrustedCertificate(uri, () => {
          console.info(TAG + 'setCerStatus then getUserTrustedCertificate,errCode is' + errCode);
        });
        this.updateUserTrustedCertificateList();
      } else {
        console.error(TAG + 'setUserCertificateStatus fail,errCode is ' + errCode);
      }
    });
  }

  deleteUserCertificate(uri: string, callback: Function): void {
    certManagerModel.deleteCertOrCred(CMModelOptType.CM_MODEL_OPT_USER_CA, uri, (errCode: CMModelErrorCode) => {
      if (errCode === CMModelErrorCode.CM_MODEL_ERROR_SUCCESS) {
        this.updateUserTrustedCertificateList();
      } else {
        console.error(TAG + 'deleteUserCertificate fail,errCode is ' + errCode);
      }
      callback();
    });
  }
}