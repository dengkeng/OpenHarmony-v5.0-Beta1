/*
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

import Rsm from '@ohos.resourceManager';
import {LogUtil} from './LogUtil'

const TAG = "Note_GlobalResourceManager"

export class GlobalResourceManager {
  public async getStringByResource(res: any): Promise<string> {
    let json = JSON.parse(JSON.stringify(res));
    let id = json.id;
    LogUtil.info(TAG, "ResourceID = " + id)
    return await this.getStringById(id);
  }

  public getStringById(id: number): Promise<string>{
    let promise = new Promise<string>(resolve => {
      let resourceMgr = Rsm.getResourceManager("com.example.note");
      resourceMgr.then((result) => {
        result.getString(id)
          .then((resource) => {
            resolve(resource);
            LogUtil.info(TAG, 'getStringById resolve(resource) : ' + resolve(resource));
            LogUtil.info(TAG, 'getStringById resource : ' + resource);
            LogUtil.info(TAG, 'getStringById resource2 : ' + JSON.stringify(resource));
          })
          .catch((err) => {
            LogUtil.info(TAG, 'getStringById err : ' + JSON.stringify(err));
          });
      });
    });
    LogUtil.info(TAG, 'getStringById promise: ' + JSON.stringify(promise));
    return promise;
  }
}

let mGlobalResourceManager = new GlobalResourceManager();

export default mGlobalResourceManager as GlobalResourceManager;
