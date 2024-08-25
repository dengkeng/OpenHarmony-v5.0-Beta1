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

import account_osAccount from '@ohos.account.osAccount';
import logger from './logger'
import utils from './utils'

const TAG = 'AccountManager';

export interface UserId {
  localId: number;
}

export class AccountManager {
    async getAccountUserId(userId: UserId) : Promise<boolean> {
        let accountInfo = await account_osAccount.getAccountManager().queryCurrentOsAccount();
        if (!utils.isValid(accountInfo)) {
            logger.warn(TAG, 'getAccountUserId queryCurrentOsAccount fail! userId is null');
            return false;
        }
        userId.localId = accountInfo.localId;
        logger.info(TAG, 'getAccountUserId accountInfo.localId=' + accountInfo.localId);
        return true;
    }
}

let accountManager = new AccountManager();

export default accountManager as AccountManager;