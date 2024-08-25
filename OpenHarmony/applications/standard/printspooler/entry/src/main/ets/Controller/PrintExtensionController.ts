/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

import print from '@ohos.print';
import { Log, PrinterExtensionInfo } from '@ohos/common';
import AppStorageHelper from '../Common/Adapter/AppStorageHelper';
import {AppStorageKeyName} from '@ohos/common';
import {PrintExtensionModel} from '../Model/PrintExtensionModel';

const TAG = '[PrintExtensionController]:';

/**
 * PrintExtensionController
 *
 */
export class PrintExtensionController {
    private mPrintExtensionModel : PrintExtensionModel = new PrintExtensionModel()

    /**
     * init
     *
     */
    public init() : void {
        Log.info(TAG, 'PrintExtensionController init')
        AppStorageHelper.createValue<Array<PrinterExtensionInfo>>(this.getModel().getPrintExtensions, AppStorageKeyName.PRINT_EXTENSION_LIST_NAME)
    }

    /**
     * get all printExtension
     */
    public getAllPrintExtension() : void {
        Log.info(TAG, 'queryPrinterCapability')
        print.queryAllPrinterExtensionInfos().then((data)=> {
            Log.info(TAG, 'start connect Printer success data : ' )
            this.getModel().dealGetAllPrintExtension(data)
        }).catch((err)=> {
            Log.error(TAG, 'failed to get AllPrintExtension because ' + JSON.stringify(err));
        });
    }

    /**
     * get model
     *
     * @return PrintExtensionModel
     */
    public getModel() : PrintExtensionModel {
        return this.mPrintExtensionModel
    }
}