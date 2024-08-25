/*
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

import {processDataCallback} from "./i_idl_service_ext";
import {insertDataToMapCallback} from "./i_idl_service_ext";
import IIdlServiceExt from "./i_idl_service_ext";
import rpc from "@ohos.rpc";

export default class IdlServiceExtProxy implements IIdlServiceExt {
    constructor(proxy) {
        this.proxy = proxy;
    }

    processData(data: number, callback: processDataCallback): void
    {
        let _option = new rpc.MessageOption();
        let _data = new rpc.MessageParcel();
        let _reply = new rpc.MessageParcel();
        _data.writeInt(data);
        this.proxy.sendMessageRequest(IdlServiceExtProxy.COMMAND_PROCESS_DATA, _data, _reply, _option).then(function(result) {
            if (result.errCode === 0) {
                let _errCode = result.reply.readInt();
                if (_errCode != 0) {
                    let _returnValue = undefined;
                    callback(_errCode, _returnValue);
                    return;
                }
                let _returnValue = result.reply.readInt();
                callback(_errCode, _returnValue);
            } else {
                console.log("sendMessageRequest failed, errCode: " + result.errCode);
            }
        })
    }

    insertDataToMap(key: string, val: number, callback: insertDataToMapCallback): void
    {
        let _option = new rpc.MessageOption();
        let _data = new rpc.MessageParcel();
        let _reply = new rpc.MessageParcel();
        _data.writeString(key);
        _data.writeInt(val);
        this.proxy.sendMessageRequest(IdlServiceExtProxy.COMMAND_INSERT_DATA_TO_MAP, _data, _reply, _option).then(function(result) {
            if (result.errCode === 0) {
                let _errCode = result.reply.readInt();
                callback(_errCode);
            } else {
                console.log("sendMessageRequest failed, errCode: " + result.errCode);
            }
        })
    }

    static readonly COMMAND_PROCESS_DATA = 1;
    static readonly COMMAND_INSERT_DATA_TO_MAP = 2;
    private proxy
}
