/**
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

import common from '@ohos.app.ability.common';
import Audio from '@ohos.multimedia.audio';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import DataShareExtensionAbility from '@ohos.application.DataShareExtensionAbility';
import rpc from '@ohos.rpc';
import process from '@ohos.process';
import settings from '@ohos.settings';
import relationalStore from '@ohos.data.relationalStore';
import Want from '@ohos.app.ability.Want';
import dataSharePredicates from '@ohos.data.dataSharePredicates';
import { AsyncCallback, BusinessError } from '@ohos.base';
import SettingsDataConfig from '../Utils/SettingsDataConfig';
import SettingsDBHelper from '../Utils/SettingsDBHelper';
import { Log } from '../Utils/Log';
import { GlobalContext}  from '../Utils/GlobalContext';


interface  IRequest {
    operation:string ;
    columns:string[];
    predicates:dataSharePredicates.DataSharePredicates|relationalStore.RdbPredicates|null;
    value:relationalStore.ValuesBucket|null
}
let rdbStore:relationalStore.RdbStore|undefined = undefined;
let requests:IRequest[] = [];
let SETTINGS_AUDIO_RINGTONE = "settings.audio.ringtone"
let SETTINGS_AUDIO_MEDIA = "settings.audio.media"
let SETTINGS_AUDIO_VOICE_CALL = "settings.audio.voicecall"
let trustList: Array<String> = [
settings.display.SCREEN_BRIGHTNESS_STATUS,
settings.display.AUTO_SCREEN_BRIGHTNESS,
settings.display.SCREEN_OFF_TIMEOUT
];
let ret:number = 0;
let err:BusinessError = {"code":-1} as BusinessError;

export default class DataExtAbility extends DataShareExtensionAbility {
    onCreate(want: Want) {
        GlobalContext.thisContext =  this.context;
        this.onInitialized();
        Log.info('onCreate  context'+ JSON.stringify(this.context));
    }

    onInitialized() {
        Log.info('onInitialize start');
        let context = GlobalContext.thisContext as common.Context;
        Log.info('onInitialize start context: '+ JSON.stringify(this.context));
        if (context !== undefined) {
            SettingsDBHelper.getInstance().getRdbStore().then((rdb: relationalStore.RdbStore|undefined) => {
                rdbStore = rdb;
                for (let i = 0; i < requests.length; i++) {
                    let opt: string = requests[i].operation;
                    let columns: string[] = requests[i].columns;
                    let predicates = (requests[i].predicates) as dataSharePredicates.DataSharePredicates;

                    let value: relationalStore.ValuesBucket|null = requests[i].value;
                    if (opt == "insert") {
                        if(value){
                            rdbStore?.insert(SettingsDataConfig.TABLE_NAME, value,  (err, ret) => {
                                Log.info('onInitialized insert ret: ' + ret);
                            });
                        }
                    } else if (opt == "query") {
                        if(predicates){
                            rdbStore?.query(SettingsDataConfig.TABLE_NAME, predicates, columns, (err: BusinessError, resultSet: relationalStore.ResultSet) => {
                                    Log.info('onInitialized query ret: ' + JSON.stringify(resultSet));
                                });
                        }

                    } else if (opt == "update") {
                        if(value){
                            rdbStore?.update(SettingsDataConfig.TABLE_NAME, value, predicates, (err, ret) => {
                                Log.info('onInitialized update ret: ' + ret);
                            });
                        }
                    }
                }
            }).catch((err: Error) => {
                Log.error('onInitialize failed:' + JSON.stringify(err));
            })
        } else {
            Log.info('onInitialize context error!');
        }
        Log.info('onInitialize end');
    }

    insert(uri: string, value: relationalStore.ValuesBucket, callback : AsyncCallback<number>) {
        Log.info('insert keyword = ' + value[SettingsDataConfig.FIELD_KEYWORD] + ' start:' + uri);
        let rdbInsert = (GrantStatus: boolean) => {
            if (!GrantStatus) {
                callback(err, ret);
                return;
            }
            this.DoSystemSetting(value[SettingsDataConfig.FIELD_KEYWORD]?.toString(), value[SettingsDataConfig.FIELD_VALUE]?.toString());

            if (rdbStore == null) {
                let request: IRequest= {
                    operation: "insert", columns: [], predicates: null, value: value
                };
                Log.info('insert request = ' + JSON.stringify(request));
                requests.push(request);
                callback(err, ret);
            } else {
                rdbStore.insert(SettingsDataConfig.TABLE_NAME, value,  (err, ret) => {
                    Log.info('insert result: ' + ret);
                    callback(err, ret);
                });
            }
        }

        try {
            Log.info('Start to verify permissions.');
            this.verifyPermission(value, rdbInsert);
        } catch (err) {
            Log.error('Insert Data error:' + JSON.stringify(err));
            callback(err, ret);
        }
    }


    update(uri: string, predicates: dataSharePredicates.DataSharePredicates, value:relationalStore.ValuesBucket, callback: AsyncCallback<number>) {
        Log.info('update keyword = ' + value[SettingsDataConfig.FIELD_KEYWORD] + ' start:' + uri);
        let rdbUpData = (GrantStatus:boolean) => {
            if (!GrantStatus) {
                callback(err, ret);
                return;
            }
            this.DoSystemSetting(value[SettingsDataConfig.FIELD_KEYWORD]?.toString(), value[SettingsDataConfig.FIELD_VALUE]?.toString());
            if (rdbStore == null) {
                let request : IRequest= {
                    operation: "update", columns: [], predicates: predicates, value: value
                };
                Log.info('update request = ' + JSON.stringify(request));
                requests.push(request);
                callback(err, ret);
            } else {
                rdbStore.update(SettingsDataConfig.TABLE_NAME, value, predicates , (err, ret)=> {
                    Log.info('update result: ' + ret);
                    callback(err, ret);
                });
            }
        }
        try {
            Log.info('Start to verify permissions.');
            this.verifyPermission(value, rdbUpData);
        } catch (err) {
            Log.error('upData error:' + JSON.stringify(err));
            callback(err, ret);
        }
    }

    delete(uri: string, predicates: dataSharePredicates.DataSharePredicates, callback: AsyncCallback<number>) {
        Log.info('nothing to do');
    }

    query(uri: string, predicates: dataSharePredicates.DataSharePredicates, columns: string[], callback: AsyncCallback<Object>) {
        Log.info( 'query start uri:' + uri);
        if (rdbStore == null) {
            let request: IRequest= {operation:"query", columns : columns, predicates : predicates, value:null};
            Log.info('query request = '+ JSON.stringify(request));
            requests.push(request);
            callback(err, {"_napiwrapper":{}});
        } else {
            rdbStore.query(SettingsDataConfig.TABLE_NAME, predicates, columns,  (err:BusinessError, resultSet:relationalStore.ResultSet)=> {
                Log.info('query result: '+ JSON.stringify(resultSet.rowCount) +'columnNames'+ JSON.stringify(resultSet.columnNames));
                callback(err, resultSet);
            })
        }
    }

    private DoSystemSetting(settingsKey: string|undefined, settingsValue: string|undefined) {
        switch (settingsKey) {
            case SETTINGS_AUDIO_RINGTONE:
                try {
                    let volumeType = Audio.AudioVolumeType.RINGTONE;
                    Audio.getAudioManager().setVolume(volumeType, Number(settingsValue)).then(() => {
                        Log.info('settings Promise returned to indicate a successful RINGTONE setting.')
                    });
                } catch (err) {
                    Log.info('settings RINGTONE failed error = ' + JSON.stringify(err));
                }
                break
            case SETTINGS_AUDIO_MEDIA:
                try {
                    let volumeType = Audio.AudioVolumeType.MEDIA;
                    Audio.getAudioManager().setVolume(volumeType, Number(settingsValue)).then(() => {
                        Log.info('settings Promise returned to indicate a successful MEDIA setting.')
                    });
                } catch (err) {
                    Log.info('settings MEDIA failed error = ' + JSON.stringify(err));
                }
                break
            case SETTINGS_AUDIO_VOICE_CALL:
                try {
                    let volumeType = Audio.AudioVolumeType.VOICE_CALL;
                    Audio.getAudioManager().setVolume(volumeType, Number(settingsValue)).then(() => {
                        Log.info('settings Promise returned to indicate a successful VOICE_CALL setting.')
                    });
                } catch (err) {
                    Log.info('settings VOICE_CALL failed error = ' + JSON.stringify(err));
                }
                break
            default:
                Log.info(settingsKey + ' key is not audio');
                break
        }
    }

    private verifyPermission(value: relationalStore.ValuesBucket, callBack: (GrantStatus: boolean) => void ) {
        if (this.isTrustList(value[SettingsDataConfig.FIELD_KEYWORD] as string) || process.uid == rpc.IPCSkeleton.getCallingUid()) {
            callBack(true);
            return;
        }
        try {
            let tokenID = rpc.IPCSkeleton.getCallingTokenId();
            Log.info('tokenID = ' + tokenID);
            let grantStatus = abilityAccessCtrl.createAtManager().verifyAccessToken(tokenID, "ohos.permission.MANAGE_SECURE_SETTINGS");
            grantStatus.then(data => {
                if (data == abilityAccessCtrl.GrantStatus.PERMISSION_GRANTED) {
                    Log.info('MANAGE_SECURE_SETTINGS active');
                    callBack(true);
                } else {
                    Log.warn('MANAGE_SECURE_SETTINGS grantStatus= ' + JSON.stringify(data));
                    callBack(false);
                }
            }).catch((err: BusinessError) => {
                Log.error('tokenID = ' + tokenID + ' verifyAccessToken is failed: ' + JSON.stringify(err));
                callBack(false);
            })
        } catch (err) {
            Log.error('err = ' + JSON.stringify(err));
            callBack(false);
        }
    }

    private isTrustList(keyWord: string): boolean {
        return trustList.includes(keyWord)
    }
}