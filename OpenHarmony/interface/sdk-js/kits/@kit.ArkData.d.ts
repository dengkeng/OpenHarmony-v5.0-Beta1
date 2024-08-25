/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

/**
 * @file
 * @kit ArkData
 */

import DataShareExtensionAbility from '@ohos.application.DataShareExtensionAbility';
import cloudData from '@ohos.data.cloudData';
import cloudExtension from '@ohos.data.cloudExtension';
import commonType from '@ohos.data.commonType';
import dataShare from '@ohos.data.dataShare';
import dataSharePredicates from '@ohos.data.dataSharePredicates';
import DataShareResultSet, { DataType } from '@ohos.data.DataShareResultSet';
import distributedDataObject from '@ohos.data.distributedDataObject';
import distributedKVStore from '@ohos.data.distributedKVStore';
import preferences from '@ohos.data.preferences';
import relationalStore from '@ohos.data.relationalStore';
import unifiedDataChannel from '@ohos.data.unifiedDataChannel';
import uniformTypeDescriptor from '@ohos.data.uniformTypeDescriptor';
import uniformDataStruct from '@ohos.data.uniformDataStruct';
import { ValueType, ValuesBucket } from '@ohos.data.ValuesBucket';
import sendablePreferences from '@ohos.data.sendablePreferences';

export {
  DataShareExtensionAbility, DataShareResultSet, DataType, ValueType, ValuesBucket, cloudData, cloudExtension, 
  commonType, dataShare, dataSharePredicates, distributedDataObject, distributedKVStore, preferences,
  relationalStore, unifiedDataChannel, uniformTypeDescriptor, uniformDataStruct, sendablePreferences,
};
