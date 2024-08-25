/*
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

import fileAccess from '@ohos.file.fileAccess'
import Logger from '../log/Logger'
import abilityAccessCtrl from '@ohos.abilityAccessCtrl'
import { Permissions } from '@ohos.abilityAccessCtrl'
import FileShare from '@ohos.fileshare'
import wantConstant from '@ohos.app.ability.wantConstant'
import ErrorCodeConst from '../constants/ErrorCodeConst'
import MediaLibrary from '@ohos.multimedia.mediaLibrary'
import { FILE_MANAGER_PREFERENCES, FILE_SUFFIX, SELECT_MODE } from '../constants/Constant'
import StringUtil from './StringUtil'
import { ArrayUtil } from './ArrayUtil'
import { getPreferences } from './PreferencesUtil'

const TAG = 'AbilityCommonUtil'

let mediaLibrary: MediaLibrary.MediaLibrary = null

/**
 * Ability公共工具类
 */
namespace AbilityCommonUtil {

/**
 * 需要用户授权的权限列表
 */
  export const PERMISSION_LIST: Array<Permissions> = [
    "ohos.permission.MEDIA_LOCATION",
    "ohos.permission.READ_MEDIA",
    "ohos.permission.WRITE_MEDIA"
  ]

  /**
   * 用来获取startAbility调用方应用uid的key
   */
  export const CALLER_UID = 'ohos.aafwk.param.callerUid'

  export const CALLER_BUNDLE_NAME = 'ohos.aafwk.param.callerBundleName'

  /**
   * 最大选择文件的个数
   */
  export const MAX_FILE_PICK_NUM = 500

  /**
   * 后缀最大长度,包括'.'
   */
  export const SUFFIX_MAX_LENGTH: number = 255;

  /**
   * 三方传入的后缀数组长度最大100
   */
  export const SUFFIX_LIST_MAX_LENGTH: number = 100;

  /**
   * picker对外返回的响应码
   */
  export const RESULT_CODE = {
    SUCCESS: 0,
    CANCEL: -1
  }

  export const ABILITY_LIST = {
    FILE_MANAGER: 'FileManagerAbility',
    FILE_PICKER: 'FilePickerAbility',
    PATH_PICKER: 'PathPickerAbility'
  }
  /**
   * 拉起Ability时必要的初始化操作
   */
  export function init(): Promise<void[]> {
    const fileAccessHelperPromise = createFileAccessHelper();
    getMediaLibrary();
    const getRequestPermission = requestPermission();
    const initData = initLastSelectPath();
    return Promise.all([fileAccessHelperPromise, getRequestPermission, initData]);
  }

  /**
   * 获取FileAccessHelper，用于获取文件和操作文件
   */
  export function createFileAccessHelper(): Promise<void> {
    if (globalThis.fileAccessHelper) {
      return Promise.resolve()
    }
    return new Promise(async (resolve, reject) => {
      try {
        let wants = await fileAccess.getFileAccessAbilityInfo()
        globalThis.fileAcsHelper = fileAccess.createFileAccessHelper(globalThis.abilityContext, wants)
        // 获取设备根节点信息
        const rootIterator: fileAccess.RootIterator = await globalThis.fileAcsHelper.getRoots()
        let rootInfoArr = []
        let result = rootIterator.next()
        let isDone = result.done
        while (!isDone) {
          const rootInfo: fileAccess.RootInfo = result.value
          Logger.i(TAG, 'RootInfo: ' + rootInfo.uri + ', ' + rootInfo.deviceType + ', ' + rootInfo.deviceFlags + ', ' + rootInfo.displayName+','+rootInfo.relativePath)
          rootInfoArr.push(rootInfo)
          result = rootIterator.next()
          isDone = result.done
        }
        globalThis.rootInfoArr = rootInfoArr
      } catch (err) {
        Logger.e(TAG, 'createFileAccessHelper fail, error:' + JSON.stringify(err))
      } finally {
        resolve()
      }
    })
  }

  /**
   * Ability初始化时，加载最新保存的路径Uri
   */
  export function initLastSelectPath(): Promise<void> {
    return new Promise((resolve, reject) => {
      const defaultValue = FILE_MANAGER_PREFERENCES.lastSelectPath.defaultValue;
      const lastSelectPathKey = FILE_MANAGER_PREFERENCES.lastSelectPath.key;
      getPreferences(FILE_MANAGER_PREFERENCES.name).then(preferences => {
        preferences.get(lastSelectPathKey, defaultValue).then((result: string) => {
          AppStorage.SetOrCreate<string>(lastSelectPathKey, result);
          resolve();
          Logger.i(TAG, 'initLastSelectPath result: ' + result);
        }).catch((error) => {
          AppStorage.SetOrCreate<string>(lastSelectPathKey, defaultValue);
          Logger.e(TAG, 'initLastSelectPath preferences.get fail, error:' + JSON.stringify(error));
          resolve();
        })
      }).catch(err => {
        AppStorage.SetOrCreate<string>(lastSelectPathKey, defaultValue);
        Logger.e(TAG, 'initLastSelectPath getPreferences fail, error: ' + JSON.stringify(err));
        resolve();
      })
    })
  }

  /**
   * 申请文件管理器需用户授权的权限
   */
  export function requestPermission(): Promise<void> {
    let atManager = abilityAccessCtrl.createAtManager()
    try {
      return atManager.requestPermissionsFromUser(globalThis.abilityContext, PERMISSION_LIST).then((data) => {
        if (data.authResults.some(item => item !== 0)) {
          Logger.e(TAG, 'requestPermissionsFromUser some permission request fail, result:' + JSON.stringify(data))
        } else {
          Logger.i(TAG, 'requestPermissionsFromUser success, result:' + JSON.stringify(data))
        }
      }).catch((error) => {
        Logger.e(TAG, 'requestPermissionsFromUser fail, error:' + JSON.stringify(error))
      })
    } catch (error) {
      Logger.e(TAG, 'requestPermissionsFromUser error occurred, error:' + JSON.stringify(error))
    }
  }

  /**
   * uri授权
   * @param uriList 待授权的uri列表
   * @param bundleName 授权应用的包名
   */
  export function grantUriPermission(uriList: Array<string>, bundleName: string): Promise<boolean> {
    return new Promise(async (resolve, reject) => {
      Logger.i(TAG, "grantUriPermission start,grantSize = " + uriList?.length);
      let grantSuccessCount: number = 0;
      for (let uri of uriList) {
        try {
          await FileShare.grantUriPermission(
            uri,
            bundleName,
            wantConstant.Flags.FLAG_AUTH_READ_URI_PERMISSION | wantConstant.Flags.FLAG_AUTH_WRITE_URI_PERMISSION);
          grantSuccessCount++;
        } catch (error) {
          resolve(false);
          Logger.e(TAG, `grantUriPermission fail,grantSuccessCount:${grantSuccessCount}}, uri: ${uri}, error: ${JSON.stringify(error)}`);
          return;
        }
      }
      Logger.i(TAG, "grantUriPermission end,grantSuccessCount = " + grantSuccessCount);
      resolve(true)
    })

  }

  /**
   * 文件选择完成，返回uri列表
   * @param resultCode
   * @param result
   * @param message
   */
  export async function terminateFilePicker(result: Array<string> = [], displayNames: Array<string> = [], resultCode: number = RESULT_CODE.SUCCESS, message: string = ''): Promise<void> {
    const bundleName = globalThis.pickerCallerBundleName
    if (result.length && bundleName) {
      // uri授权
      const isSuccess = await grantUriPermission(result, bundleName);
      if (!isSuccess) {
        resultCode = ErrorCodeConst.PICKER.GRANT_URI_PERMISSION_FAIL,
        result = []
        message = 'uri grant permission fail'
        displayNames = []
      }
    }

    let abilityResult = {
      resultCode: resultCode,
      want: {
        bundleName: globalThis.abilityContext.abilityInfo.bundleName,
        abilityName: ABILITY_LIST.FILE_PICKER,
        parameters: {
          'select_item_list': result,
          'file_name_list': displayNames,
          message: message,
          'result': result[0],
        }
      }
    }
    globalThis.abilityContext.terminateSelfWithResult(abilityResult, (error) => {
      if (error.code) {
        Logger.e(TAG, 'terminateFilePicker failed. Cause: ' + JSON.stringify(error))
        return
      }
      Logger.d(TAG, 'terminateFilePicker success. result: ' + JSON.stringify(abilityResult))
    })
  }
  /**
   * 文件创建完成，返回uri列表
   * @param result
   * @param resultCode
   * @param message
   */
  export async function terminatePathPicker(result: Array<string>, resultCode: number = RESULT_CODE.SUCCESS, message: string = ''): Promise<void> {
    const bundleName = globalThis.pathCallerBundleName
    if (result.length && bundleName) {
      // uri授权
      const isSuccess = await grantUriPermission(result, bundleName);
      if (!isSuccess) {
        resultCode = ErrorCodeConst.PICKER.GRANT_URI_PERMISSION_FAIL,
        result = []
        message = 'uri grant permission fail'
      }
    }
    let abilityResult = {
      resultCode: resultCode,
      want: {
        bundleName: globalThis.pathAbilityContext.abilityInfo.bundleName,
        abilityName: ABILITY_LIST.PATH_PICKER,
        parameters: {
          'pick_path_return': result,
          'key_pick_select_clouddisk': false,
          'message': message,
          // 兼容老版本picker
          'result': result[0]
        }
      }
    }
    globalThis.pathAbilityContext.terminateSelfWithResult(abilityResult, (error) => {
      if (error.code) {
        Logger.e(TAG, 'terminatePathPicker failed. Cause: ' + JSON.stringify(error))
        return
      }
      Logger.d(TAG, 'terminatePathPicker success. result: ' + JSON.stringify(abilityResult))
    })
  }

  /**
   * 获取选择文件的最大个数
   * @param num 调用方传入的个数
   */
  export function getPickFileNum(num: any): number {
    if (typeof num === 'number') {
      if (num > 0 && num <= MAX_FILE_PICK_NUM) {
        return num;
      }
    }
    return MAX_FILE_PICK_NUM;
  }

  /**
   * 获取选择文件的类型列表
   * @param keyPickType 调用方传入文件类型（兼容双框架action）
   * @param keyPickTypeList 调用方传入文件类型列表
   */
  export function getKeyPickTypeList(keyPickType, keyPickTypeList): Array<string>{
    let typeList =[]
    if (keyPickType) {
      typeList.push(keyPickType)
    }
    if (keyPickTypeList && keyPickTypeList.length !== 0) {
      typeList = typeList.concat(keyPickTypeList)
    }
    return typeList.filter(item => item)
  }

  /**
   * 获取选择文件Mode,默认选择文件
   * @param keySelectMode 调用方传入文件mode
   */
  export function getKeySelectMode(keySelectMode: any): number {
    if (typeof keySelectMode === 'number') {
      if (keySelectMode === SELECT_MODE.FILE
        || keySelectMode === SELECT_MODE.FOLDER
        || keySelectMode === SELECT_MODE.MIX) {
        return keySelectMode;
      }
    }
    return SELECT_MODE.FILE;
  }

  /**
   * 获取支持的文件后缀列表
   * @param keyFileSuffixFilter 调用方传入文件后缀列表
   */
  export function getKeyFileSuffixFilter(keyFileSuffixFilter: string[]): Array<string> {
    let suffixList = [];
    if (!ArrayUtil.isEmpty(keyFileSuffixFilter)) {
      let len = keyFileSuffixFilter.length;
      let size = len > SUFFIX_LIST_MAX_LENGTH ? SUFFIX_LIST_MAX_LENGTH : len;
      for (let index = 0; index < size; index++) {
        const suffixStr = keyFileSuffixFilter[index];
        if (typeof suffixStr === 'string') {
          const suffixArray = suffixStr.split(FILE_SUFFIX.SUFFIX_SPLIT);
          for (let index = 0; index < suffixArray.length; index++) {
            const suffix = suffixArray[index];
            if (checkFileSuffix(suffix)) {
              suffixList.push(suffix.toUpperCase())
            }
          }
        }
      }
    }
    return suffixList.filter((item, index, array) => {
      return array.indexOf(item) === index;
    });
  }

  export function checkFileSuffix(fileSuffix: String): boolean {
    return fileSuffix && fileSuffix.length <= SUFFIX_MAX_LENGTH && fileSuffix.startsWith(FILE_SUFFIX.SUFFIX_START);
  }

  /**
   * 路径选择器获取支持的文件后缀，只支持获取第一个文件后缀
   * @param keyFileSuffixChoices 调用方传入文件后缀列表
   */
  export function getKeyFileSuffixChoices(keyFileSuffixChoices: string[]): string {
    if (!ArrayUtil.isEmpty(keyFileSuffixChoices)) {
      let len = keyFileSuffixChoices.length;
      let size = len > SUFFIX_LIST_MAX_LENGTH ? SUFFIX_LIST_MAX_LENGTH : len;
      for (let index = 0; index < size; index++) {
        const suffixStr = keyFileSuffixChoices[index];
        if (typeof suffixStr === 'string') {
          const suffixArray = suffixStr.split(FILE_SUFFIX.SUFFIX_SPLIT);
          for (let index = 0; index < suffixArray.length; index++) {
            const suffix = suffixArray[index];
            if (checkFileSuffix(suffix)) {
              return suffix;
            }
          }
        }
      }
    }
    return '';
  }

  /**
   * 获取媒体库对象实例的统一接口
   */
  export function getMediaLibrary(): MediaLibrary.MediaLibrary {
    if (!mediaLibrary) {
      try {
        mediaLibrary = MediaLibrary.getMediaLibrary(globalThis.abilityContext)
      } catch (error) {
        Logger.e(TAG, 'getMediaLibrary fail, error:' + JSON.stringify(error))
      }
    }
    return mediaLibrary
  }

  export function releaseMediaLibrary(): void {
    if (!mediaLibrary) {
      try {
        mediaLibrary.release()
      } catch (error) {
        Logger.e(TAG, 'releaseMediaLibrary fail, error: ' + JSON.stringify(error))
      }
    }
  }
}

export default AbilityCommonUtil
