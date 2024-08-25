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

import { toast } from '../../base/utils/Common';
import { FileMimeTypeUtil } from '../../base/utils/FileMimeTypeUtil';
import { FILE_SUFFIX, SELECT_MODE } from '../constants/Constant';
import ObjectUtil from './ObjectUtil';

/**
 * 文件选择器文件状态
 *
 * @param item 文件对象
 * @param checkedNum 选中数量
 * @return 是否超限  选择类型是否不匹配
 */
export function pickerStatus(item, checkedNum) {
  return {
    // 选择是否超限
    exceedLimit: globalThis.filePickerViewFlag && (checkedNum >= globalThis.filePickNum && !item.isChecked),
    // 选择类型是否不匹配
    differentTypes: !checkFileSelectable(item)
  };
}

/**
 * 根据文件后缀判断文件是否可选
 * @param item
 */
function checkFileSelectable(item): boolean {
  // 非文件选择器场景
  if (!globalThis.filePickerViewFlag) {
    return true;
  }

  // selectMode检查
  let selectMode: number = globalThis.keySelectMode;
  let isFolder = false;
  if (ObjectUtil.hasKey(item, 'isFolder')) {
    isFolder = item.isFolder;
  }
  // 文件夹模式，直接返回
  if (selectMode === SELECT_MODE.FOLDER) {
    return isFolder;
  }

  if (isFolder) {
    // 混选模式下，文件夹直接返回
    if (selectMode === SELECT_MODE.MIX) {
      return true;
    }
    // 文件模式下，文件夹直接返回false
    return false;
  }
  // 后缀检查
  let keyFileSuffixFilter: string[] = globalThis.keyFileSuffixFilter;
  if (Array.isArray(keyFileSuffixFilter) && keyFileSuffixFilter.length > 0) {
    return checkFileSuffix(item.fileName, keyFileSuffixFilter);
  }

  // mimeType检查
  return checkFileMimetype(item.fileName);
}

/**
 * 校验选中的文件后缀
 *
 * @param fileName 文件名称
 * @param keyFileSuffixFilter 指定后缀
 * @return 如果文件后缀满足三方指定，则返回true
 */
function checkFileSuffix(fileName: string, keyFileSuffixFilter: Array<string>): boolean {
  if (keyFileSuffixFilter) {
    if (fileName) {
      const suffix = FILE_SUFFIX.SUFFIX_START + FileMimeTypeUtil.getFileSuffix(fileName);
      if (keyFileSuffixFilter.includes(suffix)) {
        return true;
      }
    }
    return false;
  }
  return true;
}

/**
 * 校验选中的文件mimetype
 *
 * @param fileName 文件名称
 * @return 条件满足返回true
 */
function checkFileMimetype(fileName: string): boolean {
  if (!fileName) {
    return false;
  }
  let keyPickTypeList: string[] = globalThis.keyPickTypeList;
  // 输入的类型全转换成小写，避免大小敏感问题
  keyPickTypeList.forEach(item => item.toLowerCase());
  // 类型列表为空或包含*或*/*时,可选择所有文件
  if (!keyPickTypeList || keyPickTypeList.length === 0 ||
    keyPickTypeList.includes('*') || keyPickTypeList.includes('*/*')) {
    return true;
  }

  const mimeTypeObj = FileMimeTypeUtil.getFileMimeType(fileName);
  const mimeType = mimeTypeObj.getMimeType();

  // mimeType未知不可选
  if (!mimeType) {
    return false;
  }

  // mimeType完全匹配
  if (keyPickTypeList.includes(mimeType)) {
    return true;
  }

  let fileCategory = mimeType;
  const index = mimeType.indexOf('/');
  if (index > 0) {
    fileCategory = mimeType.substring(0, index);
  }
  // 某一类文件
  if (keyPickTypeList.includes(fileCategory) || keyPickTypeList.includes(`${fileCategory}/*`)) {
    return true;
  }

  return false;
}

/**
 * 文件选择器 选择超限提示
 *
 * @param isImmersion 是否沉浸式
 */
export const filePickerTip = () => {
  globalThis.abilityContext.resourceManager.getPluralString($r('app.plural.filePickerTip').id, globalThis.filePickNum)
    .then((value) => {
      toast(value)
    })
}


