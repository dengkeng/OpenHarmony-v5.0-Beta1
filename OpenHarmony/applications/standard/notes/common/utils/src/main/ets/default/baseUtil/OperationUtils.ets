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

import {LogUtil} from './LogUtil'
import {MediaLibraryAccess} from '../access/MediaLibraryAccess';
import fileio from '@ohos.fileio';

const TAG = "OperationUtils"
export class OperationUtils {


    async copy(uri: string):Promise<string> {
        try {
            var context = globalThis.noteContext
            let fileAsset = await this.getFileAssetById(uri, context);
            if (fileAsset == null || fileAsset == undefined) {
                LogUtil.warn(TAG, "Failed to get fileAsset")
                return;
            }

            let fd = await MediaLibraryAccess.openAsset('RW', fileAsset);
            if (fd <= 0) {
                LogUtil.warn(TAG, "fd is invaild")
                return;
            }
            LogUtil.info(TAG, 'copyAsset read end!')

            // 通过Uri拷贝图片到指定指定的包路径下
            // 1、获取本地路径
            var dir = context.filesDir
            // 2、生成本地文件名
            var time = new Date().getTime()
            var imagePath = dir + "/" + time.toString() + "_note" + ".jpg"
            // 3、拷贝
            await fileio.copyFile(fd, imagePath)
            // 4、关闭安fd,Asset
            await MediaLibraryAccess.closeAsset(fd, fileAsset);
        } catch (error) {
            LogUtil.info(TAG, "create error: " + error);
            return;
        }
        LogUtil.debug(TAG, 'copy end');

        return imagePath.toString()
    }

    saveImageData(dataArray: Uint8Array, imageType: string): string {
        try {
            var context = globalThis.noteContext
            // 1、获取本地路径
            var dir = context.filesDir
            var time = new Date().getTime()
            var imagePath = dir + "/" + time.toString() + "_note" + "." + imageType
            let fd = fileio.openSync(imagePath, 0o100 | 0o2, 0o666)
            // 3、把image数据写入本地图片文件中
            fileio.writeSync(fd, dataArray.buffer)
        } catch (error) {
            LogUtil.info(TAG, "create error: " + error);
            return;
        }
        LogUtil.info(TAG, 'save image end');

        return imagePath.toString()
    }

    saveImage(imageData: string, imageType: string): string {
        try {
            var context = globalThis.noteContext
            // 1、获取本地路径
            var dir = context.filesDir
            // 2、生成本地文件名
            var time = new Date().getTime()
            var imagePath = dir + "/" + time.toString() + "_note" + "." + imageType
            let fd = fileio.openSync(imagePath, 0o100 | 0o2, 0o666)
            let arrayBuffer = new ArrayBuffer(imageData.length)
            let ia = new Uint8Array(arrayBuffer)
            for(let i = 0; i < imageData.length; i++) {
                ia[i] = imageData.charCodeAt(i)
            }

            // 3、把image数据写入本地图片文件中
            fileio.writeSync(fd, ia.buffer)

        } catch (error) {
            LogUtil.info(TAG, "create error: " + error);
            return;
        }
        LogUtil.debug(TAG, 'save image end');

        return imagePath.toString()
    }

    getIdByUri(uri:string): number {
        let srcIndex = uri.lastIndexOf('/');
        let srcEnd = uri.length;
        let srcId = uri.substring(srcIndex + 1, srcEnd);
        let numId = new Number(srcId);
        LogUtil.debug(TAG, `getIdByUri numId: ${numId}`);
        return numId.valueOf();
    }

    async getFileAssetById(imagePath, context){
        LogUtil.info(TAG, 'getFileAssetById', imagePath);
        let fetchOpt = {
            selections : '',
            selectionArgs : [],
            uri:imagePath
        }

        try {
            let result = await MediaLibraryAccess.getFirstObject(fetchOpt, context);
            if (result == null) {
                LogUtil.info(TAG, 'getFileAssetByUri fail');
                return null;
            }
            return result.obj;
        } catch (error) {
            LogUtil.info(TAG, 'getFileAssetById error');
            return null;
        }
    }
}

let mOperationUtils = new OperationUtils();
export default mOperationUtils as OperationUtils;
