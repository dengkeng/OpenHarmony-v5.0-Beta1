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

import { BusinessError } from '@ohos.base';
import ScreenshotManager from '@ohos.screenshot';
import WindowMar from '@ohos.window';
import ImageMar from '@ohos.multimedia.image';
import mediaLibrary from '@ohos.multimedia.mediaLibrary';
import FileIo from '@ohos.fileio';
import display from '@ohos.display';
import Constants from '../common/constants';
import Log from '../../../../../../../../common/src/main/ets/default/Log';
import Want from '@ohos.app.ability.Want';

const TAG = 'ScreenShot-ScreenShotModel';

const SCREEN_SHOT_PATH = 'Screenshots/';
const SCREENSHOT_PREFIX = 'Screenshot';
const PICTURE_TYPE = '.jpg';
const SAVE_IMAGE_DELAY = 300;
const OPTIONS_QUALITY = 100;
const CREATE_WINDOW_DELAY = 300;

export class ScreenShotModel {
  private captureImage: ImageMar.PixelMap | undefined = undefined;
  private imageFileName: string = '';

  async shotScreen() {
    Log.showInfo(TAG, 'shotScreen');
    await new Promise<number>((resolve) => setTimeout(resolve, CREATE_WINDOW_DELAY));
    ScreenshotManager.save().then(async (data) => {
      Log.showInfo(TAG, `ScreenshotManager.save data:${JSON.stringify(data)}`);
      if (!!data) {
        this.captureImage = data;
        AppStorage.Set('captureImage', data);
        this.saveImage(this.captureImage, {
          format: 'image/jpeg',
          quality: OPTIONS_QUALITY,
        });
      }
    }).catch((err: BusinessError) => {
      Log.showInfo(TAG, `ScreenshotManager.save err:${JSON.stringify(err)}`);
    });
  }

  async saveImage(pixelMap: ImageMar.PixelMap, options: ImageMar.PackingOption) {
    const media = mediaLibrary.getMediaLibrary(globalThis.shotScreenContext);
    Log.showInfo(TAG, `saveImage options:${JSON.stringify(options)}`);
    this.imageFileName = SCREENSHOT_PREFIX + '_' + (new Date()).getTime() + PICTURE_TYPE;
    const packer = ImageMar.createImagePacker();
    Log.showInfo(TAG, `saveImage packer:${JSON.stringify(packer)}`);
    this.showWindow();
    await new Promise<number>((resolve) => setTimeout(resolve, SAVE_IMAGE_DELAY));
    packer.packing(pixelMap, options).then((jpegData) => {
      Log.showInfo(TAG, 'packing jpegData type:' + jpegData.constructor.name + '  value : ' + jpegData);
      media.getPublicDirectory(mediaLibrary.DirectoryType.DIR_IMAGE, (err, rp) => {
        if (rp != undefined) {
          Log.showInfo(TAG, `getPublicDirectory successful:${JSON.stringify(rp)}`);
          media.createAsset(mediaLibrary.MediaType.IMAGE, this.imageFileName, rp + SCREEN_SHOT_PATH,
            (createAssetErr, fileAsset) => {
              if (fileAsset != undefined) {
                Log.showInfo(TAG, `createAsset successful:${JSON.stringify(fileAsset.uri)}`);
                fileAsset.open('rw').then((fd) => {
                  if (fd == undefined) {
                    Log.showInfo(TAG, 'fileAsset open fail');
                    return;
                  }
                  Log.showInfo(TAG, `open successful, fd = ${JSON.stringify(fd)}`);
                  FileIo.write(fd, jpegData).then(num => {
                    Log.showInfo(TAG, `FileIo write, num = ${JSON.stringify(num)}`);
                    fileAsset.close(fd).then(() => {
                      Log.showInfo(TAG, 'FileIo close,successful');
                    });
                  });
                });
              } else {
                Log.showInfo(TAG, 'createAsset fail');
              }
            });
        } else {
          Log.showInfo(TAG, 'getPublicDirectory fail');
        }
      });
    });
  }

  showWindow() {
    Log.showInfo(TAG, 'showWindow');
    WindowMar.find(Constants.WIN_NAME).then((win) => {
      win.show(() => {
        Log.showInfo(TAG, 'window show');
      });
    });
  }

  dismiss(): void {
    Log.showInfo(TAG, 'dismiss');
    //close ability
    globalThis.shotScreenContext.terminateSelf((err: BusinessError) => {
      Log.showInfo(TAG, `terminateSelf finish err:${err}`);
      WindowMar.find(Constants.WIN_NAME).then((win) => {
        win.destroy(() => {
          Log.showInfo(TAG, 'destroy the window finish');
        });
      });
    });
  }

  openAbility(wantData: Want) {
    Log.showInfo(TAG, `openAbility want:${JSON.stringify(wantData)}`);
    globalThis.shotScreenContext.startAbility(wantData);
  }
}

let screenShotModel = new ScreenShotModel();

export default screenShotModel as ScreenShotModel;