// @ts-nocheck
/**
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

import windowManager from '@ohos.window'
import Extension from '@ohos.WallpaperExtension'
import wallPaper from '@ohos.wallpaper'

const MODULE_TAG = 'ExtWallpaper : ';

export default class WallpaperExtAbility extends Extension {
    onCreated(want) {
        console.info(MODULE_TAG + 'ability on created start');
        windowManager.create(this.context, "wallpaper", 2000).then((win) => {
            win.loadContent("pages/index").then(() => {
                console.info(MODULE_TAG, "wallpaper window loadContent in then!")
                win.show().then(() => {
                    win.setFullScreen(true).then(() => {
                        console.info(MODULE_TAG, "set full");
                    });
                    console.info(MODULE_TAG, "then begin window show in then!");
                })
            })
        }, (error) => {
            Log.showError(TAG, name + " window createFailed, error.code = " + error.code)
        })
        //        super.setUiContent("pages/index");
        this.initWallpaperImage();
        console.info(MODULE_TAG + 'ability on created end');
    }

    onWallpaperChanged(wallpaperType) {
        console.info(MODULE_TAG + 'ability on wallpaper changed start, type is : ' + wallpaperType);
        if (wallPaper) {
            this.sendPixelMapData();
        }
        console.info(MODULE_TAG + 'ability on wallpaper changed end');
    }

    onDestroy() {
        console.info(MODULE_TAG + 'ability on destroy');
    }

    initWallpaperImage() {
        console.info(MODULE_TAG + 'ability init wallpaper image start');
        if (!wallPaper) {
            console.info(MODULE_TAG + 'ability init wallpaper image failed as wallpaper is null');
            return;
        }
        this.sendPixelMapData();
        console.info(MODULE_TAG + 'ability init wallpaper image end');
    }

    sendPixelMapData() {
        console.info(MODULE_TAG + 'ability send pixel map data start');
        wallPaper.getPixelMap(0, (err, data) => {
            console.info(MODULE_TAG + 'ability get pixel map, err: ' + JSON.stringify(err) +
            " data: " + JSON.stringify(data));
            AppStorage.SetOrCreate('slPixelData', data);
            console.info(MODULE_TAG + 'ability set or create end');
        });
        console.info(MODULE_TAG + 'ability send pixel map data end');
    }
};
