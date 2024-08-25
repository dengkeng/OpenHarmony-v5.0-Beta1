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
import { PrintPageSize } from '../framework/Print';

import { MediaType } from '../model/Constants';
import { MediaSize, MediaSizeHelper } from '../model/MediaSize';

export class MediaSizeUtil {
  public static readonly defaultSizeCode = 26;

  public static getMediaSizeArrayByCodes(codes: number[]): PrintPageSize[] {
    return codes.map((code) => {
      if (MediaSizeHelper.sCodeToStringMap.has(code)) {
        let mediaSize = MediaSizeHelper.sCodeToStringMap.get(code);
        let pageSize = new PrintPageSize(code.toString(),mediaSize.name,mediaSize.heightMils,mediaSize.widthMils);
        return pageSize;
      }
      return null;
    });
  }

  public static getDefaultMediaSizeByMediaType(mediaType: number): Array<MediaSize> {
    let list: Array<MediaSize> = new Array<MediaSize>();
    if (mediaType === MediaType.NORMAL) {
      return this.getDocSizeList();
    }
    if (mediaType === MediaType.PHOTO) {
      return this.getPhotoSizeList();
    }
    return list;
  }

  public static getDocSizeList(): Array<MediaSize> {
    let list: Array<MediaSize> = new Array<MediaSize>();
    list.push(MediaSizeHelper.ISO_A4);
    list.push(MediaSizeHelper.ISO_A5);
    list.push(MediaSizeHelper.JIS_B5);
    list.push(MediaSizeHelper.ISO_C5);
    list.push(MediaSizeHelper.ISO_DL);
    return <Array<MediaSize>>list;
  }

  public static getPhotoSizeList(): Array<MediaSize> {
    let list: Array<MediaSize> = new Array<MediaSize>();
    list.push(MediaSizeHelper.ISO_A4);
    list.push(MediaSizeHelper.PHOTO_4x6);
    list.push(MediaSizeHelper.PHOTO_5x7);
    return <Array<MediaSize>>list;
  }

  public static initMediaSizeArray(mediaSizeArray: Array<MediaSize>): void {
    mediaSizeArray.push(MediaSizeHelper.ISO_A4);
    mediaSizeArray.push(MediaSizeHelper.ISO_A5);
    mediaSizeArray.push(MediaSizeHelper.JIS_B5);
    mediaSizeArray.push(MediaSizeHelper.ISO_C5);
    mediaSizeArray.push(MediaSizeHelper.ISO_DL);
    mediaSizeArray.push(MediaSizeHelper.LETTER);
    mediaSizeArray.push(MediaSizeHelper.LEGAL);
    mediaSizeArray.push(MediaSizeHelper.PHOTO_4x6);
    mediaSizeArray.push(MediaSizeHelper.PHOTO_5x7);
  }

  public static mediaSizeToPageSize(mediaSize: MediaSize): PrintPageSize {
    let pageSize = new PrintPageSize(mediaSize.id, mediaSize.name, mediaSize.widthMils, mediaSize.heightMils);
    return pageSize;
  }

  public static pageSizeToMediaSize(pageSize: PrintPageSize): MediaSize {
    let mediaSize = this.getMediaSizeByCode(Number.parseInt(pageSize.id));
    return mediaSize;
  }

  public static getCodesBySizes(sizes: string[]): number[] {
    let codes: number[] = new Array<number>();
    for (let size of sizes) {
      for (let key of MediaSizeHelper.sCodeToStringMap.keys()) {
        if (MediaSizeHelper.sCodeToStringMap.get(key).name === size) {
          codes.push(key);
        }
      }
    }
    return codes;
  }

  public static getMediaSizeByCode(code: number): MediaSize {
    let result: boolean = <boolean>MediaSizeHelper.sCodeToStringMap.has(code);
    if (result) {
      return MediaSizeHelper.sCodeToStringMap.get(code);
    }
    return MediaSizeHelper.sCodeToStringMap.get(MediaSizeUtil.defaultSizeCode);
  }

  public static toMediaCode(code: number): number {
    let result: boolean = <boolean>MediaSizeHelper.sCodeToStringMap.has(code);
    if (result) {
      return code;
    }
    return 0;
  }
}