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

import { BreadData, FilesData, FileDataSource } from '../../../databases/model/FileData';
import { renderSize, gridName, isDlpFile } from '../../../base/utils/Tools';
import DateTimeUtil from '../../../base/utils/DateTimeUtil';
import { pickerStatus, filePickerTip } from '../../../base/utils/FilePickerUtil';
import { Z_INDEX } from '../../../base/constants/UiConstant';
import Logger from '../../../base/log/Logger';
import { NoContent } from '../common/NoContent';
import { VideoDurationTag } from '../common/VideoDurationTag';

const TAG = 'MyPhone_FilesList';
const filePickerViewFlag = globalThis.filePickerViewFlag;

@Styles function pressedStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
}

@Styles function normalStyles() {
  .borderRadius($r('app.float.common_borderRadius8'))
  .backgroundColor($r('app.color.transparent_color'))
}

@Extend(Text) function grayText() {
  .fontSize($r('app.float.common_font_size12'))
  .fontColor($r('app.color.black'))
  .lineHeight($r('app.float.common_size19'))
  .opacity($r('app.float.common_opacity6'))
}

@Component
export struct FilesList {
  @Link fileListSource: FileDataSource;
  /**
   * 面包屑
   */
  @Link direList: BreadData[];
  @Link isMulti: boolean;
  /**
   * 已选择项数
   */
  @Link checkedNum: number;
  /**
   * 列表展示
   */
  @Consume isList: boolean;

  build() {
    Column() {
      if (this.fileListSource.dataCount) {
        if (this.isList) {
          this.buildListView();
        } else {
          this.buildGridView();
        }
      } else {
        NoContent();
      }
    }
    .width('100%')
    .height('100%')
  }

  @Builder
  buildListView() {
    List() {
      LazyForEach(this.fileListSource, (item, index) => {
        ListItem() {
          FileListItem({
            fileItem: item,
            fileListSource: $fileListSource,
            direList: $direList,
            checkedNum: $checkedNum,
            isMulti: $isMulti
          })
        }
      }, item => item?.id.toString())
    }
    .align(Alignment.TopStart)
    .edgeEffect(EdgeEffect.None)
  }

  @Builder
  buildGridView() {
    Grid() {
      LazyForEach(this.fileListSource, (item, index) => {
        GridItem() {
          FileListItem({
            fileItem: item,
            fileListSource: $fileListSource,
            direList: $direList,
            checkedNum: $checkedNum,
            isMulti: $isMulti
          })
        }
      }, item => item?.id.toString())
    }
    .columnsTemplate('1fr 1fr 1fr')
    .columnsGap($r('app.float.file_list_columns_gap'))
    .rowsGap($r('app.float.file_list_rows_gap'))
    .padding({ left: $r('app.float.common_padding12'), right: $r('app.float.common_padding12') })
    .height('100%')
  }
}


@Component
struct FileListItem {
  @Consume isList: boolean;
  @State fileItem: FilesData = new FilesData({});
  @Link fileListSource: FileDataSource;
  @Link direList: BreadData[];
  @Link @Watch('isMultiChange') isMulti: boolean;
  @Link checkedNum: number;
  @State isChecked: boolean = false;
  @State filePickerViewFlag: boolean = globalThis.filePickerViewFlag;
  @State isImageLoaded: boolean = true;

  isShowThumbnail(item) {
    return this.isImageLoaded && item.thumbUri;
  }

  isMultiChange() {
    this.isChecked = false;
  }

  async aboutToAppear(): Promise<void> {
    this.isChecked = this.fileItem.isChecked;
    if (!this.isMulti) {
      this.isChecked = false;
      this.fileItem.isChecked = false;
    }
  }

  getRightIcon(item): Resource {
    if (this.isMulti) {
      if (pickerStatus(this.fileItem, this.checkedNum).differentTypes) {
        return;
      }
      return item.isChecked ? $r('app.media.checkbox_b') : $r('app.media.checkbox_g');
    } else if (item.isFolder && this.isList) {
      return $r('app.media.ic_arrow_right');
    }
  }

  build() {
    Row() {
      if (this.isList) {
        this.buildListItemView();
      } else {
        this.buildGridItemView();
      }
    }
    .opacity(this.calOpacity())
    .onClick(async () => {
      this.onClickEvent();
    })
    .stateStyles({
      pressed: pressedStyles,
      normal: normalStyles
    })
    .gesture(
      LongPressGesture({ repeat: false })//长按动作存在会连续触发
        .onAction((event: GestureEvent) => {
          this.longPressEvent();
        })
    )
  }

  /**
   * 长按
   */
  longPressEvent() {
    Logger.i(TAG, 'longPressEvent start');
    if (!this.isMulti) {
      this.isMulti = true;
      if (this.fileItem.isFolder) {
        return;
      }
      let status = pickerStatus(this.fileItem, this.checkedNum);
      if (status.exceedLimit) {
        filePickerTip();
        return;
      }
      if (status.differentTypes) {
        return;
      }

      this.fileItem.isChecked = true;
      this.isChecked = true;
      this.checkedNum++;
    }
  }

  onClickEvent() {
    Logger.i(TAG, 'onClickEvent start');
    let status = pickerStatus(this.fileItem, this.checkedNum);
    if (this.isMulti) {
      if (this.fileItem.isFolder) {
        return;
      }
      // 选择器页面，选择文件超出上限
      if (status.exceedLimit) {
        filePickerTip();
        return;
      } else if (status.differentTypes) {
        return;
      }

      // 多选模式下文件选择状态切换
      this.fileItem.isChecked = !this.fileItem.isChecked;
      this.isChecked = this.fileItem.isChecked;
      if (this.isChecked) {
        this.checkedNum++;
      } else {
        if (this.checkedNum > 0) {
          this.checkedNum--;
        }
      }
    } else {
      if (!this.fileItem.isFolder) {
        if (status.differentTypes) {
          return;
        }
        if (!status.exceedLimit && !status.differentTypes) {
          // 选中的数据回调给三方应用
          this.fileItem.pickFile();
          return;
        }
      }
      this.clickFolder();
    }
  }

  /**
   * 点击文件夹
   */
  clickFolder() {
    this.direList.push({
      title: this.fileItem.fileName,
      url: this.fileItem.uri,
      fileIterator: this.fileItem.fileIterator
    });
  }

  calOpacity() {
    const statusObj = pickerStatus(this.fileItem, this.checkedNum);
    return statusObj.exceedLimit || (!this.fileItem.isFolder && statusObj.differentTypes) ||
      (this.isMulti && this.fileItem.isFolder) ? $r('app.float.common_opacity2') : $r('app.float.common_opacity10');
  }

  @Builder
  buildListItemView() {
    Flex({ alignItems: ItemAlign.Center }) {
      Column() {
        Image(this.isShowThumbnail(this.fileItem) ? this.fileItem.thumbUri : this.fileItem.icon)
          .objectFit(this.isShowThumbnail(this.fileItem) ? ImageFit.Cover : ImageFit.Contain)
          .autoResize(false)
          .height($r('app.float.common_size36'))
          .width($r('app.float.common_size36'))
          .borderRadius($r('app.float.album_borderRadius_5'))
          .onError((error) => {
            this.isImageLoaded = false
            Logger.e(TAG, 'onError: ' + this.fileItem.fileName +
              ', ' + this.fileItem.thumbUri + ',' + JSON.stringify(error))
          })
        if (isDlpFile(this.fileItem.fileName)) {
          Image($r('app.media.lockNoBorder'))
            .objectFit(ImageFit.Fill)
            .width($r('app.float.common_size6'))
            .height($r('app.float.common_size8'))
            .zIndex(Z_INDEX.LEVEL10)
            .position({ x: $r('app.float.common_position24'), y: $r('app.float.common_position26') })
        }
        if (this.fileItem.mimeTypeObj.isVideo() && this.isShowThumbnail(this.fileItem)) {
          Image($r('app.media.hidisk_ic_video_list'))
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height($r('app.float.common_size20'))
            .width($r('app.float.common_size20'))
            .position({ x: $r('app.float.common_position8'), y: $r('app.float.common_position8') })
        }
      }

      Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Start, justifyContent: FlexAlign.Center }) {
        Text(this.fileItem.fileName)
          .fontSize($r('app.float.common_font_size14'))
          .fontWeight(FontWeight.Medium)
          .maxLines(2)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .fontColor($r('app.color.black'))
        Row() {
          Text(DateTimeUtil.getDateStringForCategory(this.fileItem.mtime))
            .grayText()
          Text('-')
            .grayText()
          Text(!this.fileItem.isFolder ? renderSize(this.fileItem.size) : $r('app.string.num', this.fileItem.sub))
            .grayText()
        }
        .margin({ top: $r('app.float.common_padding2') })
        .opacity($r('app.float.common_opacity6'))
      }
      .flexGrow(1)
      .margin({ left: $r('app.float.common_margin10') })
      .width('70%')

      if ((this.fileItem.isFolder && !this.isMulti) || (this.isMulti && !this.fileItem.isFolder)) {
        Image(this.getRightIcon(this.fileItem))
          .objectFit(ImageFit.Contain)
          .autoResize(false)
          .height($r('app.float.common_size20'))
          .width($r('app.float.common_size20'))
      }
    }
    .height($r('app.float.common_size64'))
    .padding({ right: $r('app.float.common_padding16'), left: $r('app.float.common_padding16') })
  }

  @Builder
  buildGridItemView() {
    Flex({ direction: FlexDirection.Column,
      alignItems: ItemAlign.Center }) {
      Column() {
        Column() {
          Image(this.isShowThumbnail(this.fileItem) ? this.fileItem.thumbUri : this.fileItem.localGridIcon)
            .objectFit(this.isShowThumbnail(this.fileItem) ? ImageFit.Cover : ImageFit.Contain)
            .borderRadius($r('app.float.album_borderRadius_8'))
            .width('100%')
            .onError(() => {
              this.isImageLoaded = false
            })
          if ((this.fileItem.isFolder && !this.isMulti) || (this.isMulti && !this.fileItem.isFolder)) {
            Image(this.getRightIcon(this.fileItem))
              .objectFit(ImageFit.Fill)
              .width($r('app.float.common_size20'))
              .height($r('app.float.common_size20'))
              .opacity(true ? 1 : $r('app.float.common_opacity4'))
              .markAnchor({ x: $r('app.float.common_vp26'), y: $r('app.float.common_vp26') })
              .position({ x: '100%', y: '100%' })
          }
          if (isDlpFile(this.fileItem.fileName)) {
            Image($r('app.media.lockNoBorder'))
              .objectFit(ImageFit.Fill)
              .width($r('app.float.common_size10'))
              .height($r('app.float.common_size12'))
              .zIndex(Z_INDEX.LEVEL10)
              .markAnchor({ x: $r('app.float.common_markAnchor_28'), y: $r('app.float.common_markAnchor_16') })
              .position({ x: '100%', y: '100%' })
          }
          if (this.fileItem.mimeTypeObj.isVideo() && this.isShowThumbnail(this.fileItem)) {
            VideoDurationTag({
              duration: this.fileItem.duration
            })
          }
        }.width('100%')
        .aspectRatio(1)
        .padding({ bottom: $r('app.float.common_padding10') })

        Text(gridName(this.fileItem.fileName))
          .fontSize($r('app.float.common_font_size12'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .fontColor($r('app.color.recently_font_color'))
          .maxLines(1)
        Text(this.fileItem.mtime ? DateTimeUtil.getDateStringForCategory(this.fileItem.mtime) : '')
          .fontSize($r('app.float.common_font_size10'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .fontColor($r('app.color.recently_font_color'))
          .opacity($r('app.float.common_opacity6'))
        Text(this.fileItem.isFolder ? $r('app.string.num', this.fileItem.sub) : renderSize(this.fileItem.size))
          .fontSize($r('app.float.common_font_size10'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(1)
          .fontColor($r('app.color.recently_font_color'))
          .opacity($r('app.float.common_opacity6'))
      }
      .borderRadius($r('app.float.album_borderRadius_5'))
      .padding({
        left: $r('app.float.common_padding4'),
        right: $r('app.float.common_padding4'),
        top: $r('app.float.common_padding10'),
        bottom: $r('app.float.common_padding10')
      })
    }
  }
}