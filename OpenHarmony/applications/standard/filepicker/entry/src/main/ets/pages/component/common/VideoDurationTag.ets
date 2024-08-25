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

import DateTimeUtil from '../../../base/utils/DateTimeUtil';

@Component
export struct VideoDurationTag {
  @Prop duration: number;

  build() {
    Row() {
      Image($r('app.media.ic_news_video_play_tag'))
        .objectFit(ImageFit.Contain)
        .height($r('app.float.common_size6'))
        .width($r('app.float.common_size6'))
        .margin({ right: $r('app.float.common_margin2') })
      Text(DateTimeUtil.formatDuration(this.duration))
        .fontColor($r('app.color.white'))
        .fontSize($r('app.float.common_font_size10'))
    }
    .position({ x: 0, y: '100%' })
    .markAnchor({ x: $r('app.float.recent_markAnchor_4'), y: $r('app.float.recent_markAnchor_20') })
    .padding({
      left: $r('app.float.common_padding4'),
      right: $r('app.float.common_padding4'),
      top: $r('app.float.common_padding2'),
      bottom: $r('app.float.common_padding2')
    })
    .borderRadius($r('app.float.common_borderRadius8'))
    .backgroundColor('rgba(0, 0, 0, 0.35)')
  }
}