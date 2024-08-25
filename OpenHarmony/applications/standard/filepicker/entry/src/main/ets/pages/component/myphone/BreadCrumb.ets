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

import { BreadData } from '../../../databases/model/FileData';

@Styles
function pressedStyles() {
  .backgroundColor($r('app.color.hicloud_hmos_bg'))
  .borderRadius($r('app.float.common_borderRadius8'))
}

@Styles
function normalStyles() {
  .backgroundColor($r('app.color.transparent_color'))
  .borderRadius($r('app.float.common_borderRadius8'))
}

@Component
export struct BreadCrumb {
  @Link @Watch('onDireListUpdated') direList: BreadData[];
  scroller: Scroller = new Scroller();

  // 监听面包屑变化，滚动到指定位置
  onDireListUpdated(): void {
    setTimeout(() => {
      this.scroller.scrollEdge(Edge.End);
    }, 10);
  }

  build() {
    Row() {
      Row() {
        Text($r('app.string.myPhone'))
          .fontSize($r('app.float.common_font_size12'))
          .opacity($r('app.float.common_opacity9'))
          .height($r('app.float.common_size30'))
          .fontColor(this.direList.length ? $r('app.color.detail_path_text_color') : $r('app.color.black'))
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .stateStyles({
            pressed: pressedStyles,
            normal: normalStyles
          })
        if (this.direList.length) {
          Image($r('app.media.ic_arrow_right'))
            .objectFit(ImageFit.Contain)
            .height($r('app.float.common_size15'))
            .width($r('app.float.common_size15'))
            .interpolation(ImageInterpolation.Medium)
        }
      }
      .onClick(() => {
        if (!this.direList.length) {
          return;
        }
        this.direList = [];
      })

      Scroll(this.scroller) {
        Row() {
          ForEach(this.direList, (item, index) => {
            BreadCrumbItem({
              direItem: item,
              index: index,
              direList: $direList,
            })
          }, item => item.url.toString())
        }
      }
      .layoutWeight(1)
      .align(Alignment.TopStart)
      .scrollBar(BarState.Off)
      .scrollable(ScrollDirection.Horizontal)
    }
    .padding({ left: $r('app.float.common_padding16'), right: $r('app.float.common_padding16') })
  }
}

@Component
struct BreadCrumbItem {
  direItem: BreadData;
  index: number;
  @Link direList: BreadData[];

  getTitle(breadCrumb: string) {
    const breadCrumbMaxLength = 10;
    return breadCrumb.length > breadCrumbMaxLength ? breadCrumb.substring(0, breadCrumbMaxLength) + '...' : breadCrumb;
  }

  isLast(): boolean {
    return this.index === this.direList.length - 1;
  }

  build() {
    Row() {
      Text(this.getTitle('' + this.direItem.title))
        .fontSize($r('app.float.common_font_size12'))
        .opacity($r('app.float.common_opacity9'))
        .fontColor(this.isLast() ? $r('app.color.black') : $r('app.color.detail_path_text_color'))
        .height($r('app.float.common_size30'))
        .margin({ left: $r('app.float.common_size4'), right: $r('app.float.common_size4') })
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .textAlign(TextAlign.Center)
        .maxLines(1)
        .stateStyles({
          pressed: pressedStyles,
          normal: normalStyles
        })
      if (!this.isLast()) {
        Image($r('app.media.ic_arrow_right'))
          .objectFit(ImageFit.Contain)
          .autoResize(false)
          .height($r('app.float.common_size15'))
          .width($r('app.float.common_size15'))
      }
    }
    .height($r('app.float.common_size30'))
    .onClick(() => {
      if (this.isLast()) {
        return;
      }
      this.direList.splice(this.index + 1);
    })
  }
}

