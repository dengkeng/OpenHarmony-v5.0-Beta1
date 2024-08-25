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

import SelectionModel from '../../Model/SelectionModel'
import { Log } from '@ohos/common';
import CheckEmptyUtils from '@ohos/common';
import WifiP2pHelper from '../../Common/Adapter/WifiP2pHelper';
import { Constants, Duplex, PrinterInfo } from '@ohos/common';

const TAG = 'SelectComponent'

@Extend(Row) function selectStyle()
{
  .width($r('app.float.select_comp_width'))
  .height($r('app.float.params_comp_height'))
  .margin({ top: $r('app.float.select_comp_margin_top'), bottom: $r('app.float.select_comp_margin_bottom')
  , left: $r('app.float.select_comp_margin_left'), right: $r('app.float.select_comp_margin_right') })
  .border({ width: $r('app.float.border_width'), radius: $r('app.float.radius_s'), color: $r('app.color.border_line') })
}

@Extend(Row) function selectItemStyle()
{
  .width($r('app.float.select_item_width'))
  .height($r('app.float.select_item_height'))
  .justifyContent(FlexAlign.Start)
  .margin({ top: $r('app.float.select_item_margin_top'), bottom: $r('app.float.select_item_margin_bottom') })
  .borderRadius($r('app.float.radius_m'))
}

@Component
export struct PrinterSelection {
  @Consume('PrinterSelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentPrinter') currentPrinterSelection: SelectionModel;
  @Consume('CanPrint') canPrint: boolean;
  @Provide('PrinterPopup') customPopup: boolean = false
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            PrinterSelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => select.name)
      }
      .edgeEffect(EdgeEffect.Spring)
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_printer'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_printer')
      Row() {
        LoadingProgress()
          .width($r('app.float.select_loadingProgress_size'))
          .height($r('app.float.select_loadingProgress_size'))
          .margin({
            left: $r('app.float.select_loadingProgress_margin_left'),
            right: $r('app.float.select_loadingProgress_margin_right')
          })
          .key('Index_LoadingProgress_printer')
          .visibility(this.checkLoading() ? Visibility.Visible : Visibility.None)
        Text(this.currentPrinterSelection.res)
          .fontSize($r('app.float.font_size_body2'))
          .textAlign(TextAlign.Start)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .maxLines(Constants.NUMBER_1)
          .width(this.checkLoading() ? $r('app.float.select_checkLoading_true_width') : $r('app.float.select_checkLoading_false_width'))
          .margin({
            left: this.checkLoading() ? $r('app.float.select_checkLoading_true_margin_left') : $r('app.float.select_checkLoading_false_margin_left')
          })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_Printer')
      .selectStyle()
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .backgroundColor(this.bgColor)
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }.height($r('app.float.params_row_height')).width($r('app.float.params_row_width'))

  }

  aboutToAppear() {
  }

  checkLoading() {
    let printer: PrinterInfo | undefined =
      SelectionModel.getSelectionValue<PrinterInfo>(this.currentPrinterSelection.name);
    if ((!CheckEmptyUtils.isEmpty(printer) && printer!.printerId !== '-1' && !this.canPrint)) {
      return true;
    }
    return false;
  }
}

@Component
struct PrinterSelectionComponent {
  @Consume('CurrentPrinter') currentPrinterSelection: SelectionModel;
  @Consume('PrinterPopup') customPopup: boolean
  @Consume('PrinterSelectFlag') printerSelectFlag: boolean
  @Consume('OpenWLANFlag') openWlanFlag: boolean
  @State bgColor: Resource = $r('app.color.effect_color_white');
  private selection?: SelectionModel;

  build() {
    Row() {
      Text(this.selection!.res)
        .textAlign(TextAlign.Start)
        .fontSize($r('app.float.font_size_body2'))
        .margin({ left: $r('app.float.select_text_margin_left'), right: $r('app.float.select_text_margin_right') })
        .onTouch((event: TouchEvent) => {
          if (event.type === TouchType.Down) {
            this.bgColor = $r('app.color.effect_color_press')
          }
          if (event.type === TouchType.Up) {
            this.bgColor = $r('app.color.effect_color_white')
          }
        })
    }
    .selectItemStyle()
    .onClick(() => {
      if (WifiP2pHelper.checkWifiActive()) {
        this.printerSelectFlag = true
      } else {
        this.openWlanFlag = !this.openWlanFlag
      }
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.bgColor = $r('app.color.effect_color_white')
      }
    })

  }
}


@Component
export struct MediaSizeSelection {
  @Consume('MediaSizeSelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentMediaSize') currentMediaSize: SelectionModel;
  @Provide('MediaSizePopup') customPopup: boolean = false;
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            MediaSizeSelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => JSON.stringify(select))
      }
      .edgeEffect(EdgeEffect.Spring)
      .scrollBar(this.selectArray.length > Constants.NUMBER_5 ? BarState.Auto : BarState.Off)
      .height(this.selectArray.length > Constants.NUMBER_5 ?
      $r('app.float.select_max_height') : this.selectArray.length * Constants.NUMBER_48)
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_media_size'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_mediaSize')
      Row() {
        Text(this.currentMediaSize.res).fontSize($r('app.float.font_size_body2')).textAlign(TextAlign.Start)
          .width($r('app.float.select_text_width'))
          .margin({ left: $r('app.float.select_text_margin_left') })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_MediaSize')
      .selectStyle()
      .backgroundColor(this.bgColor)
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }
  }

  aboutToAppear() {
    Log.info(TAG, 'aboutToAppear this.selectArray length = ' + this.selectArray.length)

  }
}

@Component
struct MediaSizeSelectionComponent {
  @Consume('CurrentMediaSize') currentMediaSize: SelectionModel;
  @Consume('MediaSizePopup') customPopup: boolean
  @State bgColor: Resource = $r('app.color.effect_color_white');
  private selection?: SelectionModel;

  build() {
    Row() {
      Text(this.selection!.res)
        .textAlign(TextAlign.Start)
        .fontSize($r('app.float.font_size_body2'))
        .margin({ left: $r('app.float.select_text_margin_left'), right: $r('app.float.select_text_margin_right') })
    }
    .selectItemStyle()
    .onClick(() => {
      this.currentMediaSize = this.selection!
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.checkSelectedColor()
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor = $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.checkSelectedColor()
      }
    })
  }

  aboutToAppear() {
    this.checkSelectedColor()
  }

  checkSelectedColor() {
    if (this.selection!.name === this.currentMediaSize.name) {
      this.bgColor = $r('app.color.selected_color')
    } else {
      this.bgColor = $r('app.color.effect_color_white')
    }
  }
}

@Component
export struct DirectionSelection {
  @Consume('DirectionSelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentDirection') currentDirection: SelectionModel;
  @Provide('DirectionPopup') customPopup: boolean = false
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            DirectionSelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => select.name)
      }
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_direction'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_direction')
      Row() {
        Text(this.currentDirection.res).fontSize($r('app.float.font_size_body2')).textAlign(TextAlign.Start)
          .width($r('app.float.select_text_width'))
          .margin({ left: $r('app.float.select_text_margin_left') })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_Direction')
      .selectStyle()
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .backgroundColor(this.bgColor)
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }
  }

  aboutToAppear() {
  }
}

@Component
struct DirectionSelectionComponent {
  @Consume('CurrentDirection') currentDirection: SelectionModel;
  @Consume('DirectionPopup') customPopup: boolean
  @State bgColor: Resource = $r('app.color.effect_color_white');
  private selection?: SelectionModel

  build() {
    Row() {
      Text(this.selection!.res)
        .textAlign(TextAlign.Start)
        .fontSize($r('app.float.font_size_body2'))
        .margin({ left: $r('app.float.select_text_margin_left'), right: $r('app.float.select_text_margin_right') })
    }
    .backgroundColor(this.selection!.name === this.currentDirection.name ? $r('app.color.selected_color') : Color.White)
    .selectItemStyle()
    .onClick(() => {
      this.currentDirection = this.selection!
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.checkSelectedColor()
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor = $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.checkSelectedColor()
      }
    })
  }

  aboutToAppear() {
    this.checkSelectedColor()
  }

  checkSelectedColor() {
    if (this.selection!.name === this.currentDirection.name) {
      this.bgColor = $r('app.color.selected_color')
    } else {
      this.bgColor = $r('app.color.effect_color_white')
    }
  }
}

@Component
export struct MediaTypeSelection {
  @Consume('MediaTypeSelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentMediaType') currentMediaType: SelectionModel;
  @Provide('MediaTypePopup') customPopup: boolean = false
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            MediaTypeSelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => select.name)
      }
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_media_type'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_mediaType')
      Row() {
        Text(this.currentMediaType.res).fontSize($r('app.float.font_size_body2')).textAlign(TextAlign.Start)
          .width($r('app.float.select_text_width'))
          .margin({ left: $r('app.float.select_text_margin_left') })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_MediaType')
      .selectStyle()
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .backgroundColor(this.bgColor)
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }
  }

  aboutToAppear() {
  }
}

@Component
struct MediaTypeSelectionComponent {
  @Consume('CurrentMediaType') currentMediaType: SelectionModel;
  @Consume('MediaTypePopup') customPopup: boolean
  @State bgColor: Resource = $r('app.color.effect_color_white')
  private selection?: SelectionModel;

  build() {
    Row() {
      Text(this.selection!.res)
        .textAlign(TextAlign.Start)
        .fontSize($r('app.float.font_size_body2'))
        .margin({ left: $r('app.float.select_text_margin_left'), right: $r('app.float.select_text_margin_right') })
    }
    .backgroundColor(this.selection!.name === this.currentMediaType.name ? $r('app.color.selected_color') : Color.White)
    .selectItemStyle()
    .onClick(() => {
      this.currentMediaType = this.selection!
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.checkSelectedColor()
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor = $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.checkSelectedColor()
      }
    })
  }

  aboutToAppear() {
    this.checkSelectedColor()
  }

  checkSelectedColor() {
    if (this.selection!.name === this.currentMediaType.name) {
      this.bgColor = $r('app.color.selected_color')
    } else {
      this.bgColor = $r('app.color.effect_color_white')
    }
  }
}

@Component
export struct QualitySelection {
  @Consume('QualitySelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentQuality') currentQuality: SelectionModel;
  @Provide('QualityPopup') customPopup: boolean = false
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            QualitySelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => select.name)
      }
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_print_quality'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_printQuality')
      Row() {
        Text(this.currentQuality.res).fontSize($r('app.float.font_size_body2')).textAlign(TextAlign.Start)
          .width($r('app.float.select_text_width'))
          .margin({ left: $r('app.float.select_text_margin_left') })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_Quality')
      .selectStyle()
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .backgroundColor(this.bgColor)
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }
  }

  aboutToAppear() {
  }
}

@Component
struct QualitySelectionComponent {
  @Consume('CurrentQuality') currentQuality: SelectionModel;
  @Consume('QualityPopup') customPopup: boolean
  @State bgColor: Resource = $r('app.color.effect_color_white');
  private selection?: SelectionModel;

  build() {
    Row() {
      Text(this.selection!.res)
        .textAlign(TextAlign.Start)
        .fontSize($r('app.float.font_size_body2'))
        .margin({ left: $r('app.float.select_text_margin_left'), right: $r('app.float.select_text_margin_right') })
    }
    .backgroundColor(this.selection!.name === this.currentQuality.name ? $r('app.color.selected_color') : Color.White)
    .selectItemStyle()
    .onClick(() => {
      this.currentQuality = this.selection!
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.checkSelectedColor()
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor = $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.checkSelectedColor()
      }
    })
  }

  aboutToAppear() {
    this.checkSelectedColor()
  }

  checkSelectedColor() {
    if (this.selection!.name === this.currentQuality.name) {
      this.bgColor = $r('app.color.selected_color')
    } else {
      this.bgColor = $r('app.color.effect_color_white')
    }
  }
}

@Component
export struct DuplexSelection {
  @Consume('DuplexSelectArray') selectArray: Array<SelectionModel>;
  @Consume('CurrentDuplex') currentDuplex: SelectionModel;
  @Provide('DuplexPopup') customPopup: boolean = false
  @State bgColor: Resource = $r('app.color.effect_color_white');

  @Builder popupBuilder() {
    if (this.customPopup){
      List() {
        ForEach(this.selectArray, (select: SelectionModel) => {
          ListItem() {
            DuplexSelectionComponent({ selection: select })
          }.key(`Selection_ListItem_${select.name}`)
        }, (select: SelectionModel) => select.name)
      }
      .width($r('app.float.select_comp_width'))
      .padding($r('app.float.select_comp_padding'))
    }
  }

  build() {
    Row() {
      Text($r('app.string.index_duplex_mode'))
        .fontSize($r('app.float.font_size_body2'))
        .width($r('app.float.text_label_width'))
        .textAlign(TextAlign.End)
        .key('Index_Text_printDuplex')
      Row() {
        Text(this.getText()).fontSize($r('app.float.font_size_body2')).textAlign(TextAlign.Start)
          .width($r('app.float.select_text_width'))
          .margin({ left: $r('app.float.select_text_margin_left') })
        Image($r('app.media.ic_select_button'))
          .height($r('app.float.select_image_button_size'))
          .width($r('app.float.select_image_button_size'))
          .margin({
            left: $r('app.float.select_image_button_margin_left'),
            right: $r('app.float.select_image_button_margin_right')
          })
      }
      .key('Selection_Duplex')
      .selectStyle()
      .onClick(() => {
        this.customPopup = !this.customPopup
      })
      .bindPopup(this.customPopup, {
        builder: this.popupBuilder,
        placement: Placement.Bottom,
        popupColor: Color.White,
        enableArrow: false,
        onStateChange: (e) => {
          if (!e.isVisible) {
            this.customPopup = false
          }
        }
      })
      .backgroundColor(this.bgColor)
      .onHover((isHover: boolean) => {
        if (isHover) {
          this.bgColor = $r('app.color.effect_color_hover')
        } else {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
      .onTouch((event: TouchEvent) => {
        if (event.type === TouchType.Down) {
          this.bgColor = $r('app.color.effect_color_press')
        }
        if (event.type === TouchType.Up) {
          this.bgColor = $r('app.color.effect_color_white')
        }
      })
    }
  }

  getText(){
    if(SelectionModel.getSelectionValue<number>(this.currentDuplex.name) === Duplex.SINGLE){
      return $r('app.string.DuplexMode_SINGLE')
    } else {
      return this.currentDuplex.res
    }
  }

  aboutToAppear() {
  }
}

@Component
struct DuplexSelectionComponent {
  @Consume('CurrentDuplex') currentDuplex: SelectionModel;
  @Consume('DuplexPopup') customPopup: boolean;
  @Consume('NeedDuplex') needDuplex: boolean;
  @State bgColor: Resource = $r('app.color.effect_color_white');
  @State isSingle: boolean = true;
  private selection?: SelectionModel;

  build() {
    Row() {
      Image(this.getImage()).width(48).height(48).margin({right:16}).objectFit(ImageFit.Contain)
      Column(){
        Text(SelectionModel.getSelectionValue<number>(this.selection!.name)! === Duplex.SINGLE?$r('app.string.DuplexMode_SINGLE'):$r('app.string.DuplexMode_DOUBLE'))
          .textAlign(TextAlign.Start)
          .fontSize($r('app.float.font_size_body1'))
          .fontColor('#E5000000')
        Text(this.selection!.res)
          .textAlign(TextAlign.Start)
          .fontSize($r('app.float.font_size_body2'))
          .fontColor('#99000000')
      }.alignItems(HorizontalAlign.Start)
    }
    .backgroundColor(this.selection!.name === this.currentDuplex.name ? $r('app.color.selected_color') : Color.White)
    .width($r('app.float.select_item_width'))
    .height($r('app.float.duplex_select_item_height'))
    .justifyContent(FlexAlign.Start)
    .alignItems(VerticalAlign.Center)
    .margin({ top: $r('app.float.select_item_margin_top'), bottom: $r('app.float.select_item_margin_bottom')})
    .padding({left:16,right:16})
    .borderRadius($r('app.float.radius_m'))
    .enabled(this.isSingle||this.needDuplex)
    .opacity(this.isSingle||this.needDuplex?1:0.4)
    .onClick(() => {
      this.currentDuplex = this.selection!
      this.customPopup = false
    })
    .backgroundColor(this.bgColor)
    .onHover((isHover: boolean) => {
      if (isHover) {
        this.bgColor = $r('app.color.effect_color_hover')
      } else {
        this.checkSelectedColor()
      }
    })
    .onTouch((event: TouchEvent) => {
      if (event.type === TouchType.Down) {
        this.bgColor = $r('app.color.effect_color_press')
      }
      if (event.type === TouchType.Up) {
        this.checkSelectedColor()
      }
    })
  }

  aboutToAppear() {
    Log.info(TAG,'DuplexSelectionComponent: ',JSON.stringify(this.currentDuplex))
    this.isSingle = (SelectionModel.getSelectionValue<number>(this.selection!.name) === Duplex.SINGLE);
    this.checkSelectedColor()
  }

  checkSelectedColor() {
    if (this.selection!.name === this.currentDuplex.name) {
      this.bgColor = $r('app.color.selected_color')
    } else {
      this.bgColor = $r('app.color.effect_color_white')
    }
  }

  getImage(){
    Log.info(TAG,'getImage: ',this.selection!.name)
    let res = $r('app.media.ic_single');
    if (SelectionModel.getSelectionValue<number>(this.selection!.name) === Duplex.LONG) {
      Log.info(TAG,'getImage: app.media.ic_long',this.selection!.name)
      res = $r('app.media.ic_long')
    } else if(SelectionModel.getSelectionValue<number>(this.selection!.name) === Duplex.SHORT) {
      Log.info(TAG,'getImage: app.media.ic_short',this.selection!.name)
      res = $r('app.media.ic_short')
    }
    return res
  }
}