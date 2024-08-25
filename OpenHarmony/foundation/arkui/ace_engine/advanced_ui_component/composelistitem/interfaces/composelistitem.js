/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

if (!("finalizeConstruction" in ViewPU.prototype)) {
  Reflect.set(ViewPU.prototype, "finalizeConstruction", () => { });
}
export var IconType;
(function (h11) {
  h11[h11["BADGE"] = 1] = "BADGE";
  h11[h11["NORMAL_ICON"] = 2] = "NORMAL_ICON";
  h11[h11["SYSTEM_ICON"] = 3] = "SYSTEM_ICON";
  h11[h11["HEAD_SCULPTURE"] = 4] = "HEAD_SCULPTURE";
  h11[h11["APP_ICON"] = 5] = "APP_ICON";
  h11[h11["PREVIEW"] = 6] = "PREVIEW";
  h11[h11["LONGITUDINAL"] = 7] = "LONGITUDINAL";
  h11[h11["VERTICAL"] = 8] = "VERTICAL";
})(IconType || (IconType = {}));
var ItemHeight;
(function (g11) {
  g11[g11["FIRST_HEIGHT"] = 48] = "FIRST_HEIGHT";
  g11[g11["SECOND_HEIGHT"] = 56] = "SECOND_HEIGHT";
  g11[g11["THIRD_HEIGHT"] = 64] = "THIRD_HEIGHT";
  g11[g11["FOURTH_HEIGHT"] = 72] = "FOURTH_HEIGHT";
  g11[g11["FIFTH_HEIGHT"] = 96] = "FIFTH_HEIGHT";
})(ItemHeight || (ItemHeight = {}));
const TEXT_MAX_LINE = 1;
const ITEM_BORDER_SHOWN = 2;
const TEXT_COLUMN_SPACE = 4;
const TEXT_SAFE_MARGIN = 8;
const LISTITEM_PADDING = 6;
const SWITCH_PADDING = 4;
const STACK_PADDING = 4;
const BADGE_SIZE = 8;
const SMALL_ICON_SIZE = 16;
const SYSTEM_ICON_SIZE = 24;
const TEXT_ARROW_HEIGHT = 32;
const SAFE_LIST_PADDING = 32;
const HEADSCULPTURE_SIZE = 40;
const BUTTON_SIZE = 28;
const APP_ICON_SIZE = 64;
const PREVIEW_SIZE = 96;
const LONGITUDINAL_SIZE = 96;
const VERTICAL_SIZE = 96;
const NORMAL_ITEM_ROW_SPACE = 16;
const SPECIAL_ITEM_ROW_SPACE = 0;
const SPECIAL_ICON_SIZE = 0;
const DEFAULT_ROW_SPACE = 0;
const SPECICAL_ROW_SPACE = 4;
const OPERATEITEM_ICONLIKE_SIZE = 24;
const OPERATEITEM_ARROW_WIDTH = 12;
const OPERATEITEM_ICON_CLICKABLE_SIZE = 40;
const OPERATEITEM_IMAGE_SIZE = 48;
const RIGHT_CONTENT_NULL_LEFTWIDTH = '100%';
const RIGHT_CONTENT_NULL_RIGHTWIDTH = '0vp';
const LEFT_PART_WIDTH = 'calc(66% - 16vp)';
const RIGHT_PART_WIDTH = '34%';
const LEFT_ONLY_ARROW_WIDTH = 'calc(100% - 40vp)';
const RIGHT_ONLY_ARROW_WIDTH = '24vp';
const ICON_SIZE_MAP = new Map([
  [IconType.BADGE, BADGE_SIZE],
  [IconType.NORMAL_ICON, SMALL_ICON_SIZE],
  [IconType.SYSTEM_ICON, SYSTEM_ICON_SIZE],
  [IconType.HEAD_SCULPTURE, HEADSCULPTURE_SIZE],
  [IconType.APP_ICON, APP_ICON_SIZE],
  [IconType.PREVIEW, PREVIEW_SIZE],
  [IconType.LONGITUDINAL, LONGITUDINAL_SIZE],
  [IconType.VERTICAL, VERTICAL_SIZE]
]);
class ContentItemStruct extends ViewPU {
  constructor(a11, b11, c11, d11 = -1, e11 = undefined, f11) {
    super(a11, c11, d11, f11);
    if (typeof e11 === "function") {
      this.paramsGenerator_ = e11;
    }
    this.__iconStyle = new SynchedPropertySimpleOneWayPU(b11.iconStyle, this, "iconStyle");
    this.__icon = new SynchedPropertyObjectOneWayPU(b11.icon, this, "icon");
    this.__primaryText = new SynchedPropertyObjectOneWayPU(b11.primaryText, this, "primaryText");
    this.__secondaryText = new SynchedPropertyObjectOneWayPU(b11.secondaryText, this, "secondaryText");
    this.__description = new SynchedPropertyObjectOneWayPU(b11.description, this, "description");
    this.__itemRowSpace = new ObservedPropertySimplePU(NORMAL_ITEM_ROW_SPACE, this, "itemRowSpace");
    this.__leftWidth = new SynchedPropertySimpleOneWayPU(b11.leftWidth, this, "leftWidth");
    this.__primaryTextColor = new ObservedPropertyObjectPU({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_primary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" }, this, "primaryTextColor");
    this.__secondaryTextColor = new ObservedPropertyObjectPU({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" }, this, "secondaryTextColor");
    this.__descriptionColor = new ObservedPropertyObjectPU({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" }, this, "descriptionColor");
    this.setInitiallyProvidedValue(b11);
    this.declareWatch("iconStyle", this.onPropChange);
    this.declareWatch("icon", this.onPropChange);
    this.declareWatch("primaryText", this.onPropChange);
    this.declareWatch("secondaryText", this.onPropChange);
    this.declareWatch("description", this.onPropChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(z10) {
    if (z10.iconStyle === undefined) {
      this.__iconStyle.set(null);
    }
    if (z10.icon === undefined) {
      this.__icon.set(null);
    }
    if (z10.primaryText === undefined) {
      this.__primaryText.set(null);
    }
    if (z10.secondaryText === undefined) {
      this.__secondaryText.set(null);
    }
    if (z10.description === undefined) {
      this.__description.set(null);
    }
    if (z10.itemRowSpace !== undefined) {
      this.itemRowSpace = z10.itemRowSpace;
    }
    if (z10.leftWidth === undefined) {
      this.__leftWidth.set(LEFT_PART_WIDTH);
    }
    if (z10.primaryTextColor !== undefined) {
      this.primaryTextColor = z10.primaryTextColor;
    }
    if (z10.secondaryTextColor !== undefined) {
      this.secondaryTextColor = z10.secondaryTextColor;
    }
    if (z10.descriptionColor !== undefined) {
      this.descriptionColor = z10.descriptionColor;
    }
  }
  updateStateVars(y10) {
    this.__iconStyle.reset(y10.iconStyle);
    this.__icon.reset(y10.icon);
    this.__primaryText.reset(y10.primaryText);
    this.__secondaryText.reset(y10.secondaryText);
    this.__description.reset(y10.description);
    this.__leftWidth.reset(y10.leftWidth);
  }
  purgeVariableDependenciesOnElmtId(x10) {
    this.__iconStyle.purgeDependencyOnElmtId(x10);
    this.__icon.purgeDependencyOnElmtId(x10);
    this.__primaryText.purgeDependencyOnElmtId(x10);
    this.__secondaryText.purgeDependencyOnElmtId(x10);
    this.__description.purgeDependencyOnElmtId(x10);
    this.__itemRowSpace.purgeDependencyOnElmtId(x10);
    this.__leftWidth.purgeDependencyOnElmtId(x10);
    this.__primaryTextColor.purgeDependencyOnElmtId(x10);
    this.__secondaryTextColor.purgeDependencyOnElmtId(x10);
    this.__descriptionColor.purgeDependencyOnElmtId(x10);
  }
  aboutToBeDeleted() {
    this.__iconStyle.aboutToBeDeleted();
    this.__icon.aboutToBeDeleted();
    this.__primaryText.aboutToBeDeleted();
    this.__secondaryText.aboutToBeDeleted();
    this.__description.aboutToBeDeleted();
    this.__itemRowSpace.aboutToBeDeleted();
    this.__leftWidth.aboutToBeDeleted();
    this.__primaryTextColor.aboutToBeDeleted();
    this.__secondaryTextColor.aboutToBeDeleted();
    this.__descriptionColor.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get iconStyle() {
    return this.__iconStyle.get();
  }
  set iconStyle(w10) {
    this.__iconStyle.set(w10);
  }
  get icon() {
    return this.__icon.get();
  }
  set icon(v10) {
    this.__icon.set(v10);
  }
  get primaryText() {
    return this.__primaryText.get();
  }
  set primaryText(u10) {
    this.__primaryText.set(u10);
  }
  get secondaryText() {
    return this.__secondaryText.get();
  }
  set secondaryText(t10) {
    this.__secondaryText.set(t10);
  }
  get description() {
    return this.__description.get();
  }
  set description(s10) {
    this.__description.set(s10);
  }
  get itemRowSpace() {
    return this.__itemRowSpace.get();
  }
  set itemRowSpace(r10) {
    this.__itemRowSpace.set(r10);
  }
  get leftWidth() {
    return this.__leftWidth.get();
  }
  set leftWidth(q10) {
    this.__leftWidth.set(q10);
  }
  get primaryTextColor() {
    return this.__primaryTextColor.get();
  }
  set primaryTextColor(p10) {
    this.__primaryTextColor.set(p10);
  }
  get secondaryTextColor() {
    return this.__secondaryTextColor.get();
  }
  set secondaryTextColor(o10) {
    this.__secondaryTextColor.set(o10);
  }
  get descriptionColor() {
    return this.__descriptionColor.get();
  }
  set descriptionColor(n10) {
    this.__descriptionColor.set(n10);
  }
  onWillApplyTheme(m10) {
    this.primaryTextColor = m10.colors.fontPrimary;
    this.secondaryTextColor = m10.colors.fontSecondary;
    this.descriptionColor = m10.colors.fontTertiary;
  }
  onPropChange() {
    if (this.icon == null && this.iconStyle == null) {
      this.itemRowSpace = SPECIAL_ITEM_ROW_SPACE;
    }
    else {
      this.itemRowSpace = NORMAL_ITEM_ROW_SPACE;
    }
  }
  aboutToAppear() {
    this.onPropChange();
  }
  createIcon(v9 = null) {
    this.observeComponentCreation2((x9, y9) => {
      If.create();
      if (this.icon != null && this.iconStyle != null) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.observeComponentCreation2((c10, d10) => {
            If.create();
            if (this.iconStyle <= IconType.PREVIEW) {
              this.ifElseBranchUpdateFunction(0, () => {
                this.observeComponentCreation2((k10, l10) => {
                  Image.create(this.icon);
                  Image.objectFit(ImageFit.Contain);
                  Image.width(ICON_SIZE_MAP.get(this.iconStyle));
                  Image.height(ICON_SIZE_MAP.get(this.iconStyle));
                  Image.borderRadius({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_default_m'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
                  Image.focusable(true);
                  Image.draggable(false);
                  Image.fillColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
                }, Image);
              });
            }
            else {
              this.ifElseBranchUpdateFunction(1, () => {
                this.observeComponentCreation2((g10, h10) => {
                  Image.create(this.icon);
                  Image.objectFit(ImageFit.Contain);
                  Image.constraintSize({
                    minWidth: SPECIAL_ICON_SIZE,
                    maxWidth: ICON_SIZE_MAP.get(this.iconStyle),
                    minHeight: SPECIAL_ICON_SIZE,
                    maxHeight: ICON_SIZE_MAP.get(this.iconStyle)
                  });
                  Image.borderRadius({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_default_m'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
                  Image.focusable(true);
                  Image.draggable(false);
                  Image.fillColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
                }, Image);
              });
            }
          }, If);
          If.pop();
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
  }
  createText(y8 = null) {
    this.observeComponentCreation2((t9, u9) => {
      Column.create({ space: TEXT_COLUMN_SPACE });
      Column.flexShrink(1);
      Column.margin({
        top: TEXT_SAFE_MARGIN,
        bottom: TEXT_SAFE_MARGIN
      });
      Column.alignItems(HorizontalAlign.Start);
    }, Column);
    this.observeComponentCreation2((r9, s9) => {
      Text.create(this.primaryText);
      Text.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_body1'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Text.fontColor(ObservedObject.GetRawObject(this.primaryTextColor));
      Text.maxLines(TEXT_MAX_LINE);
      Text.textOverflow({ overflow: TextOverflow.Ellipsis });
      Text.fontWeight(FontWeight.Medium);
      Text.focusable(true);
      Text.draggable(false);
    }, Text);
    Text.pop();
    this.observeComponentCreation2((k9, l9) => {
      If.create();
      if (this.secondaryText != null) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.observeComponentCreation2((p9, q9) => {
            Text.create(this.secondaryText);
            Text.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_body2'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
            Text.fontColor(ObservedObject.GetRawObject(this.secondaryTextColor));
            Text.maxLines(TEXT_MAX_LINE);
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.focusable(true);
            Text.draggable(false);
          }, Text);
          Text.pop();
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
    this.observeComponentCreation2((d9, e9) => {
      If.create();
      if (this.description != null) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.observeComponentCreation2((i9, j9) => {
            Text.create(this.description);
            Text.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_body2'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
            Text.fontColor(ObservedObject.GetRawObject(this.descriptionColor));
            Text.maxLines(TEXT_MAX_LINE);
            Text.textOverflow({ overflow: TextOverflow.Ellipsis });
            Text.focusable(true);
            Text.draggable(false);
          }, Text);
          Text.pop();
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
    Column.pop();
  }
  initialRender() {
    this.observeComponentCreation2((w8, x8) => {
      Row.create({ space: this.itemRowSpace });
      Row.margin({ right: 16 });
      Row.padding({ left: LISTITEM_PADDING });
      Row.width(this.leftWidth);
      Row.flexShrink(1);
    }, Row);
    this.createIcon.bind(this)(this);
    this.createText.bind(this)(this);
    Row.pop();
  }
  rerender() {
    this.updateDirtyElements();
  }
}
class CreateIconParam {
}
class OperateItemStruct extends ViewPU {
  constructor(p8, q8, r8, s8 = -1, t8 = undefined, u8) {
    super(p8, r8, s8, u8);
    if (typeof t8 === "function") {
      this.paramsGenerator_ = t8;
    }
    this.__arrow = new SynchedPropertyObjectOneWayPU(q8.arrow, this, "arrow");
    this.__icon = new SynchedPropertyObjectOneWayPU(q8.icon, this, "icon");
    this.__subIcon = new SynchedPropertyObjectOneWayPU(q8.subIcon, this, "subIcon");
    this.__button = new SynchedPropertyObjectOneWayPU(q8.button, this, "button");
    this.__switch = new SynchedPropertyObjectOneWayPU(q8.switch, this, "switch");
    this.__checkBox = new SynchedPropertyObjectOneWayPU(q8.checkBox, this, "checkBox");
    this.__radio = new SynchedPropertyObjectOneWayPU(q8.radio, this, "radio");
    this.__image = new SynchedPropertyObjectOneWayPU(q8.image, this, "image");
    this.__text = new SynchedPropertyObjectOneWayPU(q8.text, this, "text");
    this.__switchState = new ObservedPropertySimplePU(false, this, "switchState");
    this.__radioState = new ObservedPropertySimplePU(false, this, "radioState");
    this.__checkBoxState = new ObservedPropertySimplePU(false, this, "checkBoxState");
    this.__rightWidth = new SynchedPropertySimpleOneWayPU(q8.rightWidth, this, "rightWidth");
    this.__secondaryTextColor = new ObservedPropertyObjectPU({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" }, this, "secondaryTextColor");
    this.__hoveringColor = new ObservedPropertyObjectPU('#0d000000', this, "hoveringColor");
    this.__activedColor = new ObservedPropertyObjectPU('#1a0a59f7', this, "activedColor");
    this.__parentCanFocus = new SynchedPropertySimpleTwoWayPU(q8.parentCanFocus, this, "parentCanFocus");
    this.__parentCanTouch = new SynchedPropertySimpleTwoWayPU(q8.parentCanTouch, this, "parentCanTouch");
    this.__parentIsHover = new SynchedPropertySimpleTwoWayPU(q8.parentIsHover, this, "parentIsHover");
    this.__parentCanHover = new SynchedPropertySimpleTwoWayPU(q8.parentCanHover, this, "parentCanHover");
    this.__parentIsActive = new SynchedPropertySimpleTwoWayPU(q8.parentIsActive, this, "parentIsActive");
    this.__parentFrontColor = new SynchedPropertyObjectTwoWayPU(q8.parentFrontColor, this, "parentFrontColor");
    this.__rowSpace = new ObservedPropertySimplePU(DEFAULT_ROW_SPACE, this, "rowSpace");
    this.setInitiallyProvidedValue(q8);
    this.declareWatch("arrow", this.onPropChange);
    this.declareWatch("icon", this.onPropChange);
    this.declareWatch("subIcon", this.onPropChange);
    this.declareWatch("button", this.onPropChange);
    this.declareWatch("switch", this.onPropChange);
    this.declareWatch("checkBox", this.onPropChange);
    this.declareWatch("radio", this.onPropChange);
    this.declareWatch("image", this.onPropChange);
    this.declareWatch("text", this.onPropChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(o8) {
    if (o8.arrow === undefined) {
      this.__arrow.set(null);
    }
    if (o8.icon === undefined) {
      this.__icon.set(null);
    }
    if (o8.subIcon === undefined) {
      this.__subIcon.set(null);
    }
    if (o8.button === undefined) {
      this.__button.set(null);
    }
    if (o8.switch === undefined) {
      this.__switch.set(null);
    }
    if (o8.checkBox === undefined) {
      this.__checkBox.set(null);
    }
    if (o8.radio === undefined) {
      this.__radio.set(null);
    }
    if (o8.image === undefined) {
      this.__image.set(null);
    }
    if (o8.text === undefined) {
      this.__text.set(null);
    }
    if (o8.switchState !== undefined) {
      this.switchState = o8.switchState;
    }
    if (o8.radioState !== undefined) {
      this.radioState = o8.radioState;
    }
    if (o8.checkBoxState !== undefined) {
      this.checkBoxState = o8.checkBoxState;
    }
    if (o8.rightWidth === undefined) {
      this.__rightWidth.set(RIGHT_PART_WIDTH);
    }
    if (o8.secondaryTextColor !== undefined) {
      this.secondaryTextColor = o8.secondaryTextColor;
    }
    if (o8.hoveringColor !== undefined) {
      this.hoveringColor = o8.hoveringColor;
    }
    if (o8.activedColor !== undefined) {
      this.activedColor = o8.activedColor;
    }
    if (o8.rowSpace !== undefined) {
      this.rowSpace = o8.rowSpace;
    }
  }
  updateStateVars(n8) {
    this.__arrow.reset(n8.arrow);
    this.__icon.reset(n8.icon);
    this.__subIcon.reset(n8.subIcon);
    this.__button.reset(n8.button);
    this.__switch.reset(n8.switch);
    this.__checkBox.reset(n8.checkBox);
    this.__radio.reset(n8.radio);
    this.__image.reset(n8.image);
    this.__text.reset(n8.text);
    this.__rightWidth.reset(n8.rightWidth);
  }
  purgeVariableDependenciesOnElmtId(m8) {
    this.__arrow.purgeDependencyOnElmtId(m8);
    this.__icon.purgeDependencyOnElmtId(m8);
    this.__subIcon.purgeDependencyOnElmtId(m8);
    this.__button.purgeDependencyOnElmtId(m8);
    this.__switch.purgeDependencyOnElmtId(m8);
    this.__checkBox.purgeDependencyOnElmtId(m8);
    this.__radio.purgeDependencyOnElmtId(m8);
    this.__image.purgeDependencyOnElmtId(m8);
    this.__text.purgeDependencyOnElmtId(m8);
    this.__switchState.purgeDependencyOnElmtId(m8);
    this.__radioState.purgeDependencyOnElmtId(m8);
    this.__checkBoxState.purgeDependencyOnElmtId(m8);
    this.__rightWidth.purgeDependencyOnElmtId(m8);
    this.__secondaryTextColor.purgeDependencyOnElmtId(m8);
    this.__hoveringColor.purgeDependencyOnElmtId(m8);
    this.__activedColor.purgeDependencyOnElmtId(m8);
    this.__parentCanFocus.purgeDependencyOnElmtId(m8);
    this.__parentCanTouch.purgeDependencyOnElmtId(m8);
    this.__parentIsHover.purgeDependencyOnElmtId(m8);
    this.__parentCanHover.purgeDependencyOnElmtId(m8);
    this.__parentIsActive.purgeDependencyOnElmtId(m8);
    this.__parentFrontColor.purgeDependencyOnElmtId(m8);
    this.__rowSpace.purgeDependencyOnElmtId(m8);
  }
  aboutToBeDeleted() {
    this.__arrow.aboutToBeDeleted();
    this.__icon.aboutToBeDeleted();
    this.__subIcon.aboutToBeDeleted();
    this.__button.aboutToBeDeleted();
    this.__switch.aboutToBeDeleted();
    this.__checkBox.aboutToBeDeleted();
    this.__radio.aboutToBeDeleted();
    this.__image.aboutToBeDeleted();
    this.__text.aboutToBeDeleted();
    this.__switchState.aboutToBeDeleted();
    this.__radioState.aboutToBeDeleted();
    this.__checkBoxState.aboutToBeDeleted();
    this.__rightWidth.aboutToBeDeleted();
    this.__secondaryTextColor.aboutToBeDeleted();
    this.__hoveringColor.aboutToBeDeleted();
    this.__activedColor.aboutToBeDeleted();
    this.__parentCanFocus.aboutToBeDeleted();
    this.__parentCanTouch.aboutToBeDeleted();
    this.__parentIsHover.aboutToBeDeleted();
    this.__parentCanHover.aboutToBeDeleted();
    this.__parentIsActive.aboutToBeDeleted();
    this.__parentFrontColor.aboutToBeDeleted();
    this.__rowSpace.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get arrow() {
    return this.__arrow.get();
  }
  set arrow(l8) {
    this.__arrow.set(l8);
  }
  get icon() {
    return this.__icon.get();
  }
  set icon(k8) {
    this.__icon.set(k8);
  }
  get subIcon() {
    return this.__subIcon.get();
  }
  set subIcon(j8) {
    this.__subIcon.set(j8);
  }
  get button() {
    return this.__button.get();
  }
  set button(i8) {
    this.__button.set(i8);
  }
  get switch() {
    return this.__switch.get();
  }
  set switch(h8) {
    this.__switch.set(h8);
  }
  get checkBox() {
    return this.__checkBox.get();
  }
  set checkBox(g8) {
    this.__checkBox.set(g8);
  }
  get radio() {
    return this.__radio.get();
  }
  set radio(f8) {
    this.__radio.set(f8);
  }
  get image() {
    return this.__image.get();
  }
  set image(e8) {
    this.__image.set(e8);
  }
  get text() {
    return this.__text.get();
  }
  set text(d8) {
    this.__text.set(d8);
  }
  get switchState() {
    return this.__switchState.get();
  }
  set switchState(c8) {
    this.__switchState.set(c8);
  }
  get radioState() {
    return this.__radioState.get();
  }
  set radioState(b8) {
    this.__radioState.set(b8);
  }
  get checkBoxState() {
    return this.__checkBoxState.get();
  }
  set checkBoxState(a8) {
    this.__checkBoxState.set(a8);
  }
  get rightWidth() {
    return this.__rightWidth.get();
  }
  set rightWidth(z7) {
    this.__rightWidth.set(z7);
  }
  get secondaryTextColor() {
    return this.__secondaryTextColor.get();
  }
  set secondaryTextColor(y7) {
    this.__secondaryTextColor.set(y7);
  }
  get hoveringColor() {
    return this.__hoveringColor.get();
  }
  set hoveringColor(x7) {
    this.__hoveringColor.set(x7);
  }
  get activedColor() {
    return this.__activedColor.get();
  }
  set activedColor(w7) {
    this.__activedColor.set(w7);
  }
  get parentCanFocus() {
    return this.__parentCanFocus.get();
  }
  set parentCanFocus(v7) {
    this.__parentCanFocus.set(v7);
  }
  get parentCanTouch() {
    return this.__parentCanTouch.get();
  }
  set parentCanTouch(u7) {
    this.__parentCanTouch.set(u7);
  }
  get parentIsHover() {
    return this.__parentIsHover.get();
  }
  set parentIsHover(t7) {
    this.__parentIsHover.set(t7);
  }
  get parentCanHover() {
    return this.__parentCanHover.get();
  }
  set parentCanHover(s7) {
    this.__parentCanHover.set(s7);
  }
  get parentIsActive() {
    return this.__parentIsActive.get();
  }
  set parentIsActive(r7) {
    this.__parentIsActive.set(r7);
  }
  get parentFrontColor() {
    return this.__parentFrontColor.get();
  }
  set parentFrontColor(q7) {
    this.__parentFrontColor.set(q7);
  }
  get rowSpace() {
    return this.__rowSpace.get();
  }
  set rowSpace(p7) {
    this.__rowSpace.set(p7);
  }
  onWillApplyTheme(o7) {
    this.secondaryTextColor = o7.colors.fontSecondary;
    this.hoveringColor = o7.colors.interactiveHover;
    this.activedColor = o7.colors.interactiveActive;
  }
  onPropChange() {
    if (this.switch != null) {
      this.switchState = this.switch.isCheck;
    }
    if (this.radio != null) {
      this.radioState = this.radio.isCheck;
    }
    if (this.checkBox != null) {
      this.checkBoxState = this.checkBox.isCheck;
    }
    if ((this.button == null && this.image == null && this.icon != null && this.text != null) ||
      (this.button == null && this.image == null && this.icon == null && this.arrow != null && this.text != null)) {
      this.rowSpace = SPECICAL_ROW_SPACE;
    }
    else {
      this.rowSpace = DEFAULT_ROW_SPACE;
    }
  }
  aboutToAppear() {
    this.onPropChange();
  }
  createButton(z6 = null) {
    this.observeComponentCreation2((h7, i7) => {
      Button.createWithChild();
      Button.margin({ right: LISTITEM_PADDING });
      Button.hitTestBehavior(HitTestMode.Block);
      Button.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_button3'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Button.fontColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_primary_activated_transparent'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Button.height(BUTTON_SIZE);
      Button.backgroundColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_button_normal'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Button.labelStyle({
        maxLines: TEXT_MAX_LINE
      });
      Button.onFocus(() => {
        this.parentCanFocus = false;
      });
      Button.onTouch((n7) => {
        if (n7.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (n7.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Button.onHover((m7) => {
        this.parentCanHover = false;
        if (m7 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!m7) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
    }, Button);
    this.observeComponentCreation2((f7, g7) => {
      Row.create();
      Row.padding({
        left: TEXT_SAFE_MARGIN,
        right: TEXT_SAFE_MARGIN
      });
    }, Row);
    this.observeComponentCreation2((d7, e7) => {
      Text.create(this.button?.text);
      Text.focusable(true);
    }, Text);
    Text.pop();
    Row.pop();
    Button.pop();
  }
  createIcon(m6, n6 = null) {
    this.observeComponentCreation2((s6, t6) => {
      Button.createWithChild({ type: ButtonType.Normal });
      Button.hitTestBehavior(HitTestMode.Block);
      Button.backgroundColor(Color.Transparent);
      Button.height(OPERATEITEM_ICON_CLICKABLE_SIZE);
      Button.width(OPERATEITEM_ICON_CLICKABLE_SIZE);
      Button.borderRadius({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_clicked'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Button.onFocus(() => {
        this.parentCanFocus = false;
      });
      Button.onTouch((y6) => {
        if (y6.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (y6.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Button.onHover((x6) => {
        this.parentCanHover = false;
        if (x6 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!x6) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
      Button.onClick((m6.icon?.action));
    }, Button);
    this.observeComponentCreation2((q6, r6) => {
      Image.create(m6.icon?.value);
      Image.height(OPERATEITEM_ICONLIKE_SIZE);
      Image.width(OPERATEITEM_ICONLIKE_SIZE);
      Image.focusable(true);
      Image.fillColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_primary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Image.draggable(false);
    }, Image);
    Button.pop();
  }
  createImage(i6 = null) {
    this.observeComponentCreation2((k6, l6) => {
      Image.create(this.image);
      Image.height(OPERATEITEM_IMAGE_SIZE);
      Image.width(OPERATEITEM_IMAGE_SIZE);
      Image.draggable(false);
      Image.margin({ right: LISTITEM_PADDING });
    }, Image);
  }
  createText(e6 = null) {
    this.observeComponentCreation2((g6, h6) => {
      Text.create(this.text);
      Text.margin({ right: LISTITEM_PADDING });
      Text.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_body2'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Text.fontColor(ObservedObject.GetRawObject(this.secondaryTextColor));
      Text.focusable(true);
      Text.draggable(false);
      Text.flexShrink(1);
    }, Text);
    Text.pop();
  }
  createArrow(s5 = null) {
    this.observeComponentCreation2((x5, y5) => {
      Button.createWithChild({ type: ButtonType.Normal });
      Button.margin({ right: LISTITEM_PADDING });
      Button.hitTestBehavior(HitTestMode.Block);
      Button.backgroundColor(Color.Transparent);
      Button.height(OPERATEITEM_ICONLIKE_SIZE);
      Button.width(OPERATEITEM_ARROW_WIDTH);
      Button.onFocus(() => {
        this.parentCanFocus = false;
      });
      Button.onTouch((d6) => {
        if (d6.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (d6.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Button.onHover((c6) => {
        this.parentCanHover = false;
        if (c6 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!c6) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
      Button.onClick(this.arrow?.action);
    }, Button);
    this.observeComponentCreation2((v5, w5) => {
      Image.create(this.arrow?.value);
      Image.height(OPERATEITEM_ICONLIKE_SIZE);
      Image.width(OPERATEITEM_ARROW_WIDTH);
      Image.focusable(true);
      Image.fillColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_fourth'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Image.draggable(false);
    }, Image);
    Button.pop();
  }
  createRadio(j5 = null) {
    this.observeComponentCreation2((l5, m5) => {
      Radio.create({ value: '', group: '' });
      Radio.margin({ right: LISTITEM_PADDING });
      Radio.checked(this.radioState);
      Radio.onChange(this.radio?.onChange);
      Radio.height(OPERATEITEM_ICONLIKE_SIZE);
      Radio.width(OPERATEITEM_ICONLIKE_SIZE);
      Radio.onFocus(() => {
        this.parentCanFocus = false;
      });
      Radio.hitTestBehavior(HitTestMode.Block);
      Radio.onTouch((r5) => {
        if (r5.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (r5.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Radio.onHover((q5) => {
        this.parentCanHover = false;
        if (q5 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!q5) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
    }, Radio);
  }
  createCheckBox(a5 = null) {
    this.observeComponentCreation2((c5, d5) => {
      Checkbox.create();
      Checkbox.margin({ right: LISTITEM_PADDING });
      Checkbox.select(this.checkBoxState);
      Checkbox.onChange(this.checkBox?.onChange);
      Checkbox.height(OPERATEITEM_ICONLIKE_SIZE);
      Checkbox.height(OPERATEITEM_ICONLIKE_SIZE);
      Checkbox.onFocus(() => {
        this.parentCanFocus = false;
      });
      Checkbox.hitTestBehavior(HitTestMode.Block);
      Checkbox.onTouch((i5) => {
        if (i5.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (i5.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Checkbox.onHover((h5) => {
        this.parentCanHover = false;
        if (h5 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!h5) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
    }, Checkbox);
    Checkbox.pop();
  }
  createSwitch(n4 = null) {
    this.observeComponentCreation2((t4, u4) => {
      Row.create();
      Row.margin({ right: SWITCH_PADDING });
      Row.height(OPERATEITEM_ICON_CLICKABLE_SIZE);
      Row.width(OPERATEITEM_ICON_CLICKABLE_SIZE);
      Row.justifyContent(FlexAlign.Center);
      Row.onFocus(() => {
        this.parentCanFocus = false;
      });
      Row.onTouch((z4) => {
        if (z4.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (z4.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Row.onHover((y4) => {
        this.parentCanHover = false;
        if (y4 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!y4) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
    }, Row);
    this.observeComponentCreation2((q4, r4) => {
      Toggle.create({ type: ToggleType.Switch, isOn: this.switchState });
      Toggle.onChange(this.switch?.onChange);
      Toggle.onClick(() => {
        this.switchState = !this.switchState;
      });
      Toggle.hitTestBehavior(HitTestMode.Block);
    }, Toggle);
    Toggle.pop();
    Row.pop();
  }
  createTextArrow(v3 = null) {
    this.observeComponentCreation2((g4, h4) => {
      Button.createWithChild({ type: ButtonType.Normal });
      Button.hitTestBehavior(HitTestMode.Block);
      Button.labelStyle({
        maxLines: TEXT_MAX_LINE
      });
      Button.backgroundColor(Color.Transparent);
      Button.height(TEXT_ARROW_HEIGHT);
      Button.borderRadius({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_clicked'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Button.onFocus(() => {
        this.parentCanFocus = false;
      });
      Button.onTouch((m4) => {
        if (m4.type == TouchType.Down) {
          this.parentCanTouch = false;
        }
        if (m4.type == TouchType.Up) {
          this.parentCanTouch = true;
        }
      });
      Button.onHover((l4) => {
        this.parentCanHover = false;
        if (l4 && this.parentFrontColor === this.hoveringColor) {
          this.parentFrontColor = this.parentIsActive ? this.activedColor : Color.Transparent.toString();
        }
        if (!l4) {
          this.parentCanHover = true;
          if (this.parentIsHover) {
            this.parentFrontColor = this.parentIsHover ? this.hoveringColor :
              (this.parentIsActive ? this.activedColor : Color.Transparent.toString());
          }
        }
      });
      Button.onClick(this.arrow?.action);
    }, Button);
    this.observeComponentCreation2((e4, f4) => {
      Row.create({ space: SPECICAL_ROW_SPACE });
      Row.padding({
        left: TEXT_SAFE_MARGIN,
        right: LISTITEM_PADDING
      });
    }, Row);
    this.observeComponentCreation2((c4, d4) => {
      Text.create(this.text);
      Text.fontSize({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_text_size_body2'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Text.fontColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_text_secondary'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Text.focusable(true);
      Text.draggable(false);
      Text.constraintSize({
        maxWidth: `calc(100% - ${OPERATEITEM_ARROW_WIDTH}vp)`
      });
    }, Text);
    Text.pop();
    this.observeComponentCreation2((a4, b4) => {
      Image.create(this.arrow?.value);
      Image.height(OPERATEITEM_ICONLIKE_SIZE);
      Image.width(OPERATEITEM_ARROW_WIDTH);
      Image.fillColor({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_fourth'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Image.focusable(true);
      Image.draggable(false);
    }, Image);
    Row.pop();
    Button.pop();
  }
  initialRender() {
    this.observeComponentCreation2((t3, u3) => {
      Row.create({
        space: this.rowSpace
      });
      Row.width(this.rightWidth);
      Row.flexShrink(1);
      Row.justifyContent(FlexAlign.End);
    }, Row);
    this.observeComponentCreation2((b3, c3) => {
      If.create();
      if (this.button != null) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.createButton.bind(this)(this);
        });
      }
      else if (this.image != null) {
        this.ifElseBranchUpdateFunction(1, () => {
          this.createImage.bind(this)(this);
        });
      }
      else if (this.icon != null && this.text != null) {
        this.ifElseBranchUpdateFunction(2, () => {
          this.createText.bind(this)(this);
          this.createIcon.bind(this)(makeBuilderParameterProxy("createIcon", { icon: () => (this["__icon"] ? this["__icon"] : this["icon"]) }), this);
        });
      }
      else if (this.arrow != null && this.text == null) {
        this.ifElseBranchUpdateFunction(3, () => {
          this.createArrow.bind(this)(this);
        });
      }
      else if (this.arrow != null && this.text != null) {
        this.ifElseBranchUpdateFunction(4, () => {
          this.createTextArrow.bind(this)(this);
        });
      }
      else if (this.text != null) {
        this.ifElseBranchUpdateFunction(5, () => {
          this.createText.bind(this)(this);
        });
      }
      else if (this.radio != null) {
        this.ifElseBranchUpdateFunction(6, () => {
          this.createRadio.bind(this)(this);
        });
      }
      else if (this.checkBox != null) {
        this.ifElseBranchUpdateFunction(7, () => {
          this.createCheckBox.bind(this)(this);
        });
      }
      else if (this.switch != null) {
        this.ifElseBranchUpdateFunction(8, () => {
          this.createSwitch.bind(this)(this);
        });
      }
      else if (this.icon != null) {
        this.ifElseBranchUpdateFunction(9, () => {
          this.createIcon.bind(this)(makeBuilderParameterProxy("createIcon", { icon: () => (this["__icon"] ? this["__icon"] : this["icon"]) }), this);
          this.observeComponentCreation2((g3, h3) => {
            If.create();
            if (this.subIcon != null) {
              this.ifElseBranchUpdateFunction(0, () => {
                this.createIcon.bind(this)(makeBuilderParameterProxy("createIcon", { icon: () => (this["__subIcon"] ? this["__subIcon"] : this["subIcon"]) }), this);
              });
            }
            else {
              this.ifElseBranchUpdateFunction(1, () => {
              });
            }
          }, If);
          If.pop();
        });
      }
      else {
        this.ifElseBranchUpdateFunction(10, () => {
        });
      }
    }, If);
    If.pop();
    Row.pop();
  }
  rerender() {
    this.updateDirtyElements();
  }
}
export class ComposeListItem extends ViewPU {
  constructor(t2, u2, v2, w2 = -1, x2 = undefined, y2) {
    super(t2, v2, w2, y2);
    if (typeof x2 === "function") {
      this.paramsGenerator_ = x2;
    }
    this.__contentItem = new SynchedPropertyObjectOneWayPU(u2.contentItem, this, "contentItem");
    this.__operateItem = new SynchedPropertyObjectOneWayPU(u2.operateItem, this, "operateItem");
    this.__frontColor = new ObservedPropertyObjectPU(Color.Transparent.toString(), this, "frontColor");
    this.__borderSize = new ObservedPropertySimplePU(0, this, "borderSize");
    this.__canFocus = new ObservedPropertySimplePU(false, this, "canFocus");
    this.__canTouch = new ObservedPropertySimplePU(true, this, "canTouch");
    this.__canHover = new ObservedPropertySimplePU(true, this, "canHover");
    this.__isHover = new ObservedPropertySimplePU(true, this, "isHover");
    this.__itemHeight = new ObservedPropertySimplePU(ItemHeight.FIRST_HEIGHT, this, "itemHeight");
    this.__isActive = new ObservedPropertySimplePU(false, this, "isActive");
    this.__hoveringColor = new ObservedPropertyObjectPU('#0d000000', this, "hoveringColor");
    this.__touchDownColor = new ObservedPropertyObjectPU('#1a000000', this, "touchDownColor");
    this.__activedColor = new ObservedPropertyObjectPU('#1a0a59f7', this, "activedColor");
    this.__focusOutlineColor = new ObservedPropertyObjectPU({ "id": -1, "type": 10001, params: ['sys.color.ohos_id_color_focused_outline'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" }, this, "focusOutlineColor");
    this.setInitiallyProvidedValue(u2);
    this.declareWatch("contentItem", this.onPropChange);
    this.declareWatch("operateItem", this.onPropChange);
    this.finalizeConstruction();
  }
  setInitiallyProvidedValue(s2) {
    if (s2.contentItem === undefined) {
      this.__contentItem.set(null);
    }
    if (s2.operateItem === undefined) {
      this.__operateItem.set(null);
    }
    if (s2.frontColor !== undefined) {
      this.frontColor = s2.frontColor;
    }
    if (s2.borderSize !== undefined) {
      this.borderSize = s2.borderSize;
    }
    if (s2.canFocus !== undefined) {
      this.canFocus = s2.canFocus;
    }
    if (s2.canTouch !== undefined) {
      this.canTouch = s2.canTouch;
    }
    if (s2.canHover !== undefined) {
      this.canHover = s2.canHover;
    }
    if (s2.isHover !== undefined) {
      this.isHover = s2.isHover;
    }
    if (s2.itemHeight !== undefined) {
      this.itemHeight = s2.itemHeight;
    }
    if (s2.isActive !== undefined) {
      this.isActive = s2.isActive;
    }
    if (s2.hoveringColor !== undefined) {
      this.hoveringColor = s2.hoveringColor;
    }
    if (s2.touchDownColor !== undefined) {
      this.touchDownColor = s2.touchDownColor;
    }
    if (s2.activedColor !== undefined) {
      this.activedColor = s2.activedColor;
    }
    if (s2.focusOutlineColor !== undefined) {
      this.focusOutlineColor = s2.focusOutlineColor;
    }
  }
  updateStateVars(r2) {
    this.__contentItem.reset(r2.contentItem);
    this.__operateItem.reset(r2.operateItem);
  }
  purgeVariableDependenciesOnElmtId(q2) {
    this.__contentItem.purgeDependencyOnElmtId(q2);
    this.__operateItem.purgeDependencyOnElmtId(q2);
    this.__frontColor.purgeDependencyOnElmtId(q2);
    this.__borderSize.purgeDependencyOnElmtId(q2);
    this.__canFocus.purgeDependencyOnElmtId(q2);
    this.__canTouch.purgeDependencyOnElmtId(q2);
    this.__canHover.purgeDependencyOnElmtId(q2);
    this.__isHover.purgeDependencyOnElmtId(q2);
    this.__itemHeight.purgeDependencyOnElmtId(q2);
    this.__isActive.purgeDependencyOnElmtId(q2);
    this.__hoveringColor.purgeDependencyOnElmtId(q2);
    this.__touchDownColor.purgeDependencyOnElmtId(q2);
    this.__activedColor.purgeDependencyOnElmtId(q2);
    this.__focusOutlineColor.purgeDependencyOnElmtId(q2);
  }
  aboutToBeDeleted() {
    this.__contentItem.aboutToBeDeleted();
    this.__operateItem.aboutToBeDeleted();
    this.__frontColor.aboutToBeDeleted();
    this.__borderSize.aboutToBeDeleted();
    this.__canFocus.aboutToBeDeleted();
    this.__canTouch.aboutToBeDeleted();
    this.__canHover.aboutToBeDeleted();
    this.__isHover.aboutToBeDeleted();
    this.__itemHeight.aboutToBeDeleted();
    this.__isActive.aboutToBeDeleted();
    this.__hoveringColor.aboutToBeDeleted();
    this.__touchDownColor.aboutToBeDeleted();
    this.__activedColor.aboutToBeDeleted();
    this.__focusOutlineColor.aboutToBeDeleted();
    SubscriberManager.Get().delete(this.id__());
    this.aboutToBeDeletedInternal();
  }
  get contentItem() {
    return this.__contentItem.get();
  }
  set contentItem(p2) {
    this.__contentItem.set(p2);
  }
  get operateItem() {
    return this.__operateItem.get();
  }
  set operateItem(o2) {
    this.__operateItem.set(o2);
  }
  get frontColor() {
    return this.__frontColor.get();
  }
  set frontColor(n2) {
    this.__frontColor.set(n2);
  }
  get borderSize() {
    return this.__borderSize.get();
  }
  set borderSize(m2) {
    this.__borderSize.set(m2);
  }
  get canFocus() {
    return this.__canFocus.get();
  }
  set canFocus(l2) {
    this.__canFocus.set(l2);
  }
  get canTouch() {
    return this.__canTouch.get();
  }
  set canTouch(k2) {
    this.__canTouch.set(k2);
  }
  get canHover() {
    return this.__canHover.get();
  }
  set canHover(j2) {
    this.__canHover.set(j2);
  }
  get isHover() {
    return this.__isHover.get();
  }
  set isHover(i2) {
    this.__isHover.set(i2);
  }
  get itemHeight() {
    return this.__itemHeight.get();
  }
  set itemHeight(h2) {
    this.__itemHeight.set(h2);
  }
  get isActive() {
    return this.__isActive.get();
  }
  set isActive(g2) {
    this.__isActive.set(g2);
  }
  get hoveringColor() {
    return this.__hoveringColor.get();
  }
  set hoveringColor(f2) {
    this.__hoveringColor.set(f2);
  }
  get touchDownColor() {
    return this.__touchDownColor.get();
  }
  set touchDownColor(e2) {
    this.__touchDownColor.set(e2);
  }
  get activedColor() {
    return this.__activedColor.get();
  }
  set activedColor(d2) {
    this.__activedColor.set(d2);
  }
  get focusOutlineColor() {
    return this.__focusOutlineColor.get();
  }
  set focusOutlineColor(c2) {
    this.__focusOutlineColor.set(c2);
  }
  onWillApplyTheme(b2) {
    this.hoveringColor = b2.colors.interactiveHover;
    this.touchDownColor = b2.colors.interactivePressed;
    this.activedColor = b2.colors.interactiveActive;
    this.focusOutlineColor = b2.colors.interactiveFocus;
  }
  onPropChange() {
    if (this.contentItem === undefined) {
      if (this.operateItem?.image !== undefined || this.operateItem?.icon !== undefined || this.operateItem?.subIcon !== undefined) {
        this.itemHeight = OPERATEITEM_IMAGE_SIZE + SAFE_LIST_PADDING;
      }
      return;
    }
    if (this.contentItem?.secondaryText === undefined && this.contentItem?.description === undefined) {
      if (this.contentItem?.icon === undefined) {
        this.itemHeight = ItemHeight.FIRST_HEIGHT;
      }
      else {
        this.itemHeight = this.contentItem.iconStyle <= IconType.HEAD_SCULPTURE ? ItemHeight.SECOND_HEIGHT : ItemHeight.THIRD_HEIGHT;
      }
    }
    else if (this.contentItem.description === undefined) {
      if (this.contentItem.icon === undefined || (this.contentItem.icon !== undefined && this.contentItem.iconStyle <= IconType.SYSTEM_ICON)) {
        this.itemHeight = ItemHeight.THIRD_HEIGHT;
      }
      else {
        this.itemHeight = ItemHeight.FOURTH_HEIGHT;
      }
    }
    else {
      this.itemHeight = ItemHeight.FIFTH_HEIGHT;
    }
    if (ICON_SIZE_MAP.get(this.contentItem?.iconStyle) >= this.itemHeight) {
      this.itemHeight = ICON_SIZE_MAP.get(this.contentItem?.iconStyle) + SAFE_LIST_PADDING;
    }
  }
  aboutToAppear() {
    this.onPropChange();
  }
  calculatedLeftWidth() {
    if (this.operateItem === null || JSON.stringify(this.operateItem) === '{}') {
      return RIGHT_CONTENT_NULL_LEFTWIDTH;
    }
    else if (this.operateItem?.arrow != null && this.operateItem?.text == null) {
      return LEFT_ONLY_ARROW_WIDTH;
    }
    else {
      return LEFT_PART_WIDTH;
    }
  }
  calculatedRightWidth() {
    if (this.operateItem === null || JSON.stringify(this.operateItem) === '{}') {
      return RIGHT_CONTENT_NULL_RIGHTWIDTH;
    }
    else if (this.operateItem?.arrow != null && this.operateItem?.text == null) {
      return RIGHT_ONLY_ARROW_WIDTH;
    }
    else {
      return RIGHT_PART_WIDTH;
    }
  }
  initialRender() {
    this.observeComponentCreation2((z1, a2) => {
      Stack.create();
      Stack.padding({
        left: STACK_PADDING,
        right: STACK_PADDING
      });
    }, Stack);
    this.observeComponentCreation2((r1, s1) => {
      Flex.create({ justifyContent: FlexAlign.SpaceBetween, alignItems: ItemAlign.Center });
      Flex.height(this.itemHeight);
      Flex.focusable(true);
      Flex.borderRadius({ "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_default_m'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" });
      Flex.backgroundColor(ObservedObject.GetRawObject(this.frontColor));
      Flex.onFocus(() => {
        this.canFocus = true;
      });
      Flex.onBlur(() => {
        this.canFocus = false;
      });
      Flex.onHover((y1) => {
        this.isHover = y1;
        if (this.canHover) {
          this.frontColor = y1 ? this.hoveringColor :
            (this.isActive ? this.activedColor : Color.Transparent.toString());
        }
      });
      Flex.onTouch((x1) => {
        if (x1.type === TouchType.Down && this.canTouch) {
          this.frontColor = this.touchDownColor;
        }
        if (x1.type === TouchType.Up) {
          this.frontColor = this.isActive ? this.activedColor : Color.Transparent.toString();
        }
      });
      ViewStackProcessor.visualState("focused");
      Flex.border({
        radius: { "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_default_m'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" },
        width: ITEM_BORDER_SHOWN,
        color: this.focusOutlineColor,
        style: BorderStyle.Solid
      });
      ViewStackProcessor.visualState("normal");
      Flex.border({
        radius: { "id": -1, "type": 10002, params: ['sys.float.ohos_id_corner_radius_default_m'], "bundleName": "__harDefaultBundleName__", "moduleName": "__harDefaultModuleName__" },
        width: ITEM_BORDER_SHOWN,
        color: Color.Transparent
      });
      ViewStackProcessor.visualState();
    }, Flex);
    this.observeComponentCreation2((g1, h1) => {
      If.create();
      if (this.contentItem === null) {
        this.ifElseBranchUpdateFunction(0, () => {
          {
            this.observeComponentCreation2((l1, m1) => {
              if (m1) {
                let n1 = new ContentItemStruct(this, {}, undefined, l1, () => { }, { page: "library/src/main/ets/components/mainpage/composelistitem.ets", line: 733, col: 11 });
                ViewPU.create(n1);
                let o1 = () => {
                  return {};
                };
                n1.paramsGenerator_ = o1;
              }
              else {
                this.updateStateVarsOfChildByElmtId(l1, {});
              }
            }, { name: "ContentItemStruct" });
          }
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
    this.observeComponentCreation2((v, w) => {
      If.create();
      if (this.contentItem !== null) {
        this.ifElseBranchUpdateFunction(0, () => {
          {
            this.observeComponentCreation2((a1, b1) => {
              if (b1) {
                let c1 = new ContentItemStruct(this, {
                  icon: this.contentItem?.icon,
                  iconStyle: this.contentItem?.iconStyle,
                  primaryText: this.contentItem?.primaryText,
                  secondaryText: this.contentItem?.secondaryText,
                  description: this.contentItem?.description,
                  leftWidth: this.calculatedLeftWidth()
                }, undefined, a1, () => { }, { page: "library/src/main/ets/components/mainpage/composelistitem.ets", line: 736, col: 11 });
                ViewPU.create(c1);
                let d1 = () => {
                  return {
                    icon: this.contentItem?.icon,
                    iconStyle: this.contentItem?.iconStyle,
                    primaryText: this.contentItem?.primaryText,
                    secondaryText: this.contentItem?.secondaryText,
                    description: this.contentItem?.description,
                    leftWidth: this.calculatedLeftWidth()
                  };
                };
                c1.paramsGenerator_ = d1;
              }
              else {
                this.updateStateVarsOfChildByElmtId(a1, {
                  icon: this.contentItem?.icon,
                  iconStyle: this.contentItem?.iconStyle,
                  primaryText: this.contentItem?.primaryText,
                  secondaryText: this.contentItem?.secondaryText,
                  description: this.contentItem?.description,
                  leftWidth: this.calculatedLeftWidth()
                });
              }
            }, { name: "ContentItemStruct" });
          }
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
    this.observeComponentCreation2((f, g) => {
      If.create();
      if (this.operateItem !== null) {
        this.ifElseBranchUpdateFunction(0, () => {
          this.observeComponentCreation2((r, s) => {
            __Common__.create();
            __Common__.onFocus(() => {
              this.canFocus = false;
            });
            __Common__.onBlur(() => {
              this.canFocus = true;
            });
          }, __Common__);
          {
            this.observeComponentCreation2((l, m) => {
              if (m) {
                let n = new OperateItemStruct(this, {
                  icon: this.operateItem?.icon,
                  subIcon: this.operateItem?.subIcon,
                  button: this.operateItem?.button,
                  switch: this.operateItem?.switch,
                  checkBox: this.operateItem?.checkbox,
                  radio: this.operateItem?.radio,
                  image: this.operateItem?.image,
                  text: this.operateItem?.text,
                  arrow: this.operateItem?.arrow,
                  parentCanFocus: this.__canFocus,
                  parentCanTouch: this.__canTouch,
                  parentIsHover: this.__isHover,
                  parentFrontColor: this.__frontColor,
                  parentIsActive: this.__isActive,
                  parentCanHover: this.__canHover,
                  rightWidth: this.calculatedRightWidth()
                }, undefined, l, () => { }, { page: "library/src/main/ets/components/mainpage/composelistitem.ets", line: 746, col: 11 });
                ViewPU.create(n);
                let o = () => {
                  return {
                    icon: this.operateItem?.icon,
                    subIcon: this.operateItem?.subIcon,
                    button: this.operateItem?.button,
                    switch: this.operateItem?.switch,
                    checkBox: this.operateItem?.checkbox,
                    radio: this.operateItem?.radio,
                    image: this.operateItem?.image,
                    text: this.operateItem?.text,
                    arrow: this.operateItem?.arrow,
                    parentCanFocus: this.canFocus,
                    parentCanTouch: this.canTouch,
                    parentIsHover: this.isHover,
                    parentFrontColor: this.frontColor,
                    parentIsActive: this.isActive,
                    parentCanHover: this.canHover,
                    rightWidth: this.calculatedRightWidth()
                  };
                };
                n.paramsGenerator_ = o;
              }
              else {
                this.updateStateVarsOfChildByElmtId(l, {
                  icon: this.operateItem?.icon,
                  subIcon: this.operateItem?.subIcon,
                  button: this.operateItem?.button,
                  switch: this.operateItem?.switch,
                  checkBox: this.operateItem?.checkbox,
                  radio: this.operateItem?.radio,
                  image: this.operateItem?.image,
                  text: this.operateItem?.text,
                  arrow: this.operateItem?.arrow,
                  rightWidth: this.calculatedRightWidth()
                });
              }
            }, { name: "OperateItemStruct" });
          }
          __Common__.pop();
        });
      }
      else {
        this.ifElseBranchUpdateFunction(1, () => {
        });
      }
    }, If);
    If.pop();
    Flex.pop();
    Stack.pop();
  }
  rerender() {
    this.updateDirtyElements();
  }
}

export default { IconType, ComposeListItem };