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

/// <reference path='./import.ts' />
let LogTag;
(function (LogTag) {
  LogTag[LogTag['STATE_MGMT'] = 0] = 'STATE_MGMT';
  LogTag[LogTag['ARK_COMPONENT'] = 1] = 'ARK_COMPONENT';
})(LogTag || (LogTag = {}));
class ArkLogConsole {
  static log(...args) {
      aceConsole.log(LogTag.ARK_COMPONENT, ...args);
  }
  static debug(...args) {
      aceConsole.debug(LogTag.ARK_COMPONENT, ...args);
  }
  static info(...args) {
      aceConsole.info(LogTag.ARK_COMPONENT, ...args);
  }
  static warn(...args) {
      aceConsole.warn(LogTag.ARK_COMPONENT, ...args);
  }
  static error(...args) {
      aceConsole.error(LogTag.ARK_COMPONENT, ...args);
  }
}
const arkUINativeModule = globalThis.getArkUINativeModule();
function getUINativeModule() {
  if (arkUINativeModule) {
    return arkUINativeModule;
  }
  return arkUINativeModule;
}
let ModifierType;
(function (ModifierType) {
    ModifierType[ModifierType['ORIGIN'] = 0] = 'ORIGIN';
    ModifierType[ModifierType['STATE'] = 1] = 'STATE';
    ModifierType[ModifierType['FRAME_NODE'] = 2] = 'FRAME_NODE';
    ModifierType[ModifierType['EXPOSE_MODIFIER'] = 3] = 'EXPOSE_MODIFIER';
})(ModifierType || (ModifierType = {}));
const UI_STATE_NORMAL = 0;
const UI_STATE_PRESSED = 1;
const UI_STATE_FOCUSED = 1 << 1;
const UI_STATE_DISABLED = 1 << 2;
const UI_STATE_SELECTED = 1 << 3;
function applyUIAttributesInit(modifier, nativeNode) {
  let state = 0;
  if (modifier.applyPressedAttribute !== undefined) {
    state |= UI_STATE_PRESSED;
  }
  if (modifier.applyFocusedAttribute !== undefined) {
    state |= UI_STATE_FOCUSED;
  }
  if (modifier.applyDisabledAttribute !== undefined) {
    state |= UI_STATE_DISABLED;
  }
  if (modifier.applySelectedAttribute !== undefined) {
    state |= UI_STATE_SELECTED;
  }
  getUINativeModule().setSupportedUIState(nativeNode, state);
}
function applyUIAttributes(modifier, nativeNode, component) {
  applyUIAttributesInit(modifier, nativeNode);
  const currentUIState = getUINativeModule().getUIState(nativeNode);
  if (modifier.applyNormalAttribute !== undefined) {
    modifier.applyNormalAttribute(component);
  }
  if ((currentUIState & UI_STATE_PRESSED) && (modifier.applyPressedAttribute !== undefined)) {
    modifier.applyPressedAttribute(component);
  }
  if ((currentUIState & UI_STATE_FOCUSED) && (modifier.applyFocusedAttribute !== undefined)) {
    modifier.applyFocusedAttribute(component);
  }
  if ((currentUIState & UI_STATE_DISABLED) && (modifier.applyDisabledAttribute !== undefined)) {
    modifier.applyDisabledAttribute(component);
  }
  if ((currentUIState & UI_STATE_SELECTED) && (modifier.applySelectedAttribute !== undefined)) {
    modifier.applySelectedAttribute(component);
  }
}
function isResource(variable) {
  return (variable === null || variable === void 0 ? void 0 : variable.bundleName) !== undefined;
}
function isResourceEqual(stageValue, value) {
  return (stageValue.bundleName === value.bundleName) &&
    (stageValue.moduleName === value.moduleName) &&
    (stageValue.id === value.id) &&
    (stageValue.params === value.params) &&
    (stageValue.type === value.type);
}
function isBaseOrResourceEqual(stageValue, value) {
  if (isResource(stageValue) && isResource(value)) {
    return isResourceEqual(stageValue, value);
  }
  else if (!isResource(stageValue) && !isResource(value)) {
    return (stageValue === value);
  }
  return false;
}
const SAFE_AREA_TYPE_NONE = 0;
const SAFE_AREA_TYPE_SYSTEM = 1;
const SAFE_AREA_TYPE_CUTOUT = 2;
const SAFE_AREA_TYPE_KEYBOARD = 4;
const SAFE_AREA_TYPE_ALL = 7;
const SAFE_AREA_EDGE_NONE = 0;
const SAFE_AREA_EDGE_TOP = 1;
const SAFE_AREA_EDGE_BOTTOM = 2;
const SAFE_AREA_EDGE_START = 4;
const SAFE_AREA_EDGE_END = 8;
const SAFE_AREA_EDGE_ALL = 15;
const SAFE_AREA_TYPE_LIMIT = 3;
const SAFE_AREA_EDGE_LIMIT = 4;
const DIRECTION_RANGE = 3;
class ModifierWithKey {
  constructor(value) {
    this.stageValue = value;
  }
  applyStage(node) {
    if (this.stageValue === undefined || this.stageValue === null) {
      this.value = this.stageValue;
      this.applyPeer(node, true);
      return true;
    }
    const stageTypeInfo = typeof this.stageValue;
    const valueTypeInfo = typeof this.value;
    let different = false;
    if (stageTypeInfo !== valueTypeInfo) {
      different = true;
    }
    else if (stageTypeInfo === 'number' || stageTypeInfo === 'string' || stageTypeInfo === 'boolean') {
      different = (this.stageValue !== this.value);
    }
    else {
      different = this.checkObjectDiff();
    }
    if (different) {
      this.value = this.stageValue;
      this.applyPeer(node, false);
    }
    return false;
  }
  applyPeer(node, reset) { }
  checkObjectDiff() {
    return true;
  }
}
class BackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundColor(node);
    }
    else {
      getUINativeModule().common.setBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BackgroundColorModifier.identity = Symbol('backgroundColor');
class WidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetWidth(node);
    }
    else {
      getUINativeModule().common.setWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
WidthModifier.identity = Symbol('width');
class BorderWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBorderWidth(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().common.setBorderWidth(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setBorderWidth(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    }
    else {
      return true;
    }
  }
}
BorderWidthModifier.identity = Symbol('borderWidth');
class HeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetHeight(node);
    }
    else {
      getUINativeModule().common.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
HeightModifier.identity = Symbol('height');
class BorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBorderRadius(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().common.setBorderRadius(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setBorderRadius(node, this.value.topLeft, this.value.topRight, this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    }
    else {
      return true;
    }
  }
}
BorderRadiusModifier.identity = Symbol('borderRadius');
class PositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetPosition(node);
    } else {
      let positionType = new ArkPositionType();
      if (!positionType.parsePositionType(this.value)) {
        getUINativeModule().common.resetPosition(node);
      } else {
        if (!positionType.useEdges) {
          getUINativeModule().common.setPosition(node, positionType.useEdges, this.value.x, this.value.y);
        } else {
          getUINativeModule().common.setPosition(node, positionType.useEdges, this.value.top, this.value.left, this.value.bottom, this.value.right);
        }
      }
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.x, this.value.x) ||
      !isBaseOrResourceEqual(this.stageValue.y, this.value.y) ||
      !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right);
  }
}
PositionModifier.identity = Symbol('position');
class BorderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBorderColor(node);
    }
    else {
      const valueType = typeof this.value;
      if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
        getUINativeModule().common.setBorderColor(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setBorderColor(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    }
    else {
      return true;
    }
  }
}
BorderColorModifier.identity = Symbol('borderColor');
class TransformModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetTransform(node);
    }
    else {
      getUINativeModule().common.setTransform(node, this.value.matrix4x4);
    }
  }
  checkObjectDiff() {
    return !deepCompareArrays(this.stageValue.matrix4x4, this.value.matrix4x4);
  }
}
TransformModifier.identity = Symbol('transform');
class BorderStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d;
    if (reset) {
      getUINativeModule().common.resetBorderStyle(node);
    }
    else {
      let type;
      let style;
      let top;
      let right;
      let bottom;
      let left;
      if (isNumber(this.value)) {
        style = this.value;
        type = true;
      }
      else if (isObject(this.value)) {
        top = (_a = this.value) === null || _a === void 0 ? void 0 : _a.top;
        right = (_b = this.value) === null || _b === void 0 ? void 0 : _b.right;
        bottom = (_c = this.value) === null || _c === void 0 ? void 0 : _c.bottom;
        left = (_d = this.value) === null || _d === void 0 ? void 0 : _d.left;
        type = true;
      }
      if (type === true) {
        getUINativeModule().common.setBorderStyle(node, type, style, top, right, bottom, left);
      }
      else {
        getUINativeModule().common.resetBorderStyle(node);
      }
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    return !(((_a = this.value) === null || _a === void 0 ? void 0 : _a.top) === ((_b = this.stageValue) === null || _b === void 0 ? void 0 : _b.top) &&
      ((_c = this.value) === null || _c === void 0 ? void 0 : _c.right) === ((_d = this.stageValue) === null || _d === void 0 ? void 0 : _d.right) &&
      ((_e = this.value) === null || _e === void 0 ? void 0 : _e.bottom) === ((_f = this.stageValue) === null || _f === void 0 ? void 0 : _f.bottom) &&
      ((_g = this.value) === null || _g === void 0 ? void 0 : _g.left) === ((_h = this.stageValue) === null || _h === void 0 ? void 0 : _h.left));
  }
}
BorderStyleModifier.identity = Symbol('borderStyle');
class ShadowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetShadow(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().common.setShadow(node, this.value, undefined, undefined, undefined, undefined, undefined, undefined);
      }
      else {
        getUINativeModule().common.setShadow(node, undefined, this.value.radius,
          this.value.type, this.value.color,
          this.value.offsetX, this.value.offsetY, this.value.fill);
      }
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.radius === this.value.radius &&
      this.stageValue.type === this.value.type &&
      this.stageValue.color === this.value.color &&
      this.stageValue.offsetX === this.value.offsetX &&
      this.stageValue.offsetY === this.value.offsetY &&
      this.stageValue.fill === this.value.fill);
  }
}
ShadowModifier.identity = Symbol('shadow');
class HitTestBehaviorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetHitTestBehavior(node);
    }
    else {
      getUINativeModule().common.setHitTestBehavior(node, this.value);
    }
  }
}
HitTestBehaviorModifier.identity = Symbol('hitTestBehavior');
class ZIndexModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetZIndex(node);
    }
    else {
      getUINativeModule().common.setZIndex(node, this.value);
    }
  }
}
ZIndexModifier.identity = Symbol('zIndex');
class OpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOpacity(node);
    }
    else {
      getUINativeModule().common.setOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
OpacityModifier.identity = Symbol('opacity');
class AlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAlign(node);
    }
    else {
      getUINativeModule().common.setAlign(node, this.value);
    }
  }
}
AlignModifier.identity = Symbol('align');
class BackdropBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackdropBlur(node);
    }
    else {
      getUINativeModule().common.setBackdropBlur(
        node, this.value.value, (_a = this.value.options) === null || _a === void 0 ? void 0 : _a.grayscale);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
BackdropBlurModifier.identity = Symbol('backdropBlur');
class HueRotateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetHueRotate(node);
    }
    else {
      getUINativeModule().common.setHueRotate(node, this.value);
    }
  }
}
HueRotateModifier.identity = Symbol('hueRotate');
class InvertModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetInvert(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().common.setInvert(node, this.value, undefined, undefined, undefined, undefined);
      }
      else {
        getUINativeModule().common.setInvert(
          node, undefined, this.value.low, this.value.high, this.value.threshold, this.value.thresholdRange);
      }
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.high == this.value.high &&
      this.stageValue.low == this.value.low &&
      this.stageValue.threshold == this.value.threshold &&
      this.stageValue.thresholdRange == this.value.thresholdRange);
  }
}
InvertModifier.identity = Symbol('invert');
class SepiaModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSepia(node);
    }
    else {
      getUINativeModule().common.setSepia(node, this.value);
    }
  }
}
SepiaModifier.identity = Symbol('sepia');
class SaturateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSaturate(node);
    }
    else {
      getUINativeModule().common.setSaturate(node, this.value);
    }
  }
}
SaturateModifier.identity = Symbol('saturate');
class ColorBlendModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetColorBlend(node);
    }
    else {
      getUINativeModule().common.setColorBlend(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ColorBlendModifier.identity = Symbol('colorBlend');
class GrayscaleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetGrayscale(node);
    }
    else {
      getUINativeModule().common.setGrayscale(node, this.value);
    }
  }
}
GrayscaleModifier.identity = Symbol('grayscale');
class ContrastModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetContrast(node);
    }
    else {
      getUINativeModule().common.setContrast(node, this.value);
    }
  }
}
ContrastModifier.identity = Symbol('contrast');
class BrightnessModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBrightness(node);
    }
    else {
      getUINativeModule().common.setBrightness(node, this.value);
    }
  }
}
BrightnessModifier.identity = Symbol('brightness');
class BlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBlur(node);
    }
    else {
      getUINativeModule().common.setBlur(
        node, this.value.value, (_a = this.value.options) === null || _a === void 0 ? void 0 : _a.grayscale);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
BlurModifier.identity = Symbol('blur');
class LinearGradientModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetLinearGradient(node);
    }
    else {
      getUINativeModule().common.setLinearGradient(node, this.value.angle, this.value.direction, this.value.colors, this.value.repeating);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.angle === this.value.angle) &&
      (this.stageValue.direction === this.value.direction) &&
      (this.stageValue.colors === this.value.colors) &&
      (this.stageValue.repeating === this.value.repeating));
  }
}
LinearGradientModifier.identity = Symbol('linearGradient');
class RadialGradientModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetRadialGradient(node);
    }
    else {
      getUINativeModule().common.setRadialGradient(node, this.value.center, this.value.radius, this.value.colors, this.value.repeating);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.center === this.value.center) &&
      (this.stageValue.radius === this.value.radius) &&
      (this.stageValue.colors === this.value.colors) &&
      (this.stageValue.repeating === this.value.repeating));
  }
}
RadialGradientModifier.identity = Symbol('radialGradient');
class SweepGradientModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSweepGradient(node);
    }
    else {
      getUINativeModule().common.setSweepGradient(node, this.value.center, this.value.start,
        this.value.end, this.value.rotation, this.value.colors, this.value.repeating);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.center === this.value.center) &&
      (this.stageValue.start === this.value.start) &&
      (this.stageValue.end === this.value.end) &&
      (this.stageValue.rotation === this.value.rotation) &&
      (this.stageValue.colors === this.value.colors) &&
      (this.stageValue.repeating === this.value.repeating));
  }
}
SweepGradientModifier.identity = Symbol('sweepGradient');
class OverlayModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOverlay(node);
    }
    else {
      getUINativeModule().common.setOverlay(node, this.value.value, this.value.align,
        this.value.offsetX, this.value.offsetY, this.value.hasOptions, this.value.hasOffset);
    }
  }
  checkObjectDiff() {
    if (isUndefined(this.value)) {
      return !isUndefined(this.stageValue);
    }
    return this.value.checkObjectDiff(this.stageValue);
  }
}
OverlayModifier.identity = Symbol('overlay');
class BorderImageModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBorderImage(node);
    }
    else {
      let sliceTop;
      let sliceRight;
      let sliceBottom;
      let sliceLeft;
      let repeat;
      let source;
      let sourceAngle;
      let sourceDirection;
      let sourceColors;
      let sourceRepeating;
      let widthTop;
      let widthRight;
      let widthBottom;
      let widthLeft;
      let outsetTop;
      let outsetRight;
      let outsetBottom;
      let outsetLeft;
      let fill;
      if (!isUndefined(this.value.slice)) {
        if (isLengthType(this.value.slice) || isResource(this.value.slice)) {
          let tmpSlice = this.value.slice;
          sliceTop = tmpSlice;
          sliceRight = tmpSlice;
          sliceBottom = tmpSlice;
          sliceLeft = tmpSlice;
        }
        else {
          let tmpSlice = this.value.slice;
          sliceTop = tmpSlice.top;
          sliceRight = tmpSlice.right;
          sliceBottom = tmpSlice.bottom;
          sliceLeft = tmpSlice.left;
        }
      }
      repeat = this.value.repeat;
      if (!isUndefined(this.value.source)) {
        if (isString(this.value.source) || isResource(this.value.source)) {
          source = this.value.source;
        }
        else {
          let tmpSource = this.value.source;
          sourceAngle = tmpSource.angle;
          sourceDirection = tmpSource.direction;
          sourceColors = tmpSource.colors;
          sourceRepeating = tmpSource.repeating;
        }
      }
      if (!isUndefined(this.value.width)) {
        if (isLengthType(this.value.width) || isResource(this.value.width)) {
          let tmpWidth = this.value.width;
          widthTop = tmpWidth;
          widthRight = tmpWidth;
          widthBottom = tmpWidth;
          widthLeft = tmpWidth;
        }
        else {
          let tmpWidth = this.value.width;
          widthTop = tmpWidth.top;
          widthRight = tmpWidth.right;
          widthBottom = tmpWidth.bottom;
          widthLeft = tmpWidth.left;
        }
      }
      if (!isUndefined(this.value.outset)) {
        if (isLengthType(this.value.outset) || isResource(this.value.outset)) {
          let tmpOutset = this.value.outset;
          outsetTop = tmpOutset;
          outsetRight = tmpOutset;
          outsetBottom = tmpOutset;
          outsetLeft = tmpOutset;
        }
        else {
          let tmpOutset = this.value.outset;
          outsetTop = tmpOutset.top;
          outsetRight = tmpOutset.right;
          outsetBottom = tmpOutset.bottom;
          outsetLeft = tmpOutset.left;
        }
      }
      fill = this.value.fill;
      getUINativeModule().common.setBorderImage(node, sliceTop, sliceRight, sliceBottom,
        sliceLeft, repeat, source, sourceAngle, sourceDirection, sourceColors, sourceRepeating,
        widthTop, widthRight, widthBottom, widthLeft, outsetTop, outsetRight, outsetBottom,
        outsetLeft, fill);
    }
  }
}
BorderImageModifier.identity = Symbol('borderImage');
class BorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBorder(node);
    }
    else {
      getUINativeModule().common.setBorder(node, this.value.arkWidth.left,
        this.value.arkWidth.right, this.value.arkWidth.top, this.value.arkWidth.bottom,
        this.value.arkColor.leftColor, this.value.arkColor.rightColor,
        this.value.arkColor.topColor, this.value.arkColor.bottomColor,
        this.value.arkRadius.topLeft, this.value.arkRadius.topRight,
        this.value.arkRadius.bottomLeft, this.value.arkRadius.bottomRight,
        this.value.arkStyle.top, this.value.arkStyle.right, this.value.arkStyle.bottom,
        this.value.arkStyle.left);
    }
  }
  checkObjectDiff() {
    return this.value.checkObjectDiff(this.stageValue);
  }
}
BorderModifier.identity = Symbol('border');
class OutlineColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOutlineColor(node);
    }
    else {
      const valueType = typeof this.value;
      if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
        getUINativeModule().common.setOutlineColor(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setOutlineColor(node, this.value.left, this.value.right, this.value.top, this.value.bottom);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    }
    else {
      return true;
    }
  }
}
OutlineColorModifier.identity = Symbol('outlineColor');
class OutlineRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOutlineRadius(node);
    }
    else {
      const valueType = typeof this.value;
      if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
        getUINativeModule().common.setOutlineRadius(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setOutlineRadius(node, this.value.topLeft, this.value.topRight, this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    }
    else {
      return true;
    }
  }
}
OutlineRadiusModifier.identity = Symbol('outlineRadius');
class OutlineStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOutlineStyle(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().common.setOutlineStyle(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setOutlineStyle(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    return !(this.value.top === this.stageValue.top &&
      this.value.right === this.stageValue.right &&
      this.value.bottom === this.stageValue.bottom &&
      this.value.left === this.stageValue.left);
  }
}
OutlineStyleModifier.identity = Symbol('outlineStyle');
class OutlineWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOutlineWidth(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().common.setOutlineWidth(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().common.setOutlineWidth(node, this.value.left, this.value.right, this.value.top, this.value.bottom);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    }
    else {
      return true;
    }
  }
}
OutlineWidthModifier.identity = Symbol('outlineWidth');
class OutlineModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOutline(node);
    }
    else {
      let widthLeft;
      let widthRight;
      let widthTop;
      let widthBottom;
      if (!isUndefined(this.value.width) && this.value.width != null) {
        if (isNumber(this.value.width) || isString(this.value.width) || isResource(this.value.width)) {
          widthLeft = this.value.width;
          widthRight = this.value.width;
          widthTop = this.value.width;
          widthBottom = this.value.width;
        }
        else {
          widthLeft = this.value.width.left;
          widthRight = this.value.width.right;
          widthTop = this.value.width.top;
          widthBottom = this.value.width.bottom;
        }
      }
      let leftColor;
      let rightColor;
      let topColor;
      let bottomColor;
      if (!isUndefined(this.value.color) && this.value.color != null) {
        if (isNumber(this.value.color) || isString(this.value.color) || isResource(this.value.color)) {
          leftColor = this.value.color;
          rightColor = this.value.color;
          topColor = this.value.color;
          bottomColor = this.value.color;
        }
        else {
          leftColor = this.value.color.left;
          rightColor = this.value.color.right;
          topColor = this.value.color.top;
          bottomColor = this.value.color.bottom;
        }
      }
      let topLeft;
      let topRight;
      let bottomLeft;
      let bottomRight;
      if (!isUndefined(this.value.radius) && this.value.radius != null) {
        if (isNumber(this.value.radius) || isString(this.value.radius) || isResource(this.value.radius)) {
          topLeft = this.value.radius;
          topRight = this.value.radius;
          bottomLeft = this.value.radius;
          bottomRight = this.value.radius;
        }
        else {
          topLeft = this.value.radius.topLeft;
          topRight = this.value.radius.topRight;
          bottomLeft = this.value.radius.bottomLeft;
          bottomRight = this.value.radius.bottomRight;
        }
      }
      let styleTop;
      let styleRight;
      let styleBottom;
      let styleLeft;
      if (!isUndefined(this.value.style) && this.value.style != null) {
        if (isNumber(this.value.style) || isString(this.value.style) || isResource(this.value.style)) {
          styleTop = this.value.style;
          styleRight = this.value.style;
          styleBottom = this.value.style;
          styleLeft = this.value.style;
        }
        else {
          styleTop = this.value.style.top;
          styleRight = this.value.style.right;
          styleBottom = this.value.style.bottom;
          styleLeft = this.value.style.left;
        }
      }
      getUINativeModule().common.setOutline(node, widthLeft, widthRight, widthTop, widthBottom,
        leftColor, rightColor, topColor, bottomColor,
        topLeft, topRight, bottomLeft, bottomRight,
        styleTop, styleRight, styleBottom, styleLeft);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color) ||
      !isBaseOrResourceEqual(this.stageValue.radius, this.value.radius) ||
      !isBaseOrResourceEqual(this.stageValue.style, this.value.style);
  }
}
OutlineModifier.identity = Symbol('outline');
class ForegroundBlurStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetForegroundBlurStyle(node);
    }
    else {
      getUINativeModule().common.setForegroundBlurStyle(node, this.value.blurStyle, this.value.colorMode, this.value.adaptiveColor, this.value.scale,
        (_a = this.value.blurOptions) === null || _a === void 0 ? void 0 : _a.grayscale);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.blurStyle === this.value.blurStyle &&
      this.stageValue.colorMode === this.value.colorMode &&
      this.stageValue.adaptiveColor === this.value.adaptiveColor &&
      this.stageValue.scale === this.value.scale &&
      this.stageValue.blurOptions === this.value.blurOptions);
  }
}
ForegroundBlurStyleModifier.identity = Symbol('foregroundBlurStyle');
class BackgroundImagePositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().common.resetBackgroundImagePosition(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().common.setBackgroundImagePosition(node, this.value, undefined, undefined);
      }
      else {
        getUINativeModule().common.setBackgroundImagePosition(node, undefined,
          (_a = this.value) === null || _a === void 0 ? void 0 : _a.x,
          (_b = this.value) === null || _b === void 0 ? void 0 : _b.y);
      }
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d;
    return !(((_a = this.value) === null || _a === void 0 ? void 0 : _a.x) === ((_b = this.stageValue) === null || _b === void 0 ? void 0 : _b.x) &&
      ((_c = this.value) === null || _c === void 0 ? void 0 : _c.y) === ((_d = this.stageValue) === null || _d === void 0 ? void 0 : _d.y));
  }
}
BackgroundImagePositionModifier.identity = Symbol('backgroundImagePosition');
class BackgroundImageResizableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundImageResizable(node);
    }
    else {
      let sliceTop, sliceBottom, sliceLeft, sliceRight;
      if (!isUndefined(this.value.slice)) {
        let tempSlice = this.value.slice;
        sliceTop = tempSlice.top;
        sliceBottom = tempSlice.bottom;
        sliceLeft = tempSlice.left;
        sliceRight = tempSlice.right;
      }
      getUINativeModule().common.setBackgroundImageResizable(node, sliceTop, sliceBottom, sliceLeft, sliceRight);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BackgroundImageResizableModifier.identity = Symbol('backgroundImageResizable');
class LinearGradientBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetLinearGradientBlur(node);
    }
    else {
      getUINativeModule().common.setLinearGradientBlur(node, this.value.blurRadius, this.value.fractionStops, this.value.direction);
    }
  }
  checkObjectDiff() {
    return !this.value.isEqual(this.stageValue);
  }
}
LinearGradientBlurModifier.identity = Symbol('linearGradientBlur');
class BackgroundImageModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundImage(node);
    }
    else {
      getUINativeModule().common.setBackgroundImage(node, this.value.src, this.value.repeat);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.src === this.value.src &&
      this.stageValue.repeat === this.value.repeat);
  }
}
BackgroundImageModifier.identity = Symbol('backgroundImage');
class BackgroundBlurStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundBlurStyle(node);
    }
    else {
      getUINativeModule().common.setBackgroundBlurStyle(node, this.value.blurStyle, this.value.colorMode, this.value.adaptiveColor, this.value.scale,
        (_a = this.value.blurOptions) === null || _a === void 0 ? void 0 : _a.grayscale);
    }
  }
}
BackgroundBlurStyleModifier.identity = Symbol('backgroundBlurStyle');
class BackgroundImageSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().common.resetBackgroundImageSize(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().common.setBackgroundImageSize(node, this.value, undefined, undefined);
      }
      else {
        getUINativeModule().common.setBackgroundImageSize(node, undefined,
          (_a = this.value) === null || _a === void 0 ? void 0 : _a.width,
          (_b = this.value) === null || _b === void 0 ? void 0 : _b.height);
      }
    }
  }
  checkObjectDiff() {
    return !(this.value.width === this.stageValue.width &&
      this.value.height === this.stageValue.height);
  }
}
BackgroundImageSizeModifier.identity = Symbol('backgroundImageSize');
class TranslateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetTranslate(node);
    }
    else {
      getUINativeModule().common.setTranslate(node, this.value.x, this.value.y, this.value.z);
    }
  }
  checkObjectDiff() {
    return !(this.value.x === this.stageValue.x &&
      this.value.y === this.stageValue.y &&
      this.value.z === this.stageValue.z);
  }
}
TranslateModifier.identity = Symbol('translate');
class ScaleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetScale(node);
    }
    else {
      getUINativeModule().common.setScale(node, this.value.x, this.value.y, this.value.z, this.value.centerX, this.value.centerY);
    }
  }
  checkObjectDiff() {
    return !(this.value.x === this.stageValue.x &&
      this.value.y === this.stageValue.y &&
      this.value.z === this.stageValue.z &&
      this.value.centerX === this.stageValue.centerX &&
      this.value.centerY === this.stageValue.centerY);
  }
}
ScaleModifier.identity = Symbol('scale');
class RotateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetRotate(node);
    }
    else {
      getUINativeModule().common.setRotate(node, this.value.x, this.value.y,
        this.value.z, this.value.angle, this.value.centerX, this.value.centerY,
        this.value.centerY, this.value.perspective);
    }
  }
  checkObjectDiff() {
    return !(this.value.x === this.stageValue.x &&
      this.value.y === this.stageValue.y &&
      this.value.z === this.stageValue.z &&
      this.value.angle === this.stageValue.angle &&
      this.value.centerX === this.stageValue.centerX &&
      this.value.centerY === this.stageValue.centerY &&
      this.value.centerZ === this.stageValue.centerZ &&
      this.value.perspective === this.stageValue.perspective);
  }
}
RotateModifier.identity = Symbol('rotate');
class GeometryTransitionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a;
    if (reset) {
      getUINativeModule().common.resetGeometryTransition(node);
    }
    else {
      getUINativeModule().common.setGeometryTransition(node, this.value.id, (_a = this.value.options) === null ||
       _a === void 0 ? void 0 : _a.follow);
    }
  }
}
GeometryTransitionModifier.identity = Symbol('geometryTransition');
class BlendModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBlendMode(node);
    }
    else {
      getUINativeModule().common.setBlendMode(node, this.value.blendMode, this.value.blendApplyType);
    }
  }
}
BlendModeModifier.identity = Symbol('blendMode');
class ClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClip(node);
    }
    else {
      getUINativeModule().common.setClip(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ClipModifier.identity = Symbol('clip');
class MaskModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetMask(node);
    }
    else {
      getUINativeModule().common.setMask(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
MaskModifier.identity = Symbol('mask');
class PixelStretchEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetPixelStretchEffect(node);
    }
    else {
      getUINativeModule().common.setPixelStretchEffect(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.left === this.value.left &&
      this.stageValue.right === this.value.right &&
      this.stageValue.top === this.value.top &&
      this.stageValue.bottom === this.value.bottom);
  }
}
PixelStretchEffectModifier.identity = Symbol('pixelStretchEffect');
class LightUpEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetLightUpEffect(node);
    }
    else {
      getUINativeModule().common.setLightUpEffect(node, this.value);
    }
  }
}
LightUpEffectModifier.identity = Symbol('lightUpEffect');
class SphericalEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSphericalEffect(node);
    }
    else {
      getUINativeModule().common.setSphericalEffect(node, this.value);
    }
  }
}
SphericalEffectModifier.identity = Symbol('sphericalEffect');
class RenderGroupModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetRenderGroup(node);
    }
    else {
      getUINativeModule().common.setRenderGroup(node, this.value);
    }
  }
}
RenderGroupModifier.identity = Symbol('renderGroup');
class RenderFitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetRenderFit(node);
    }
    else {
      getUINativeModule().common.setRenderFit(node, this.value);
    }
  }
}
RenderFitModifier.identity = Symbol('renderFit');
class UseEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetUseEffect(node);
    }
    else {
      getUINativeModule().common.setUseEffect(node, this.value);
    }
  }
}
UseEffectModifier.identity = Symbol('useEffect');
class ForegroundEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetForegroundEffect(node);
    }
    else {
      getUINativeModule().common.setForegroundEffect(node, this.value.radius);
    }
  }
  checkObjectDiff() {
    return !(this.value.radius === this.stageValue.radius);
  }
}
ForegroundEffectModifier.identity = Symbol('foregroundEffect');
class ForegroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetForegroundColor(node);
    }
    else {
      getUINativeModule().common.setForegroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ForegroundColorModifier.identity = Symbol('foregroundColor');
class ClickModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnClick(node);
    } else {
      getUINativeModule().common.setOnClick(node, this.value);
    }
  }
}
ClickModifier.identity = Symbol('onClick');
class OnTouchModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnTouch(node);
    } else {
      getUINativeModule().common.setOnTouch(node, this.value);
    }
  }
}
OnTouchModifier.identity = Symbol('onTouch');
class OnAppearModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnAppear(node);
    } else {
      getUINativeModule().common.setOnAppear(node, this.value);
    }
  }
}
OnAppearModifier.identity = Symbol('onAppear');
class OnDisappearModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnDisappear(node);
    } else {
      getUINativeModule().common.setOnDisappear(node, this.value);
    }
  }
}
OnDisappearModifier.identity = Symbol('onDisappear');
class OnAttachModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnAttach(node);
    } else {
      getUINativeModule().common.setOnAttach(node, this.value);
    }
  }
}
OnAttachModifier.identity = Symbol('onAttach');
class OnDetachModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnDetach(node);
    } else {
      getUINativeModule().common.setOnDetach(node, this.value);
    }
  }
}
OnDetachModifier.identity = Symbol('onDetach');
class OnKeyEventModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnKeyEvent(node);
    } else {
      getUINativeModule().common.setOnKeyEvent(node, this.value);
    }
  }
}
OnKeyEventModifier.identity = Symbol('onKeyEvent');
class OnFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnFocus(node);
    } else {
      getUINativeModule().common.setOnFocus(node, this.value);
    }
  }
}
OnFocusModifier.identity = Symbol('onFocus');
class OnBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnBlur(node);
    } else {
      getUINativeModule().common.setOnBlur(node, this.value);
    }
  }
}
OnBlurModifier.identity = Symbol('onBlur');

class OnHoverModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnHover(node);
    } else {
      getUINativeModule().common.setOnHover(node, this.value);
    }
  }
}
OnHoverModifier.identity = Symbol('onHover');
class OnMouseModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnMouse(node);
    } else {
      getUINativeModule().common.setOnMouse(node, this.value);
    }
  }
}
OnMouseModifier.identity = Symbol('onMouse');
class OnSizeChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnSizeChange(node);
    } else {
      getUINativeModule().common.setOnSizeChange(node, this.value);
    }
  }
}
OnSizeChangeModifier.identity = Symbol('onSizeChange');
class OnAreaChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnAreaChange(node);
    } else {
      getUINativeModule().common.setOnAreaChange(node, this.value);
    }
  }
}
OnSizeChangeModifier.identity = Symbol('onAreaChange');
class OnGestureJudgeBeginModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOnGestureJudgeBegin(node);
    } else {
      getUINativeModule().common.setOnGestureJudgeBegin(node, this.value);
    }
  }
}
OnGestureJudgeBeginModifier.identity = Symbol('onGestureJudgeBegin');
class MotionPathModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetMotionPath(node);
    }
    else {
      let path;
      let rotatable;
      let from;
      let to;
      if (isString(this.value.path)) {
        path = this.value.path;
      }
      if (isBoolean(this.value.rotatable)) {
        rotatable = this.value.rotatable;
      }
      if (isNumber(this.value.from) && isNumber(this.value.to)) {
        from = this.value.from;
        to = this.value.to;
      }
      getUINativeModule().common.setMotionPath(node, path, from, to, rotatable);
    }
  }
  checkObjectDiff() {
    return !(this.value.path === this.stageValue.path &&
      this.value.from === this.stageValue.from &&
      this.value.to === this.stageValue.to &&
      this.value.rotatable === this.stageValue.rotatable);
  }
}
MotionPathModifier.identity = Symbol('motionPath');
class MotionBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetMotionBlur(node);
    }
    else {
      getUINativeModule().common.setMotionBlur(node, this.value.radius, this.value.anchor.x, this.value.anchor.y);
    }
  }
}
MotionBlurModifier.identity = Symbol('motionBlur');
class GroupDefaultFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetGroupDefaultFocus(node);
    }
    else {
      getUINativeModule().common.setGroupDefaultFocus(node, this.value);
    }
  }
}
GroupDefaultFocusModifier.identity = Symbol('groupDefaultFocus');
class FocusOnTouchModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetFocusOnTouch(node);
    }
    else {
      getUINativeModule().common.setFocusOnTouch(node, this.value);
    }
  }
}
FocusOnTouchModifier.identity = Symbol('focusOnTouch');
class OffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetOffset(node);
    } else {
      let positionType = new ArkPositionType();
      if (!positionType.parsePositionType(this.value)) {
        getUINativeModule().common.resetOffset(node);
      } else {
        if (!positionType.useEdges) {
          getUINativeModule().common.setOffset(node, positionType.useEdges, this.value.x, this.value.y);
        } else {
          getUINativeModule().common.setOffset(node, positionType.useEdges, this.value.top, this.value.left, this.value.bottom, this.value.right);
        }
      }
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.x, this.value.x) ||
      !isBaseOrResourceEqual(this.stageValue.y, this.value.y) ||
      !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right);
  }
}
OffsetModifier.identity = Symbol('offset');
class MarkAnchorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().common.resetMarkAnchor(node);
    }
    else {
      getUINativeModule().common.setMarkAnchor(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.x, (_b = this.value) === null || _b === void 0 ? void 0 : _b.y);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.x, this.value.x) ||
      !isBaseOrResourceEqual(this.stageValue.y, this.value.y);
  }
}
MarkAnchorModifier.identity = Symbol('markAnchor');
class DefaultFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetDefaultFocus(node);
    }
    else {
      getUINativeModule().common.setDefaultFocus(node, this.value);
    }
  }
}
DefaultFocusModifier.identity = Symbol('defaultFocus');
class FocusableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    getUINativeModule().common.setFocusable(node, this.value);
  }
}
FocusableModifier.identity = Symbol('focusable');
class TouchableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetTouchable(node);
    }
    else {
      getUINativeModule().common.setTouchable(node, this.value);
    }
  }
}
TouchableModifier.identity = Symbol('touchable');
class MarginModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetMargin(node);
    }
    else {
      getUINativeModule().common.setMargin(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
MarginModifier.identity = Symbol('margin');
class PaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetPadding(node);
    }
    else {
      getUINativeModule().common.setPadding(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
PaddingModifier.identity = Symbol('padding');
class VisibilityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetVisibility(node);
    }
    else {
      getUINativeModule().common.setVisibility(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
VisibilityModifier.identity = Symbol('visibility');
class AccessibilityTextModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAccessibilityText(node);
    }
    else {
      getUINativeModule().common.setAccessibilityText(node, this.value);
    }
  }
}
AccessibilityTextModifier.identity = Symbol('accessibilityText');
class AllowDropModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAllowDrop(node);
    }
    else {
      getUINativeModule().common.setAllowDrop(node, this.value);
    }
  }
  checkObjectDiff() {
    return !(Array.isArray(this.value) && Array.isArray(this.stageValue) &&
      this.value.length === this.stageValue.length &&
      this.value.every((value, index) => value === this.stageValue[index]));
  }
}
AllowDropModifier.identity = Symbol('allowDrop');
class AccessibilityLevelModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAccessibilityLevel(node);
    }
    else {
      getUINativeModule().common.setAccessibilityLevel(node, this.value);
    }
  }
}
AccessibilityLevelModifier.identity = Symbol('accessibilityLevel');
class AccessibilityDescriptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAccessibilityDescription(node);
    }
    else {
      getUINativeModule().common.setAccessibilityDescription(node, this.value);
    }
  }
}
AccessibilityDescriptionModifier.identity = Symbol('accessibilityDescription');
class DirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetDirection(node);
    }
    else {
      getUINativeModule().common.setDirection(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DirectionModifier.identity = Symbol('direction');
class AlignRulesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAlignRules(node);
    }
    else {
      getUINativeModule().common.setAlignRules(node, this.value.left, this.value.middle,
        this.value.right, this.value.top, this.value.center, this.value.bottom);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.left, this.value.left) ||
      !isBaseOrResourceEqual(this.stageValue.middle, this.value.middle) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.center, this.value.center) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom);
  }
}
AlignRulesModifier.identity = Symbol('alignRules');
class ExpandSafeAreaModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetExpandSafeArea(node);
    }
    else {
      getUINativeModule().common.setExpandSafeArea(node, this.value.type, this.value.edges);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.type, this.value.type) ||
      !isBaseOrResourceEqual(this.stageValue.edges, this.value.edges);
  }
}
ExpandSafeAreaModifier.identity = Symbol('expandSafeArea');
class GridSpanModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetGridSpan(node);
    }
    else {
      getUINativeModule().common.setGridSpan(node, this.value);
    }
  }
}
GridSpanModifier.identity = Symbol('gridSpan');
class GridOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetGridOffset(node);
    }
    else {
      getUINativeModule().common.setGridOffset(node, this.value);
    }
  }
}
GridOffsetModifier.identity = Symbol('gridOffset');
class AlignSelfModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAlignSelf(node);
    }
    else {
      getUINativeModule().common.setAlignSelf(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
AlignSelfModifier.identity = Symbol('alignSelf');
class SizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSize(node);
    }
    else {
      getUINativeModule().common.setSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
SizeModifier.identity = Symbol('size');
class DisplayPriorityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetDisplayPriority(node);
    }
    else {
      getUINativeModule().common.setDisplayPriority(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DisplayPriorityModifier.identity = Symbol('displayPriority');
class IdModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetId(node);
    }
    else {
      getUINativeModule().common.setId(node, this.value);
    }
  }
}
IdModifier.identity = Symbol('id');
class KeyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetKey(node);
    }
    else {
      getUINativeModule().common.setKey(node, this.value);
    }
  }
}
KeyModifier.identity = Symbol('key');
class RestoreIdModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetRestoreId(node);
    }
    else {
      getUINativeModule().common.setRestoreId(node, this.value);
    }
  }
}
RestoreIdModifier.identity = Symbol('restoreId');
class TabIndexModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetTabIndex(node);
    }
    else {
      getUINativeModule().common.setTabIndex(node, this.value);
    }
  }
}
TabIndexModifier.identity = Symbol('tabIndex');
class ObscuredModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset || (!Array.isArray(this.value))) {
      getUINativeModule().common.resetObscured(node);
    }
    else {
      getUINativeModule().common.setObscured(node, this.value);
    }
  }
  checkObjectDiff() {
    return !(Array.isArray(this.value) && Array.isArray(this.stageValue) &&
      this.value.length === this.stageValue.length &&
      this.value.every((value, index) => value === this.stageValue[index]));
  }
}
ObscuredModifier.identity = Symbol('obscured');
class BackgroundEffectModifier extends ModifierWithKey {
  constructor(options) {
    super(options);
  }
  applyPeer(node, reset) {
    let _a;
    if (reset) {
      getUINativeModule().common.resetBackgroundEffect(node);
    }
    else {
      getUINativeModule().common.setBackgroundEffect(node, this.value.radius, this.value.saturation, this.value.brightness, this.value.color,
        this.value.adaptiveColor, (_a = this.value.blurOptions) === null || _a === void 0 ? void 0 : _a.grayscale);
    }
  }
  checkObjectDiff() {
    let _a;
    let _b;
    return !(this.value.radius === this.stageValue.radius && this.value.saturation === this.stageValue.saturation &&
      this.value.brightness === this.stageValue.brightness &&
      isBaseOrResourceEqual(this.stageValue.color, this.value.color) &&
      this.value.adaptiveColor === this.stageValue.adaptiveColor &&
      ((_a = this.value.blurOptions) === null || _a === void 0 ? void 0 : _a.grayscale) === ((_b = this.stageValue.blurOptions) === null ||
      _b === void 0 ? void 0 : _b.grayscale));
  }
}
BackgroundEffectModifier.identity = Symbol('backgroundEffect');
class BackgroundBrightnessModifier extends ModifierWithKey {
  constructor(params) {
    super(params);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundBrightness(node);
    }
    else {
      getUINativeModule().common.setBackgroundBrightness(node, this.value.rate, this.value.lightUpDegree);
    }
  }
  checkObjectDiff() {
    return !(this.value.rate === this.stageValue.rate && this.value.lightUpDegree === this.stageValue.lightUpDegree);
  }
}
BackgroundBrightnessModifier.identity = Symbol('backgroundBrightness');
class BackgroundBrightnessInternalModifier extends ModifierWithKey {
  constructor(params) {
    super(params);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetBackgroundBrightnessInternal(node);
    }
    else {
      getUINativeModule().common.setBackgroundBrightnessInternal(node, this.value.rate, this.value.lightUpDegree, this.value.cubicCoeff, 
             this.value.quadCoeff, this.value.saturation, this.value.posRGB, this.value.negRGB, this.value.fraction);
    }
  }
  checkObjectDiff() {
    return !(this.value.rate === this.stageValue.rate && this.value.lightUpDegree === this.stageValue.lightUpDegree
          && this.value.cubicCoeff === this.stageValue.cubicCoeff && this.value.quadCoeff === this.stageValue.quadCoeff
          && this.value.saturation === this.stageValue.saturation && this.value.posRGB === this.stageValue.posRGB 
          && this.value.negRGB === this.stageValue.negRGB && this.value.fraction === this.stageValue.fraction);
  }
}
BackgroundBrightnessInternalModifier.identity = Symbol('backgroundBrightnessInternal');
class ForegroundBrightnessModifier extends ModifierWithKey {
    constructor(params) {
      super(params);
    }
    applyPeer(node, reset) {
      if (reset) {
        getUINativeModule().common.resetForegroundBrightness(node);
      }
      else {
        getUINativeModule().common.setForegroundBrightness(node, this.value.rate, this.value.lightUpDegree, this.value.cubicCoeff, 
          this.value.quadCoeff, this.value.saturation, this.value.posRGB, this.value.negRGB, this.value.fraction);
      }
    }
    checkObjectDiff() {
      return !(this.value.rate === this.stageValue.rate && this.value.lightUpDegree === this.stageValue.lightUpDegree
        && this.value.cubicCoeff === this.stageValue.cubicCoeff && this.value.quadCoeff === this.stageValue.quadCoeff
        && this.value.saturation === this.stageValue.saturation && this.value.posRGB === this.stageValue.posRGB 
        && this.value.negRGB === this.stageValue.negRGB && this.value.fraction === this.stageValue.fraction);
  }
}
ForegroundBrightnessModifier.identity = Symbol('foregroundBrightness');
class DragPreviewOptionsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetDragPreviewOptions(node);
    }
    else {
      getUINativeModule().common.setDragPreviewOptions(node, this.value.mode);
    }
  }
  checkObjectDiff() {
    return !(this.value.mode === this.stageValue.mode);
  }
}
DragPreviewOptionsModifier.identity = Symbol('dragPreviewOptions');
class MouseResponseRegionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().common.resetMouseResponseRegion(node);
    }
    else {
      let responseRegion = [];
      if (Array.isArray(this.value)) {
        for (let i = 0; i < this.value.length; i++) {
          responseRegion.push((_a = this.value[i].x) !== null && _a !== void 0 ? _a : 'PLACEHOLDER');
          responseRegion.push((_b = this.value[i].y) !== null && _b !== void 0 ? _b : 'PLACEHOLDER');
          responseRegion.push((_c = this.value[i].width) !== null && _c !== void 0 ? _c : 'PLACEHOLDER');
          responseRegion.push((_d = this.value[i].height) !== null && _d !== void 0 ? _d : 'PLACEHOLDER');
        }
      }
      else {
        responseRegion.push((_e = this.value.x) !== null && _e !== void 0 ? _e : 'PLACEHOLDER');
        responseRegion.push((_f = this.value.y) !== null && _f !== void 0 ? _f : 'PLACEHOLDER');
        responseRegion.push((_g = this.value.width) !== null && _g !== void 0 ? _g : 'PLACEHOLDER');
        responseRegion.push((_h = this.value.height) !== null && _h !== void 0 ? _h : 'PLACEHOLDER');
      }
      getUINativeModule().common.setMouseResponseRegion(node, responseRegion, responseRegion.length);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.value) && Array.isArray(this.stageValue)) {
      if (this.value.length !== this.stageValue.length) {
        return true;
      }
      else {
        for (let i = 0; i < this.value.length; i++) {
          if (!(isBaseOrResourceEqual(this.stageValue[i].x, this.value[i].x) &&
            isBaseOrResourceEqual(this.stageValue[i].y, this.value[i].y) &&
            isBaseOrResourceEqual(this.stageValue[i].width, this.value[i].width) &&
            isBaseOrResourceEqual(this.stageValue[i].height, this.value[i].height))) {
            return true;
          }
        }
        return false;
      }
    }
    else if (!Array.isArray(this.value) && !Array.isArray(this.stageValue)) {
      return (!(isBaseOrResourceEqual(this.stageValue.x, this.value.x) &&
        isBaseOrResourceEqual(this.stageValue.y, this.value.y) &&
        isBaseOrResourceEqual(this.stageValue.width, this.value.width) &&
        isBaseOrResourceEqual(this.stageValue.height, this.value.height)));
    }
    else {
      return false;
    }
  }
}
MouseResponseRegionModifier.identity = Symbol('mouseResponseRegion');
class ResponseRegionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().common.resetResponseRegion(node);
    }
    else {
      let responseRegion = [];
      if (Array.isArray(this.value)) {
        for (let i = 0; i < this.value.length; i++) {
          responseRegion.push((_a = this.value[i].x) !== null && _a !== void 0 ? _a : 'PLACEHOLDER');
          responseRegion.push((_b = this.value[i].y) !== null && _b !== void 0 ? _b : 'PLACEHOLDER');
          responseRegion.push((_c = this.value[i].width) !== null && _c !== void 0 ? _c : 'PLACEHOLDER');
          responseRegion.push((_d = this.value[i].height) !== null && _d !== void 0 ? _d : 'PLACEHOLDER');
        }
      }
      else {
        responseRegion.push((_e = this.value.x) !== null && _e !== void 0 ? _e : 'PLACEHOLDER');
        responseRegion.push((_f = this.value.y) !== null && _f !== void 0 ? _f : 'PLACEHOLDER');
        responseRegion.push((_g = this.value.width) !== null && _g !== void 0 ? _g : 'PLACEHOLDER');
        responseRegion.push((_h = this.value.height) !== null && _h !== void 0 ? _h : 'PLACEHOLDER');
      }
      getUINativeModule().common.setResponseRegion(node, responseRegion, responseRegion.length);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.value) && Array.isArray(this.stageValue)) {
      if (this.value.length !== this.stageValue.length) {
        return true;
      }
      else {
        for (let i = 0; i < this.value.length; i++) {
          if (!(isBaseOrResourceEqual(this.stageValue[i].x, this.value[i].x) &&
            isBaseOrResourceEqual(this.stageValue[i].y, this.value[i].y) &&
            isBaseOrResourceEqual(this.stageValue[i].width, this.value[i].width) &&
            isBaseOrResourceEqual(this.stageValue[i].height, this.value[i].height))) {
            return true;
          }
        }
        return false;
      }
    }
    else if (!Array.isArray(this.value) && !Array.isArray(this.stageValue)) {
      return (!(isBaseOrResourceEqual(this.stageValue.x, this.value.x) &&
        isBaseOrResourceEqual(this.stageValue.y, this.value.y) &&
        isBaseOrResourceEqual(this.stageValue.width, this.value.width) &&
        isBaseOrResourceEqual(this.stageValue.height, this.value.height)));
    }
    else {
      return false;
    }
  }
}
ResponseRegionModifier.identity = Symbol('responseRegion');
class FlexGrowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetFlexGrow(node);
    }
    else {
      getUINativeModule().common.setFlexGrow(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
FlexGrowModifier.identity = Symbol('flexGrow');
class FlexShrinkModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetFlexShrink(node);
    }
    else {
      getUINativeModule().common.setFlexShrink(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
FlexShrinkModifier.identity = Symbol('flexShrink');
class AspectRatioModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAspectRatio(node);
    }
    else {
      getUINativeModule().common.setAspectRatio(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
AspectRatioModifier.identity = Symbol('aspectRatio');
class ConstraintSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetConstraintSize(node);
    }
    else {
      getUINativeModule().common.setConstraintSize(node, this.value.minWidth, this.value.maxWidth, this.value.minHeight, this.value.maxHeight);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.minWidth, this.value.minWidth) ||
      !isBaseOrResourceEqual(this.stageValue.maxWidth, this.value.maxWidth) ||
      !isBaseOrResourceEqual(this.stageValue.minHeight, this.value.minHeight) ||
      !isBaseOrResourceEqual(this.stageValue.maxHeight, this.value.maxHeight);
  }
}
ConstraintSizeModifier.identity = Symbol('constraintSize');
class FlexBasisModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetFlexBasis(node);
    }
    else {
      getUINativeModule().common.setFlexBasis(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
FlexBasisModifier.identity = Symbol('flexBasis');
class LayoutWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetLayoutWeight(node);
    }
    else {
      getUINativeModule().common.setLayoutWeight(node, this.value);
    }
  }
}
LayoutWeightModifier.identity = Symbol('layoutWeight');
class EnabledModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetEnabled(node);
    }
    else {
      getUINativeModule().common.setEnabled(node, this.value);
    }
  }
}
EnabledModifier.identity = Symbol('enabled');
class UseShadowBatchingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetUseShadowBatching(node);
    }
    else {
      getUINativeModule().common.setUseShadowBatching(node, this.value);
    }
  }
}
UseShadowBatchingModifier.identity = Symbol('useShadowBatching');
class MonopolizeEventsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetMonopolizeEvents(node);
    }
    else {
      getUINativeModule().common.setMonopolizeEvents(node, this.value);
    }
  }
}
MonopolizeEventsModifier.identity = Symbol('monopolizeEvents');
class DraggableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetDraggable(node);
    }
    else {
      getUINativeModule().common.setDraggable(node, this.value);
    }
  }
}
DraggableModifier.identity = Symbol('draggable');
class AccessibilityGroupModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetAccessibilityGroup(node);
    }
    else {
      getUINativeModule().common.setAccessibilityGroup(node, this.value);
    }
  }
}
AccessibilityGroupModifier.identity = Symbol('accessibilityGroup');
class HoverEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetHoverEffect(node);
    }
    else {
      getUINativeModule().common.setHoverEffect(node, this.value);
    }
  }
}
HoverEffectModifier.identity = Symbol('hoverEffect');
class ClickEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset || !this.value) {
      getUINativeModule().common.resetClickEffect(node);
    }
    else {
      getUINativeModule().common.setClickEffect(node, this.value.level, this.value.scale);
    }
  }
  checkObjectDiff() {
    return !((this.value.level === this.stageValue.level) && (this.value.scale === this.stageValue.scale));
  }
}
ClickEffectModifier.identity = Symbol('clickEffect');
class KeyBoardShortCutModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetKeyBoardShortCut(node);
    }
    else {
      getUINativeModule().common.setKeyBoardShortCut(node, this.value.value, this.value.keys);
    }
  }
  checkObjectDiff() {
    return !this.value.isEqual(this.stageValue);
  }
}
KeyBoardShortCutModifier.identity = Symbol('keyboardShortcut');

class CustomPropertyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    const nodeId = getUINativeModule().frameNode.getIdByNodePtr(node);
    if (reset) {
      __removeCustomProperty__(nodeId, this.value.key);
    }
    else {
      __setValidCustomProperty__(nodeId, this.value.key, this.value.value);
    }
  }
}
CustomPropertyModifier.identity = Symbol('customProperty');

class TransitionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetTransition(node);
    }
    else {
      getUINativeModule().common.setTransition(node, this.value);
    }
  }
}
TransitionModifier.identity = Symbol('transition');
class SharedTransitionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetSharedTransition(node);
    }
    else {
      getUINativeModule().common.setSharedTransition(node, this.value.id, this.value.options);
    }
  }
}
SharedTransitionModifier.identity = Symbol('sharedTransition');
const JSCallbackInfoType = { STRING: 0, NUMBER: 1, OBJECT: 2, BOOLEAN: 3, FUNCTION: 4 };
const isString = (val) => typeof val === 'string';
const isNumber = (val) => typeof val === 'number';
const isBigint = (val) => typeof val === 'bigint';
const isBoolean = (val) => typeof val === 'boolean';
const isSymbol = (val) => typeof val === 'symbol';
const isUndefined = (val) => typeof val === 'undefined';
const isObject = (val) => typeof val === 'object';
const isFunction = (val) => typeof val === 'function';
const isLengthType = (val) => typeof val === 'string' || typeof val === 'number';
function checkJsCallbackInfo(value, checklist) {
  let typeVerified = false;
  checklist.forEach(function (infoType) {
    switch (infoType) {
      case JSCallbackInfoType.STRING:
        if (isString(value)) {
          typeVerified = true;
        }
        break;
      case JSCallbackInfoType.NUMBER:
        if (isNumber(value)) {
          typeVerified = true;
        }
        break;
      case JSCallbackInfoType.OBJECT:
        if (isObject(value)) {
          typeVerified = true;
        }
        break;
      case JSCallbackInfoType.FUNCTION:
        if (isFunction(value)) {
          typeVerified = true;
        }
        break;
      default:
        break;
    }
  });
  return typeVerified || checklist.length === 0;
}
function parseWithDefaultNumber(val, defaultValue) {
  if (isNumber(val)) {
    return val;
  }
  else { return defaultValue; }
}
function modifierWithKey(modifiers, identity, modifierClass, value) {
  const item = modifiers.get(identity);
  if (item) {
    item.stageValue = value;
    modifiers.set(identity, item);
  }
  else {
    modifiers.set(identity, new modifierClass(value));
  }
}

class ObservedMap {
  constructor() {
      this.map_ = new Map();
  }
  clear() {
      this.map_.clear();
  }
  delete(key) {
      return this.map_.delete(key);
  }
  forEach(callbackfn, thisArg) {
      this.map_.forEach(callbackfn, thisArg);
  }
  get(key) {
      return this.map_.get(key);
  }
  has(key) {
      return this.map_.has(key);
  }
  set(key, value) {
      const _a = this.changeCallback;
      this.map_.set(key, value);
      _a === null || _a === void 0 ? void 0 : _a(key, value);
      return this;
  }
  get size() {
      return this.map_.size;
  }
  entries() {
      return this.map_.entries();
  }
  keys() {
      return this.map_.keys();
  }
  values() {
      return this.map_.values();
  }
  [Symbol.iterator]() {
      return this.map_.entries();
  }
  get [Symbol.toStringTag]() {
      return 'ObservedMapTag';
  }
  setOnChange(callback) {
      if (this.changeCallback === undefined) {
          this.changeCallback = callback;
      }
  }
}

class ArkComponent {
  constructor(nativePtr, classType) {
    this.nativePtr = nativePtr;
    this._changed = false;
    this._classType = classType;
    if (classType === ModifierType.FRAME_NODE) {
      this._modifiersWithKeys = new ObservedMap();
      this._modifiersWithKeys.setOnChange((key, value) => {
        if (this.nativePtr === undefined) {
          return;
        }
        value.applyStage(this.nativePtr);
        getUINativeModule().frameNode.propertyUpdate(this.nativePtr);
      })
    } else if (classType === ModifierType.EXPOSE_MODIFIER || classType === ModifierType.STATE) {
      this._modifiersWithKeys = new ObservedMap();
    } else {
      this._modifiersWithKeys = new Map();
    }
    if (classType === ModifierType.STATE) {
      this._weakPtr = getUINativeModule().nativeUtils.createNativeWeakRef(nativePtr);
    }
    this._nativePtrChanged = false;
  }
  setNodePtr(nodePtr) {
    this.nativePtr = nodePtr;
  }
  getOrCreateGestureEvent() {
    if (this._gestureEvent !== null) {
      this._gestureEvent = new UIGestureEvent();
      this._gestureEvent.setNodePtr(this.nativePtr);
    }
    return this._gestureEvent;
  }
  cleanStageValue(){
    if (!this._modifiersWithKeys){
      return;
    }
    this._modifiersWithKeys.forEach((value, key) => {
        value.stageValue = undefined;
    });
  }
  applyStateUpdatePtr(instance) {
    if (this.nativePtr !== instance.nativePtr) {
      this.nativePtr = instance.nativePtr;
      this._nativePtrChanged = true;
      this._weakPtr = getUINativeModule().nativeUtils.createNativeWeakRef(instance.nativePtr);
    }
  }
  applyModifierPatch() {
    let expiringItems = [];
    let expiringItemsWithKeys = [];
    this._modifiersWithKeys.forEach((value, key) => {
      if (value.applyStage(this.nativePtr)) {
        expiringItemsWithKeys.push(key);
      }
    });
    expiringItemsWithKeys.forEach(key => {
      this._modifiersWithKeys.delete(key);
    });
  }
  onGestureJudgeBegin(callback) {
    modifierWithKey(this._modifiersWithKeys, OnGestureJudgeBeginModifier.identity, OnGestureJudgeBeginModifier, callback);
    return this;
  }
  onSizeChange(callback) {
    modifierWithKey(this._modifiersWithKeys, OnSizeChangeModifier.identity, OnSizeChangeModifier, callback);
    return this;
  }
  outline(value) {
    modifierWithKey(this._modifiersWithKeys, OutlineModifier.identity, OutlineModifier, value);
    return this;
  }
  outlineColor(value) {
    modifierWithKey(this._modifiersWithKeys, OutlineColorModifier.identity, OutlineColorModifier, value);
    return this;
  }
  outlineRadius(value) {
    modifierWithKey(this._modifiersWithKeys, OutlineRadiusModifier.identity, OutlineRadiusModifier, value);
    return this;
  }
  outlineStyle(value) {
    modifierWithKey(this._modifiersWithKeys, OutlineStyleModifier.identity, OutlineStyleModifier, value);
    return this;
  }
  outlineWidth(value) {
    modifierWithKey(this._modifiersWithKeys, OutlineWidthModifier.identity, OutlineWidthModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, WidthModifier.identity, WidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, HeightModifier.identity, HeightModifier, value);
    return this;
  }
  expandSafeArea(types, edges) {
    let opts = new ArkSafeAreaExpandOpts();
    if (types && types.length > 0) {
      let safeAreaType = '';
      for (let param of types) {
        if (!isNumber(param) || param >= SAFE_AREA_TYPE_LIMIT) {
          safeAreaType = undefined;
          break;
        }
        if (safeAreaType) {
          safeAreaType += '|';
          safeAreaType += param.toString();
        }
        else {
          safeAreaType += param.toString();
        }
      }
      opts.type = safeAreaType;
    }
    if (edges && edges.length > 0) {
      let safeAreaEdge = '';
      for (let param of edges) {
        if (!isNumber(param) || param >= SAFE_AREA_EDGE_LIMIT) {
          safeAreaEdge = undefined;
          break;
        }
        if (safeAreaEdge) {
          safeAreaEdge += '|';
          safeAreaEdge += param.toString();
        }
        else {
          safeAreaEdge += param.toString();
        }
      }
      opts.edges = safeAreaEdge;
    }
    if (opts.type === undefined && opts.edges === undefined) {
      modifierWithKey(this._modifiersWithKeys, ExpandSafeAreaModifier.identity, ExpandSafeAreaModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, ExpandSafeAreaModifier.identity, ExpandSafeAreaModifier, opts);
    }
    return this;
  }
  backgroundEffect(options) {
    modifierWithKey(this._modifiersWithKeys, BackgroundEffectModifier.identity, BackgroundEffectModifier, options);
    return this;
  }
  backgroundBrightness(params) {
    modifierWithKey(this._modifiersWithKeys, BackgroundBrightnessModifier.identity, BackgroundBrightnessModifier, params);
    return this;
  }
  backgroundBrightnessInternal(params) {
    modifierWithKey(this._modifiersWithKeys, BackgroundBrightnessInternalModifier.identity, BackgroundBrightnessInternalModifier, params);
    return this;
  }
  foregroundBrightness(params) {
    modifierWithKey(this._modifiersWithKeys, ForegroundBrightnessModifier.identity, ForegroundBrightnessModifier, params);
     return this;
  }
  dragPreviewOptions(value) {
    modifierWithKey(this._modifiersWithKeys, DragPreviewOptionsModifier.identity, DragPreviewOptionsModifier, value);
    return this;
  }
  responseRegion(value) {
    modifierWithKey(this._modifiersWithKeys, ResponseRegionModifier.identity, ResponseRegionModifier, value);
    return this;
  }
  mouseResponseRegion(value) {
    modifierWithKey(this._modifiersWithKeys, MouseResponseRegionModifier.identity, MouseResponseRegionModifier, value);
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, SizeModifier.identity, SizeModifier, value);
    return this;
  }
  constraintSize(value) {
    modifierWithKey(this._modifiersWithKeys, ConstraintSizeModifier.identity, ConstraintSizeModifier, value);
    return this;
  }
  touchable(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, TouchableModifier.identity, TouchableModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TouchableModifier.identity, TouchableModifier, undefined);
    }
    return this;
  }
  hitTestBehavior(value) {
    if (value) {
      modifierWithKey(this._modifiersWithKeys, HitTestBehaviorModifier.identity, HitTestBehaviorModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, HitTestBehaviorModifier.identity, HitTestBehaviorModifier, undefined);
    }
    return this;
  }
  layoutWeight(value) {
    if (isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, LayoutWeightModifier.identity, LayoutWeightModifier, value);
    }
    else if (isString(value) && !isNaN(Number(value))) {
      modifierWithKey(this._modifiersWithKeys, LayoutWeightModifier.identity, LayoutWeightModifier, parseInt(value.toString()));
    }
    else {
      modifierWithKey(this._modifiersWithKeys, LayoutWeightModifier.identity, LayoutWeightModifier, undefined);
    }
    return this;
  }
  padding(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, PaddingModifier.identity, PaddingModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, PaddingModifier.identity, PaddingModifier, undefined);
    }
    return this;
  }
  margin(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, MarginModifier.identity, MarginModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, MarginModifier.identity, MarginModifier, undefined);
    }
    return this;
  }
  background(builder, options) {
    throw new Error('Method not implemented.');
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, BackgroundColorModifier.identity, BackgroundColorModifier, value);
    return this;
  }
  backgroundImage(src, repeat) {
    let arkBackgroundImage = new ArkBackgroundImage();
    arkBackgroundImage.src = src;
    arkBackgroundImage.repeat = repeat;
    modifierWithKey(this._modifiersWithKeys, BackgroundImageModifier.identity, BackgroundImageModifier, arkBackgroundImage);
    return this;
  }
  backgroundImageSize(value) {
    modifierWithKey(this._modifiersWithKeys, BackgroundImageSizeModifier.identity, BackgroundImageSizeModifier, value);
    return this;
  }
  backgroundImagePosition(value) {
    modifierWithKey(this._modifiersWithKeys, BackgroundImagePositionModifier.identity, BackgroundImagePositionModifier, value);
    return this;
  }
  backgroundImageResizable(value) {
    modifierWithKey(this._modifiersWithKeys, BackgroundImageResizableModifier.identity, BackgroundImageResizableModifier, value);
    return this;
  }
  backgroundBlurStyle(value, options) {
    if (isUndefined(value)) {
      modifierWithKey(this._modifiersWithKeys, BackgroundBlurStyleModifier.identity, BackgroundBlurStyleModifier, undefined);
      return this;
    }
    let arkBackgroundBlurStyle = new ArkBackgroundBlurStyle();
    arkBackgroundBlurStyle.blurStyle = value;
    if (typeof options === 'object') {
      arkBackgroundBlurStyle.colorMode = options.colorMode;
      arkBackgroundBlurStyle.adaptiveColor = options.adaptiveColor;
      arkBackgroundBlurStyle.scale = options.scale;
      arkBackgroundBlurStyle.blurOptions = options.blurOptions;
    }
    modifierWithKey(this._modifiersWithKeys, BackgroundBlurStyleModifier.identity, BackgroundBlurStyleModifier, arkBackgroundBlurStyle);
    return this;
  }
  foregroundBlurStyle(value, options) {
    if (isUndefined(value)) {
      modifierWithKey(this._modifiersWithKeys, ForegroundBlurStyleModifier.identity, ForegroundBlurStyleModifier, undefined);
      return this;
    }
    let arkForegroundBlurStyle = new ArkForegroundBlurStyle();
    arkForegroundBlurStyle.blurStyle = value;
    if (typeof options === 'object') {
      arkForegroundBlurStyle.colorMode = options.colorMode;
      arkForegroundBlurStyle.adaptiveColor = options.adaptiveColor;
      arkForegroundBlurStyle.scale = options.scale;
      arkForegroundBlurStyle.blurOptions = options.blurOptions;
    }
    modifierWithKey(this._modifiersWithKeys, ForegroundBlurStyleModifier.identity, ForegroundBlurStyleModifier, arkForegroundBlurStyle);
    return this;
  }
  opacity(value) {
    modifierWithKey(this._modifiersWithKeys, OpacityModifier.identity, OpacityModifier, value);
    return this;
  }
  border(value) {
    let _a, _b, _c, _d;
    let arkBorder = new ArkBorder();
    if (isUndefined(value)) {
      arkBorder = undefined;
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.width) && (value === null || value === void 0 ? void 0 : value.width) !== null) {
      if (isNumber(value.width) || isString(value.width) || isResource(value.width)) {
        arkBorder.arkWidth.left = value.width;
        arkBorder.arkWidth.right = value.width;
        arkBorder.arkWidth.top = value.width;
        arkBorder.arkWidth.bottom = value.width;
      }
      else {
        arkBorder.arkWidth.left = value.width.left;
        arkBorder.arkWidth.right = value.width.right;
        arkBorder.arkWidth.top = value.width.top;
        arkBorder.arkWidth.bottom = value.width.bottom;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.color) && (value === null || value === void 0 ? void 0 : value.color) !== null) {
      if (isNumber(value.color) || isString(value.color) || isResource(value.color)) {
        arkBorder.arkColor.leftColor = value.color;
        arkBorder.arkColor.rightColor = value.color;
        arkBorder.arkColor.topColor = value.color;
        arkBorder.arkColor.bottomColor = value.color;
      }
      else {
        arkBorder.arkColor.leftColor = value.color.left;
        arkBorder.arkColor.rightColor = value.color.right;
        arkBorder.arkColor.topColor = value.color.top;
        arkBorder.arkColor.bottomColor = value.color.bottom;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.radius) && (value === null || value === void 0 ? void 0 : value.radius) !== null) {
      if (isNumber(value.radius) || isString(value.radius) || isResource(value.radius)) {
        arkBorder.arkRadius.topLeft = value.radius;
        arkBorder.arkRadius.topRight = value.radius;
        arkBorder.arkRadius.bottomLeft = value.radius;
        arkBorder.arkRadius.bottomRight = value.radius;
      }
      else {
        arkBorder.arkRadius.topLeft = (_a = value.radius) === null || _a === void 0 ? void 0 : _a.topLeft;
        arkBorder.arkRadius.topRight = (_b = value.radius) === null || _b === void 0 ? void 0 : _b.topRight;
        arkBorder.arkRadius.bottomLeft = (_c = value.radius) === null || _c === void 0 ? void 0 : _c.bottomLeft;
        arkBorder.arkRadius.bottomRight = (_d = value.radius) === null || _d === void 0 ? void 0 : _d.bottomRight;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.style) && (value === null || value === void 0 ? void 0 : value.style) !== null) {
      let arkBorderStyle = new ArkBorderStyle();
      if (arkBorderStyle.parseBorderStyle(value.style)) {
        if (!isUndefined(arkBorderStyle.style)) {
          arkBorder.arkStyle.top = arkBorderStyle.style;
          arkBorder.arkStyle.left = arkBorderStyle.style;
          arkBorder.arkStyle.bottom = arkBorderStyle.style;
          arkBorder.arkStyle.right = arkBorderStyle.style;
        }
        else {
          arkBorder.arkStyle.top = arkBorderStyle.top;
          arkBorder.arkStyle.left = arkBorderStyle.left;
          arkBorder.arkStyle.bottom = arkBorderStyle.bottom;
          arkBorder.arkStyle.right = arkBorderStyle.right;
        }
      }
    }
    modifierWithKey(this._modifiersWithKeys, BorderModifier.identity, BorderModifier, arkBorder);
    return this;
  }
  borderStyle(value) {
    modifierWithKey(this._modifiersWithKeys, BorderStyleModifier.identity, BorderStyleModifier, value);
    return this;
  }
  borderWidth(value) {
    modifierWithKey(this._modifiersWithKeys, BorderWidthModifier.identity, BorderWidthModifier, value);
    return this;
  }
  borderColor(value) {
    modifierWithKey(this._modifiersWithKeys, BorderColorModifier.identity, BorderColorModifier, value);
    return this;
  }
  borderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, BorderRadiusModifier.identity, BorderRadiusModifier, value);
    return this;
  }
  borderImage(value) {
    modifierWithKey(this._modifiersWithKeys, BorderImageModifier.identity, BorderImageModifier, value);
    return this;
  }
  foregroundEffect(value) {
    modifierWithKey(this._modifiersWithKeys, ForegroundEffectModifier.identity, ForegroundEffectModifier, value);
    return this;
  }
  foregroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, ForegroundColorModifier.identity, ForegroundColorModifier, value);
    return this;
  }
  onClick(event) {
    modifierWithKey(this._modifiersWithKeys, ClickModifier.identity, ClickModifier, event);
    return this;
  }
  onHover(event) {
    modifierWithKey(this._modifiersWithKeys, OnHoverModifier.identity, OnHoverModifier, event);
    return this;
  }
  hoverEffect(value) {
    modifierWithKey(this._modifiersWithKeys, HoverEffectModifier.identity, HoverEffectModifier, value);
    return this;
  }
  onMouse(event) {
    modifierWithKey(this._modifiersWithKeys, OnMouseModifier.identity, OnMouseModifier, event);
    return this;
  }
  onTouch(event) {
    modifierWithKey(this._modifiersWithKeys, OnTouchModifier.identity, OnTouchModifier, event);
    return this;
  }
  onKeyEvent(event) {
    modifierWithKey(this._modifiersWithKeys, OnKeyEventModifier.identity, OnKeyEventModifier, event);
    return this;
  }
  focusable(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, FocusableModifier.identity, FocusableModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, FocusableModifier.identity, FocusableModifier, undefined);
    }
    return this;
  }
  onFocus(event) {
    modifierWithKey(this._modifiersWithKeys, OnFocusModifier.identity, OnFocusModifier, event);
    return this;
  }
  onBlur(event) {
    modifierWithKey(this._modifiersWithKeys, OnBlurModifier.identity, OnBlurModifier, event);
    return this;
  }
  tabIndex(index) {
    if (typeof index !== 'number') {
      modifierWithKey(this._modifiersWithKeys, TabIndexModifier.identity, TabIndexModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TabIndexModifier.identity, TabIndexModifier, index);
    }
    return this;
  }
  defaultFocus(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, DefaultFocusModifier.identity, DefaultFocusModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, DefaultFocusModifier.identity, DefaultFocusModifier, undefined);
    }
    return this;
  }
  groupDefaultFocus(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, GroupDefaultFocusModifier.identity, GroupDefaultFocusModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, GroupDefaultFocusModifier.identity, GroupDefaultFocusModifier, undefined);
    }
    return this;
  }
  focusOnTouch(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, FocusOnTouchModifier.identity, FocusOnTouchModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, FocusOnTouchModifier.identity, FocusOnTouchModifier, undefined);
    }
    return this;
  }
  animation(value) {
    throw new Error('Method not implemented.');
  }
  transition(value) {
    modifierWithKey(this._modifiersWithKeys, TransitionModifier.identity, TransitionModifier, value);
    return this;
  }
  gesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  priorityGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  parallelGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  blur(value, options) {
    let blur = new ArkBlurOptions();
    blur.value = value;
    blur.options = options;
    modifierWithKey(this._modifiersWithKeys, BlurModifier.identity, BlurModifier, blur);
    return this;
  }
  linearGradientBlur(value, options) {
    if (isUndefined(value) || isNull(value) || isUndefined(options) || isNull(options)) {
      modifierWithKey(this._modifiersWithKeys, LinearGradientBlurModifier.identity, LinearGradientBlurModifier, undefined);
      return this;
    }
    let arkLinearGradientBlur = new ArkLinearGradientBlur();
    arkLinearGradientBlur.blurRadius = value;
    arkLinearGradientBlur.fractionStops = options.fractionStops;
    arkLinearGradientBlur.direction = options.direction;
    modifierWithKey(this._modifiersWithKeys, LinearGradientBlurModifier.identity, LinearGradientBlurModifier, arkLinearGradientBlur);
    return this;
  }
  brightness(value) {
    if (!isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, BrightnessModifier.identity, BrightnessModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, BrightnessModifier.identity, BrightnessModifier, value);
    }
    return this;
  }
  contrast(value) {
    if (!isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, ContrastModifier.identity, ContrastModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, ContrastModifier.identity, ContrastModifier, value);
    }
    return this;
  }
  grayscale(value) {
    if (!isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, GrayscaleModifier.identity, GrayscaleModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, GrayscaleModifier.identity, GrayscaleModifier, value);
    }
    return this;
  }
  colorBlend(value) {
    modifierWithKey(this._modifiersWithKeys, ColorBlendModifier.identity, ColorBlendModifier, value);
    return this;
  }
  saturate(value) {
    if (!isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, SaturateModifier.identity, SaturateModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, SaturateModifier.identity, SaturateModifier, value);
    }
    return this;
  }
  sepia(value) {
    if (!isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, SepiaModifier.identity, SepiaModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, SepiaModifier.identity, SepiaModifier, value);
    }
    return this;
  }
  invert(value) {
    if (!isUndefined(value)) {
      modifierWithKey(this._modifiersWithKeys, InvertModifier.identity, InvertModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, InvertModifier.identity, InvertModifier, undefined);
    }
    return this;
  }
  hueRotate(value) {
    if (!isNumber(value) && !isString(value)) {
      modifierWithKey(this._modifiersWithKeys, HueRotateModifier.identity, HueRotateModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, HueRotateModifier.identity, HueRotateModifier, value);
    }
    return this;
  }
  useEffect(value) {
    modifierWithKey(this._modifiersWithKeys, UseEffectModifier.identity, UseEffectModifier, value);
    return this;
  }
  backdropBlur(value, options) {
    let blur = new ArkBlurOptions();
    blur.value = value;
    blur.options = options;
    modifierWithKey(this._modifiersWithKeys, BackdropBlurModifier.identity, BackdropBlurModifier, blur);
    return this;
  }
  renderGroup(value) {
    modifierWithKey(this._modifiersWithKeys, RenderGroupModifier.identity, RenderGroupModifier, value);
    return this;
  }
  translate(value) {
    modifierWithKey(this._modifiersWithKeys, TranslateModifier.identity, TranslateModifier, value);
    return this;
  }
  scale(value) {
    modifierWithKey(this._modifiersWithKeys, ScaleModifier.identity, ScaleModifier, value);
    return this;
  }
  gridSpan(value) {
    if (isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, GridSpanModifier.identity, GridSpanModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, GridSpanModifier.identity, GridSpanModifier, undefined);
    }
    return this;
  }
  gridOffset(value) {
    if (isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, GridOffsetModifier.identity, GridOffsetModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, GridOffsetModifier.identity, GridOffsetModifier, undefined);
    }
    return this;
  }
  rotate(value) {
    modifierWithKey(this._modifiersWithKeys, RotateModifier.identity, RotateModifier, value);
    return this;
  }
  transform(value) {
    modifierWithKey(this._modifiersWithKeys, TransformModifier.identity, TransformModifier, value);
    return this;
  }
  onAppear(event) {
    modifierWithKey(this._modifiersWithKeys, OnAppearModifier.identity, OnAppearModifier, event);
    return this;
  }
  onDisAppear(event) {
    modifierWithKey(this._modifiersWithKeys, OnDisappearModifier.identity, OnDisappearModifier, event);
    return this;
  }
  onAttach(event) {
    modifierWithKey(this._modifiersWithKeys, OnAttachModifier.identity, OnAttachModifier, event);
    return this;
  }
  onDetach(event) {
    modifierWithKey(this._modifiersWithKeys, OnDetachModifier.identity, OnDetachModifier, event);
    return this;
  }
  onAreaChange(event) {
    modifierWithKey(this._modifiersWithKeys, OnAreaChangeModifier.identity, OnAreaChangeModifier, event);
    return this;
  }
  visibility(value) {
    modifierWithKey(this._modifiersWithKeys, VisibilityModifier.identity, VisibilityModifier, value);
    return this;
  }
  flexGrow(value) {
    modifierWithKey(this._modifiersWithKeys, FlexGrowModifier.identity, FlexGrowModifier, value);
    return this;
  }
  flexShrink(value) {
    modifierWithKey(this._modifiersWithKeys, FlexShrinkModifier.identity, FlexShrinkModifier, value);
    return this;
  }
  flexBasis(value) {
    modifierWithKey(this._modifiersWithKeys, FlexBasisModifier.identity, FlexBasisModifier, value);
    return this;
  }
  alignSelf(value) {
    modifierWithKey(this._modifiersWithKeys, AlignSelfModifier.identity, AlignSelfModifier, value);
    return this;
  }
  displayPriority(value) {
    modifierWithKey(this._modifiersWithKeys, DisplayPriorityModifier.identity, DisplayPriorityModifier, value);
    return this;
  }
  zIndex(value) {
    if (value !== null) {
      let zIndex = 0;
      if (typeof (value) === 'number') {
        zIndex = value;
      }
      modifierWithKey(this._modifiersWithKeys, ZIndexModifier.identity, ZIndexModifier, zIndex);
    }
    return this;
  }
  sharedTransition(id, options) {
    let arkSharedTransition = new ArkSharedTransition();
    if (isString(id)) {
      arkSharedTransition.id = id;
    }
    if (typeof options === 'object') {
      arkSharedTransition.options = options;
    }
    modifierWithKey(this._modifiersWithKeys, SharedTransitionModifier.identity, SharedTransitionModifier, arkSharedTransition);
    return this;
  }
  direction(value) {
    modifierWithKey(this._modifiersWithKeys, DirectionModifier.identity, DirectionModifier, value);
    return this;
  }
  align(value) {
    if (isNumber(value)) {
      modifierWithKey(this._modifiersWithKeys, AlignModifier.identity, AlignModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, AlignModifier.identity, AlignModifier, undefined);
    }
    return this;
  }
  position(value) {
    if (isObject(value)) {
      modifierWithKey(this._modifiersWithKeys, PositionModifier.identity, PositionModifier, value);
    } else {
      modifierWithKey(this._modifiersWithKeys, PositionModifier.identity, PositionModifier, undefined);
    }
    return this;
  }
  markAnchor(value) {
    modifierWithKey(this._modifiersWithKeys, MarkAnchorModifier.identity, MarkAnchorModifier, value);
    return this;
  }
  offset(value) {
    if (isObject(value)) {
      modifierWithKey(this._modifiersWithKeys, OffsetModifier.identity, OffsetModifier, value);
    } else {
      modifierWithKey(this._modifiersWithKeys, OffsetModifier.identity, OffsetModifier, undefined);
    }
    return this;
  }
  enabled(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, EnabledModifier.identity, EnabledModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, EnabledModifier.identity, EnabledModifier, undefined);
    }
    return this;
  }
  useShadowBatching(value) {
    modifierWithKey(this._modifiersWithKeys, UseShadowBatchingModifier.identity, UseShadowBatchingModifier, value);
    return this;
  }
  monopolizeEvents(value) {
    modifierWithKey(this._modifiersWithKeys, MonopolizeEventsModifier.identity, MonopolizeEventsModifier, value);
    return this;
  }
  useSizeType(value) {
    throw new Error('Method not implemented.');
  }
  alignRules(value) {
    if (!isObject(value) || JSON.stringify(value) === '{}') {
      modifierWithKey(this._modifiersWithKeys, AlignRulesModifier.identity, AlignRulesModifier, undefined);
      return this;
    }
    let keys = ['left', 'middle', 'right', 'top', 'center', 'bottom'];
    let arkValue = new ArkAlignRules();
    for (let i = 0; i < keys.length; i++) {
      let rule = value[keys[i]];
      let alignRule = '';
      if (isObject(rule)) {
        let alignSign = false;
        let anchorSign = false;
        let align = rule.align;
        let anchor = rule.anchor;
        if (isString(anchor)) {
          anchorSign = true;
        }
        if (i < DIRECTION_RANGE) {
          if (align in HorizontalAlign) {
            alignSign = true;
          }
        }
        else {
          if (align in VerticalAlign) {
            alignSign = true;
          }
        }
        if (!alignSign && !anchorSign) {
          alignRule += '';
        }
        else if (!anchorSign) {
          alignRule += align.toString();
          alignRule += '|';
          alignRule += '__container__';
        }
        else if (!alignSign) {
          alignRule += '2';
          alignRule += '|';
          alignRule += anchor;
        }
        else {
          alignRule += align.toString();
          alignRule += '|';
          alignRule += anchor;
        }
      }
      else {
        alignRule += '';
      }
      switch (keys[i]) {
        case 'left':
          arkValue.left = alignRule;
          break;
        case 'middle':
          arkValue.middle = alignRule;
          break;
        case 'right':
          arkValue.right = alignRule;
          break;
        case 'top':
          arkValue.top = alignRule;
          break;
        case 'center':
          arkValue.center = alignRule;
          break;
        case 'bottom':
          arkValue.bottom = alignRule;
          break;
      }
    }
    modifierWithKey(this._modifiersWithKeys, AlignRulesModifier.identity, AlignRulesModifier, arkValue);
    return this;
  }
  aspectRatio(value) {
    modifierWithKey(this._modifiersWithKeys, AspectRatioModifier.identity, AspectRatioModifier, value);
    return this;
  }
  clickEffect(value) {
    modifierWithKey(this._modifiersWithKeys, ClickEffectModifier.identity, ClickEffectModifier, value);
    return this;
  }
  onDragStart(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnter(event) {
    throw new Error('Method not implemented.');
  }
  onDragMove(event) {
    throw new Error('Method not implemented.');
  }
  onDragLeave(event) {
    throw new Error('Method not implemented.');
  }
  onDrop(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnd(event) {
    throw new Error('Method not implemented.');
  }
  allowDrop(value) {
    modifierWithKey(this._modifiersWithKeys, AllowDropModifier.identity, AllowDropModifier, value);
    return this;
  }
  draggable(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, DraggableModifier.identity, DraggableModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, DraggableModifier.identity, DraggableModifier, undefined);
    }
    return this;
  }
  overlay(value, options) {
    if (typeof value === 'undefined') {
      modifierWithKey(this._modifiersWithKeys, OverlayModifier.identity, OverlayModifier, undefined);
      return this;
    }
    let arkOverlay = new ArkOverlay();
    if (arkOverlay.splitOverlayValue(value, options)) {
      modifierWithKey(this._modifiersWithKeys, OverlayModifier.identity, OverlayModifier, arkOverlay);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, OverlayModifier.identity, OverlayModifier, undefined);
    }
    return this;
  }
  linearGradient(value) {
    modifierWithKey(this._modifiersWithKeys, LinearGradientModifier.identity, LinearGradientModifier, value);
    return this;
  }
  sweepGradient(value) {
    modifierWithKey(this._modifiersWithKeys, SweepGradientModifier.identity, SweepGradientModifier, value);
    return this;
  }
  radialGradient(value) {
    modifierWithKey(this._modifiersWithKeys, RadialGradientModifier.identity, RadialGradientModifier, value);
    return this;
  }
  motionPath(value) {
    modifierWithKey(this._modifiersWithKeys, MotionPathModifier.identity, MotionPathModifier, value);
    return this;
  }
  motionBlur(value) {
    modifierWithKey(this._modifiersWithKeys, MotionBlurModifier.identity, MotionBlurModifier, value);
    return this;
  }
  shadow(value) {
    modifierWithKey(this._modifiersWithKeys, ShadowModifier.identity, ShadowModifier, value);
    return this;
  }
  mask(value) {
    modifierWithKey(this._modifiersWithKeys, MaskModifier.identity, MaskModifier, value);
    return this;
  }
  key(value) {
    if (typeof value === 'string') {
      modifierWithKey(this._modifiersWithKeys, KeyModifier.identity, KeyModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, KeyModifier.identity, KeyModifier, undefined);
    }
    return this;
  }
  id(value) {
    if (typeof value === 'string') {
      modifierWithKey(this._modifiersWithKeys, IdModifier.identity, IdModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, IdModifier.identity, IdModifier, undefined);
    }
    return this;
  }
  geometryTransition(id, options) {
    let arkGeometryTransition = new ArkGeometryTransition();
    arkGeometryTransition.id = id;
    arkGeometryTransition.options = options;
    modifierWithKey(this._modifiersWithKeys, GeometryTransitionModifier.identity, GeometryTransitionModifier, arkGeometryTransition);
    return this;
  }
  bindPopup(show, popup) {
    throw new Error('Method not implemented.');
  }
  bindMenu(content, options) {
    throw new Error('Method not implemented.');
  }
  bindContextMenu(content, responseType, options) {
    throw new Error('Method not implemented.');
  }
  bindContentCover(isShow, builder, type) {
    throw new Error('Method not implemented.');
  }
  blendMode(blendMode, blendApplyType) {
    let arkBlendMode = new ArkBlendMode();
    arkBlendMode.blendMode = blendMode;
    arkBlendMode.blendApplyType = blendApplyType;
    modifierWithKey(this._modifiersWithKeys, BlendModeModifier.identity, BlendModeModifier, arkBlendMode);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, ClipModifier.identity, ClipModifier, value);
    return this;
  }
  bindSheet(isShow, builder, options) {
    throw new Error('Method not implemented.');
  }
  stateStyles(value) {
    throw new Error('Method not implemented.');
  }
  restoreId(value) {
    if (typeof value !== 'number') {
      modifierWithKey(this._modifiersWithKeys, RestoreIdModifier.identity, RestoreIdModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, RestoreIdModifier.identity, RestoreIdModifier, value);
    }
    return this;
  }
  onVisibleAreaChange(ratios, event) {
    throw new Error('Method not implemented.');
  }
  sphericalEffect(value) {
    modifierWithKey(this._modifiersWithKeys, SphericalEffectModifier.identity, SphericalEffectModifier, value);
    return this;
  }
  lightUpEffect(value) {
    modifierWithKey(this._modifiersWithKeys, LightUpEffectModifier.identity, LightUpEffectModifier, value);
    return this;
  }
  pixelStretchEffect(options) {
    modifierWithKey(this._modifiersWithKeys, PixelStretchEffectModifier.identity, PixelStretchEffectModifier, options);
    return this;
  }
  keyboardShortcut(value, keys, action) {
    let keyboardShortCut = new ArkKeyBoardShortCut();
    keyboardShortCut.value = value;
    keyboardShortCut.keys = keys;
    modifierWithKey(this._modifiersWithKeys, KeyBoardShortCutModifier.identity, KeyBoardShortCutModifier, keyboardShortCut);
    return this;
  }
  accessibilityGroup(value) {
    if (typeof value === 'boolean') {
      modifierWithKey(this._modifiersWithKeys, AccessibilityGroupModifier.identity, AccessibilityGroupModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, AccessibilityGroupModifier.identity, AccessibilityGroupModifier, undefined);
    }
    return this;
  }
  accessibilityText(value) {
    if (typeof value === 'string') {
      modifierWithKey(this._modifiersWithKeys, AccessibilityTextModifier.identity, AccessibilityTextModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, AccessibilityTextModifier.identity, AccessibilityTextModifier, undefined);
    }
    return this;
  }
  accessibilityDescription(value) {
    if (typeof value !== 'string') {
      modifierWithKey(this._modifiersWithKeys, AccessibilityDescriptionModifier.identity, AccessibilityDescriptionModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, AccessibilityDescriptionModifier.identity, AccessibilityDescriptionModifier, value);
    }
    return this;
  }
  accessibilityLevel(value) {
    if (typeof value !== 'string') {
      modifierWithKey(this._modifiersWithKeys, AccessibilityLevelModifier.identity, AccessibilityLevelModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, AccessibilityLevelModifier.identity, AccessibilityLevelModifier, value);
    }
    return this;
  }
  obscured(reasons) {
    modifierWithKey(this._modifiersWithKeys, ObscuredModifier.identity, ObscuredModifier, reasons);
    return this;
  }
  reuseId(id) {
    throw new Error('Method not implemented.');
  }
  renderFit(fitMode) {
    modifierWithKey(this._modifiersWithKeys, RenderFitModifier.identity, RenderFitModifier, fitMode);
    return this;
  }
  attributeModifier(modifier) {
    return this;
  }
  customProperty(key, value) {
    const property = new ArkCustomProperty();
    property.key = key;
    property.value = value;
    modifierWithKey(this._modifiersWithKeys, CustomPropertyModifier.identity, CustomPropertyModifier, property);
    return this;
  }
}
const isNull = (val) => typeof val === 'object' && val === null;
const isArray = (val) => Array.isArray(val);
const isDate = (val) => val instanceof Date;
const isRegExp = (val) => val instanceof RegExp;
const isError = (val) => val instanceof Error;
const isFloat = (val) => Number.isFinite(val) && !Number.isInteger(val);
const isInteger = (val) => Number.isInteger(val);
const isNonEmptyMap = (val) => val instanceof Map && val.size > 0;
const isTruthyString = (val) => typeof val === 'string' && val.trim() !== '';

var CommonGestureType;
(function (CommonGestureType) {
    CommonGestureType[CommonGestureType["TAP_GESTURE"] = 0] = "TAP_GESTURE";
    CommonGestureType[CommonGestureType["LONG_PRESS_GESTURE"] = 1] = "LONG_PRESS_GESTURE";
    CommonGestureType[CommonGestureType["PAN_GESTURE"] = 2] = "PAN_GESTURE";
    CommonGestureType[CommonGestureType["SWIPE_GESTURE"] = 3] = "SWIPE_GESTURE";
    CommonGestureType[CommonGestureType["PINCH_GESTURE"] = 4] = "PINCH_GESTURE";
    CommonGestureType[CommonGestureType["ROTATION_GESTURE"] = 5] = "ROTATION_GESTURE";
    CommonGestureType[CommonGestureType["GESTURE_GROUP"] = 6] = "GESTURE_GROUP";
})(CommonGestureType || (CommonGestureType = {}));

class GestureHandler {
  constructor(gestureType) {
    this.gestureType = gestureType;
  }
}

class TapGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.TAP_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.count = options.count;
    }
  }
  onAction(event) {
    this.onActionCallback = event;
    return this;
  }
  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class LongPressGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.LONG_PRESS_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.repeat = options.repeat;
      this.duration = options.duration;
    }
  }

  onAction(event) {
    this.onActionCallback = event;
    return this;
  }

  onActionEnd(event) {
    this.onActionEndCallback = event;
    return this;
  }

  onActionCancel(event) {
    this.onActionCancelCallback = event;
    return this;
  }

  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class PanGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.PAN_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.direction = options.direction;
      this.distance = options.distance;
    }
  }

  onActionStart(event) {
    this.onActionStartCallback = event;
    return this;
  }

  onActionUpdate(event) {
    this.onActionUpdateCallback = event;
    return this;
  }

  onActionEnd(event) {
    this.onActionEndCallback = event;
    return this;
  }

  onActionCancel(event) {
    this.onActionCancelCallback = event;
    return this;
  }

  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class SwipeGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.SWIPE_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.direction = options.direction;
      this.speed = options.speed;
    }
  }

  onAction(event) {
    this.onActionCallback = event;
    return this;
  }

  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class PinchGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.PINCH_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.distance = options.distance;
    }
  }

  onActionStart(event) {
    this.onActionStartCallback = event;
    return this;
  }

  onActionUpdate(event) {
    this.onActionUpdateCallback = event;
    return this;
  }

  onActionEnd(event) {
    this.onActionEndCallback = event;
    return this;
  }

  onActionCancel(event) {
    this.onActionCancelCallback = event;
    return this;
  }

  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class RotationGestureHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.ROTATION_GESTURE);
    if (options !== undefined) {
      this.fingers = options.fingers;
      this.angle = options.angle;
    }
  }

  onActionStart(event) {
    this.onActionStartCallback = event;
    return this;
  }

  onActionUpdate(event) {
    this.onActionUpdateCallback = event;
    return this;
  }

  onActionEnd(event) {
    this.onActionEndCallback = event;
    return this;
  }

  onActionCancel(event) {
    this.onActionCancelCallback = event;
    return this;
  }

  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class GestureGroupHandler extends GestureHandler {
  constructor(options) {
    super(CommonGestureType.GESTURE_GROUP);
    if (options !== undefined) {
      this.mode = options.mode;
      this.gestures = options.gestures;
    }
  }
  
  onCancel(event) {
    this.onCancelCallback = event;
    return this;
  }
  
  tag(tag) {
    this.gestureTag = tag;
    return this;
  }
}

class UICommonEvent {
  setInstanceId(instanceId) {
    this._instanceId = instanceId;
  }
  setNodePtr(nodePtr) {
    this._nodePtr = nodePtr;
  }
  // the first param is used to indicate frameNode
  // the second param is used to indicate the callback 
  // the third param is used to indicate the instanceid
  // other options will be indicated after them
  setOnClick(callback) {
    this._clickEvent = callback;
    getUINativeModule().frameNode.setOnClick(this._nodePtr, callback, this._instanceId);
  }
  setOnTouch(callback) {
    this._touchEvent = callback;
    getUINativeModule().frameNode.setOnTouch(this._nodePtr, callback, this._instanceId);
  }
  setOnAppear(callback) {
    this._onAppearEvent = callback;
    getUINativeModule().frameNode.setOnAppear(this._nodePtr, callback, this._instanceId);
  }
  setOnDisappear(callback) {
    this._onDisappearEvent = callback;
    getUINativeModule().frameNode.setOnDisappear(this._nodePtr, callback, this._instanceId);
  }
  setOnAttach(callback) {
    this._onAttachEvent = callback;
    getUINativeModule().frameNode.setOnAttach(this._nodePtr, callback, this._instanceId);
  }
  setOnDetach(callback) {
    this._onDetachEvent = callback;
    getUINativeModule().frameNode.setOnDetach(this._nodePtr, callback, this._instanceId);
  }
  setOnKeyEvent(callback) {
    this._onKeyEvent = callback;
    getUINativeModule().frameNode.setOnKeyEvent(this._nodePtr, callback, this._instanceId);
  }
  setOnFocus(callback) {
    this._onFocusEvent = callback;
    getUINativeModule().frameNode.setOnFocus(this._nodePtr, callback, this._instanceId);
  }
  setOnBlur(callback) {
    this._onBlur = callback;
    getUINativeModule().frameNode.setOnBlur(this._nodePtr, callback, this._instanceId);
  }
  setOnHover(callback) {
    this._onHoverEvent = callback;
    getUINativeModule().frameNode.setOnHover(this._nodePtr, callback, this._instanceId);
  }
  setOnMouse(callback) {
    this._onMouseEvent = callback;
    getUINativeModule().frameNode.setOnMouse(this._nodePtr, callback, this._instanceId);
  }
  setOnSizeChange(callback) {
    this._onSizeChangeEvent = callback;
    getUINativeModule().frameNode.setOnSizeChange(this._nodePtr, callback, this._instanceId);
  }
  setOnVisibleAreaApproximateChange(options, callback) {
    this._onVisibleAreaApproximateChange = callback;
    getUINativeModule().frameNode.setOnVisibleAreaApproximateChange(this._nodePtr, callback, this._instanceId, options.ratios, options.expectedUpdateInterval ? options.expectedUpdateInterval : 1000);
  }
}

function attributeModifierFunc(modifier, componentBuilder, modifierBuilder) {
  if (modifier === undefined || modifier === null) {
    return;
  }
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return componentBuilder(nativeNode);
  });
  if (modifier.isAttributeUpdater === true) {
    let modifierJS = globalThis.requireNapi('arkui.modifier');
    if (modifier.modifierState === modifierJS.AttributeUpdater.StateEnum.INIT) {
      modifier.modifierState = modifierJS.AttributeUpdater.StateEnum.UPDATE;
      modifier.attribute = modifierBuilder(nativeNode, ModifierType.STATE, modifierJS);
      modifierJS.ModifierUtils.applySetOnChange(modifier.attribute);
      modifier.initializeModifier(modifier.attribute);
      applyUIAttributesInit(modifier, nativeNode, component);
      component.applyModifierPatch();
    } else {
      modifier.attribute.applyStateUpdatePtr(component);
      modifier.attribute.applyNormalAttribute(component);
      applyUIAttributes(modifier, nativeNode, component);
      component.applyModifierPatch();
    }
  } else {
    applyUIAttributes(modifier, nativeNode, component);
    component.applyModifierPatch();
  }
}

function attributeModifierFuncWithoutStateStyles(modifier, componentBuilder, modifierBuilder) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return componentBuilder(nativeNode);
  });
  if (modifier.isAttributeUpdater === true) {
    let modifierJS = globalThis.requireNapi('arkui.modifier');
    if (modifier.modifierState === modifierJS.AttributeUpdater.StateEnum.INIT) {
      modifier.modifierState = modifierJS.AttributeUpdater.StateEnum.UPDATE;
      modifier.attribute = modifierBuilder(nativeNode, ModifierType.STATE, modifierJS);
      modifierJS.ModifierUtils.applySetOnChange(modifier.attribute);
      modifier.initializeModifier(modifier.attribute);
      component.applyModifierPatch();
    } else {
      modifier.attribute.applyStateUpdatePtr(component);
      modifier.attribute.applyNormalAttribute(component);
      if (modifier.applyNormalAttribute) {
        modifier.applyNormalAttribute(component);
      }
      component.applyModifierPatch();
    }
  } else {
    if (modifier.applyNormalAttribute) {
      modifier.applyNormalAttribute(component);
    }
    component.applyModifierPatch();
  }
}

class UIGestureEvent {
  setNodePtr(nodePtr) {
    this._nodePtr = nodePtr;
  }
  addGesture(gesture, priority, mask) {
    switch (gesture.gestureType) {
      case CommonGestureType.TAP_GESTURE: {
        let tapGesture = gesture;
        getUINativeModule().common.addTapGesture(this._nodePtr, priority, mask, tapGesture.gestureTag,
          tapGesture.fingers, tapGesture.count, tapGesture.onActionCallback);
        break;
      }
      case CommonGestureType.LONG_PRESS_GESTURE: {
        let longPressGesture = gesture;
        getUINativeModule().common.addLongPressGesture(this._nodePtr, priority, mask, longPressGesture.gestureTag,
          longPressGesture.fingers, longPressGesture.repeat, longPressGesture.duration,
          longPressGesture.onActionCallback, longPressGesture.onActionEndCallback, longPressGesture.onActionCancelCallback);
        break;
      }
      case CommonGestureType.PAN_GESTURE: {
        let panGesture = gesture;
        getUINativeModule().common.addPanGesture(this._nodePtr, priority, mask, panGesture.gestureTag,
          panGesture.fingers, panGesture.direction, panGesture.distance, panGesture.onActionStartCallback,
          panGesture.onActionUpdateCallback, panGesture.onActionEndCallback, panGesture.onActionCancelCallback);
        break;
      }
      case CommonGestureType.SWIPE_GESTURE: {
        let swipeGesture = gesture;
        getUINativeModule().common.addSwipeGesture(this._nodePtr, priority, mask, swipeGesture.gestureTag,
          swipeGesture.fingers, swipeGesture.direction, swipeGesture.speed, swipeGesture.onActionCallback);
        break;
      }
      case CommonGestureType.PINCH_GESTURE: {
        let pinchGesture = gesture;
        getUINativeModule().common.addPinchGesture(this._nodePtr, priority, mask, pinchGesture.gestureTag,
          pinchGesture.fingers, pinchGesture.distance, pinchGesture.onActionStartCallback,
          pinchGesture.onActionUpdateCallback, pinchGesture.onActionEndCallback, pinchGesture.onActionCancelCallback);
        break;
      }
      case CommonGestureType.ROTATION_GESTURE: {
        let rotationGesture = gesture;
        getUINativeModule().common.addRotationGesture(this._nodePtr, priority, mask, rotationGesture.gestureTag,
          rotationGesture.fingers, rotationGesture.angle, rotationGesture.onActionStartCallback,
          rotationGesture.onActionUpdateCallback, rotationGesture.onActionEndCallback,
          rotationGesture.onActionCancelCallback);
        break;
      }
      case CommonGestureType.GESTURE_GROUP: {
        let gestureGroup = gesture;
        let groupPtr = getUINativeModule().common.addGestureGroup(
          gestureGroup.gestureTag, gestureGroup.onCancelCallback, gestureGroup.mode);
        gestureGroup.gestures.forEach((item) => {
          addGestureToGroup(item, groupPtr);
        });
        getUINativeModule().common.attachGestureGroup(this._nodePtr, priority, mask, groupPtr);
        break;
      }
      default:
        break;
    }
  }
  addParallelGesture(gesture, mask) {
    this.addGesture(gesture, GesturePriority.PARALLEL, mask);
  }
  removeGestureByTag(tag) {
    getUINativeModule().common.removeGestureByTag(this._nodePtr, tag);
  }
  clearGestures() {
    getUINativeModule().common.clearGestures(this._nodePtr);
  }
}

function addGestureToGroup(gesture, gestureGroupPtr) {
  switch (gesture.gestureType) {
    case CommonGestureType.TAP_GESTURE: {
      let tapGesture = gesture;
      getUINativeModule().common.addTapGestureToGroup(tapGesture.gestureTag,
        tapGesture.fingers, tapGesture.count, tapGesture.onActionCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.LONG_PRESS_GESTURE: {
      let longPressGesture = gesture;
      getUINativeModule().common.addLongPressGestureToGroup(longPressGesture.gestureTag,
        longPressGesture.fingers, longPressGesture.repeat, longPressGesture.duration,
        longPressGesture.onActionCallback, longPressGesture.onActionEndCallback, longPressGesture.onActionCancelCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.PAN_GESTURE: {
      let panGesture = gesture;
      getUINativeModule().common.addPanGestureToGroup(panGesture.gestureTag,
        panGesture.fingers, panGesture.direction, panGesture.distance, panGesture.onActionStartCallback,
        panGesture.onActionUpdateCallback, panGesture.onActionEndCallback, panGesture.onActionCancelCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.SWIPE_GESTURE: {
      let swipeGesture = gesture;
      getUINativeModule().common.addSwipeGestureToGroup(swipeGesture.gestureTag,
        swipeGesture.fingers, swipeGesture.direction, swipeGesture.speed, swipeGesture.onActionCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.PINCH_GESTURE: {
      let pinchGesture = gesture;
      getUINativeModule().common.addPinchGestureToGroup(pinchGesture.gestureTag,
        pinchGesture.fingers, pinchGesture.distance, pinchGesture.onActionStartCallback,
        pinchGesture.onActionUpdateCallback, pinchGesture.onActionEndCallback, pinchGesture.onActionCancelCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.ROTATION_GESTURE: {
      let rotationGesture = gesture;
      getUINativeModule().common.addRotationGestureToGroup(rotationGesture.gestureTag,
        rotationGesture.fingers, rotationGesture.angle, rotationGesture.onActionStartCallback,
        rotationGesture.onActionUpdateCallback, rotationGesture.onActionEndCallback,
        rotationGesture.onActionCancelCallback, gestureGroupPtr);
      break;
    }
    case CommonGestureType.GESTURE_GROUP: {
      let gestureGroup = gesture;
      let groupPtr = getUINativeModule().common.addGestureGroupToGroup(
        gestureGroup.gestureTag, gestureGroup.onCancelCallback, gestureGroup.mode, gestureGroupPtr);
        gestureGroup.gestures.forEach((item) => {
          addGestureToGroup(item, groupPtr);
        });
      break;
    }
    default:
      break;
  }
}

function applyGesture(modifier, component) {
  if (modifier.applyGesture !== undefined) {
    let gestureEvent = component.getOrCreateGestureEvent();
    gestureEvent.clearGestures();
    modifier.applyGesture(gestureEvent);
  }
}

function __gestureModifier__(modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = new ArkComponent(nativeNode);
  applyGesture(modifier, component);
}

const __elementIdToCustomProperties__ = new Map();

function __setValidCustomProperty__(nodeId, key, value) {
  if (!__elementIdToCustomProperties__.has(nodeId)) {
    __elementIdToCustomProperties__.set(nodeId, new Map());
  }

  const customProperties = __elementIdToCustomProperties__.get(nodeId);

  if (customProperties) {
    customProperties.set(key, value);
  }
}

function __removeCustomProperty__(nodeId, key) {
  if (__elementIdToCustomProperties__.has(nodeId)) {
    const customProperties = __elementIdToCustomProperties__.get(nodeId);

    if (customProperties) {
      customProperties.delete(key);
      return customProperties.size > 0;
    }
  }

  return false;
}

function __removeCustomProperties__(nodeId) {
  __elementIdToCustomProperties__.delete(nodeId);
}

function __getCustomProperty__(nodeId, key) {
  if (__elementIdToCustomProperties__.has(nodeId)) {
    const customProperties = __elementIdToCustomProperties__.get(nodeId);

    if (customProperties) {
      return customProperties.get(key);
    }
  }

  return undefined;
}

function __setCustomProperty__(nodeId, key, value) {
  if (value !== undefined) {
    __setValidCustomProperty__(nodeId, key, value);
    return true;
  } else {
    return __removeCustomProperty__(nodeId, key);
  }
}

function valueToArkBorder(value){
  let borderValue = new ArkBorder();
  if (isUndefined(value)) {
    borderValue = undefined;
  }

  if (!isUndefined(value?.width) && value?.width !== null) {
    if (isNumber(value.width) || isString(value.width) || isResource(value.width)) {
      borderValue.arkWidth.left = value.width;
      borderValue.arkWidth.right = value.width;
      borderValue.arkWidth.top = value.width;
      borderValue.arkWidth.bottom = value.width;
    } else {
      borderValue.arkWidth.left = value.width.left;
      borderValue.arkWidth.right = value.width.right;
      borderValue.arkWidth.top = value.width.top;
      borderValue.arkWidth.bottom = value.width.bottom;
    }
  }
  if (!isUndefined(value?.color) && value?.color !== null) {
    if (isNumber(value.color) || isString(value.color) || isResource(value.color)) {
      borderValue.arkColor.leftColor = value.color;
      borderValue.arkColor.rightColor = value.color;
      borderValue.arkColor.topColor = value.color;
      borderValue.arkColor.bottomColor = value.color;
    } else {
      borderValue.arkColor.leftColor = (value.color).left;
      borderValue.arkColor.rightColor = (value.color).right;
      borderValue.arkColor.topColor = (value.color).top;
      borderValue.arkColor.bottomColor = (value.color).bottom;
    }
  }
  if (!isUndefined(value?.radius) && value?.radius !== null) {
    if (isNumber(value.radius) || isString(value.radius) || isResource(value.radius)) {
      borderValue.arkRadius.topLeft = value.radius;
      borderValue.arkRadius.topRight = value.radius;
      borderValue.arkRadius.bottomLeft = value.radius;
      borderValue.arkRadius.bottomRight = value.radius;
    } else {
      borderValue.arkRadius.topLeft = value.radius?.topLeft;
      borderValue.arkRadius.topRight = value.radius?.topRight;
      borderValue.arkRadius.bottomLeft = value.radius?.bottomLeft;
      borderValue.arkRadius.bottomRight = value.radius?.bottomRight;
    }
  }
  if (!isUndefined(value?.style) && value?.style !== null) {
    let arkBorderStyle = new ArkBorderStyle();
    if (arkBorderStyle.parseBorderStyle(value.style)) {
      if (!isUndefined(arkBorderStyle.style)) {
        borderValue.arkStyle.top = arkBorderStyle.style;
        borderValue.arkStyle.left = arkBorderStyle.style;
        borderValue.arkStyle.bottom = arkBorderStyle.style;
        borderValue.arkStyle.right = arkBorderStyle.style;
      } else {
        borderValue.arkStyle.top = arkBorderStyle.top;
        borderValue.arkStyle.left = arkBorderStyle.left;
        borderValue.arkStyle.bottom = arkBorderStyle.bottom;
        borderValue.arkStyle.right = arkBorderStyle.right;
      }
    }
  }
  return borderValue;
}

/// <reference path='./import.ts' />
class BlankColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().blank.resetColor(node);
    }
    else {
      getUINativeModule().blank.setColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlankColorModifier.identity = Symbol('blankColor');
class BlankHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().blank.resetBlankHeight(node);
    } else {
      getUINativeModule().blank.setBlankHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlankHeightModifier.identity = Symbol('blankHeight');

class BlankMinModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().blank.resetBlankMin(node);
    } else {
      getUINativeModule().blank.setBlankMin(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlankMinModifier.identity = Symbol('blankMin');

class ArkBlankComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, BlankColorModifier.identity, BlankColorModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, BlankHeightModifier.identity, BlankHeightModifier, value);
    return this;
  }

  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, BlankMinModifier.identity, BlankMinModifier, value[0]);
    }
    return this;
  }
}
// @ts-ignore
if (globalThis.Blank !== undefined) {
  globalThis.Blank.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkBlankComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.BlankModifier(nativePtr, classType);
    });
  };
}

globalThis.applySymbolGlyphModifierToNode = function (modifier, nodePtr) {
  let component = new ArkSymbolGlyphComponent(nodePtr);
  applyUIAttributes(modifier, nodePtr, component);
  component.applyModifierPatch();
};

globalThis.applyImageModifierToNode = function (modifier, nodePtr) {
  let component = new ArkImageComponent(nodePtr);
  applyUIAttributes(modifier, nodePtr, component);
  component.applyModifierPatch();
};

/// <reference path='./import.ts' />
class ColumnAlignItemsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().column.resetAlignItems(node);
    }
    else {
      getUINativeModule().column.setAlignItems(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ColumnAlignItemsModifier.identity = Symbol('columnAlignItems');
class ColumnJustifyContentModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().column.resetJustifyContent(node);
    }
    else {
      getUINativeModule().column.setJustifyContent(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ColumnJustifyContentModifier.identity = Symbol('columnJustifyContent');

class ColumnSpaceModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().column.resetSpace(node);
    }
    else {
      getUINativeModule().column.setSpace(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ColumnSpaceModifier.identity = Symbol('columnSpace');

class ArkColumnComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, ColumnSpaceModifier.identity, ColumnSpaceModifier, value[0].space);
    }
    return this
  }
  alignItems(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnAlignItemsModifier.identity, ColumnAlignItemsModifier, value);
    return this;
  }
  justifyContent(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnJustifyContentModifier.identity, ColumnJustifyContentModifier, value);
    return this;
  }
  pointLight(value) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Column !== undefined) {
  globalThis.Column.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkColumnComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ColumnModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ColumnSplitDividerModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().columnSplit.resetDivider(node);
    }
    else {
      getUINativeModule().columnSplit.setDivider(node, this.value.startMargin, this.value.endMargin);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.startMargin, this.value.startMargin) ||
      !isBaseOrResourceEqual(this.stageValue.endMargin, this.value.endMargin);
  }
}
ColumnSplitDividerModifier.identity = Symbol('columnSplitDivider');
class ColumnSplitResizeableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().columnSplit.resetResizeable(node);
    }
    else {
      getUINativeModule().columnSplit.setResizeable(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ColumnSplitResizeableModifier.identity = Symbol('columnSplitResizeable');
class ColumnSplitClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ColumnSplitClipModifier.identity = Symbol('columnSplitClip');
class ArkColumnSplitComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  resizeable(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnSplitResizeableModifier.identity, ColumnSplitResizeableModifier, value);
    return this;
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnSplitDividerModifier.identity, ColumnSplitDividerModifier, value);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnSplitClipModifier.identity, ColumnSplitClipModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.ColumnSplit !== undefined) {
  globalThis.ColumnSplit.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkColumnSplitComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ColumnSplitModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class DividerVerticalModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().divider.resetVertical(node);
    }
    else {
      getUINativeModule().divider.setVertical(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
DividerVerticalModifier.identity = Symbol('dividerVertical');
class DividerLineCapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().divider.resetLineCap(node);
    }
    else {
      getUINativeModule().divider.setLineCap(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
DividerLineCapModifier.identity = Symbol('dividerLineCap');
class DividerColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().divider.resetColor(node);
    }
    else {
      getUINativeModule().divider.setColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DividerColorModifier.identity = Symbol('dividerColor');
class DividerStrokeWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().divider.resetStrokeWidth(node);
    }
    else {
      getUINativeModule().divider.setStrokeWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
DividerStrokeWidthModifier.identity = Symbol('dividerStrokeWidth');
class ArkDividerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  vertical(value) {
    modifierWithKey(this._modifiersWithKeys, DividerVerticalModifier.identity, DividerVerticalModifier, value);
    return this;
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, DividerColorModifier.identity, DividerColorModifier, value);
    return this;
  }
  strokeWidth(value) {
    modifierWithKey(this._modifiersWithKeys, DividerStrokeWidthModifier.identity, DividerStrokeWidthModifier, value);
    return this;
  }
  lineCap(value) {
    modifierWithKey(this._modifiersWithKeys, DividerLineCapModifier.identity, DividerLineCapModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Divider !== undefined) {
  globalThis.Divider.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkDividerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.DividerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class FlexInitializeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().flex.resetFlexInitialize(node);
    } else {
      getUINativeModule().flex.setFlexInitialize(node, this.value.direction, this.value.wrap,
        this.value.justifyContent, this.value.alignItems, this.value.alignContent);
    }
  }
}
FlexInitializeModifier.identity = Symbol('flexInitialize');
class ArkFlexComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  pointLight(value) {
    throw new Error('Method not implemented.');
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, FlexInitializeModifier.identity, FlexInitializeModifier, value[0]);
    }
    return this;
  }
}
// @ts-ignore
if (globalThis.Flex !== undefined) {
  globalThis.Flex.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkFlexComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.FlexModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class GridRowAlignItemsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridRow.resetAlignItems(node);
    }
    else {
      getUINativeModule().gridRow.setAlignItems(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GridRowAlignItemsModifier.identity = Symbol('gridRowAlignItems');
class SetDirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridRow.resetDirection(node);
    }
    else {
      getUINativeModule().gridRow.setDirection(node,  this.value);
    }
  }
}
SetDirectionModifier.identity = Symbol('gridRowDirection');
class SetBreakpointsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridRow.resetBreakpoints(node);
    }
    else {
      getUINativeModule().gridRow.setBreakpoints(node, this.value.value, this.value.reference);
    }
  }
}
SetBreakpointsModifier.identity = Symbol('gridRowBreakpoints');
class SetColumnsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridRow.resetColumns(node);
    }
    else {
      if (isUndefined(this.value) || isNull(this.value)) {
        getUINativeModule().gridRow.resetColumns(node);
      } else if (isNumber(this.value)) {
        getUINativeModule().gridRow.setColumns(node, this.value, this.value, this.value,
          this.value, this.value, this.value);
      } else {
        getUINativeModule().gridRow.setColumns(node, this.value.xs, this.value.sm, this.value.md,
          this.value.lg, this.value.xl, this.value.xxl);
      }
    }
  }
}
SetColumnsModifier.identity = Symbol('gridRowColumns');
class SetGutterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridRow.resetGutter(node);
    }
    else {
      if (isUndefined(this.value) || isNull(this.value)) {
        getUINativeModule().gridRow.resetGutter(node);
      }
      if (isNumber(this.value)) {
        getUINativeModule().gridRow.setGutter(node, this.value,
          this.value, this.value, this.value, this.value, this.value,
          this.value, this.value, this.value, this.value, this.value, this.value);
      } else {
        if (isNumber(this.value.x)) {
          if (isNumber(this.value.y)) {
            getUINativeModule().gridRow.setGutter(node,
              this.value.x, this.value.x, this.value.x, this.value.x, this.value.x, this.value.x,
              this.value.y, this.value.y, this.value.y, this.value.y, this.value.y, this.value.y);
          } else {
            getUINativeModule().gridRow.setGutter(node,
              this.value.x, this.value.x, this.value.x, this.value.x, this.value.x, this.value.x,
              this.value.y.xs, this.value.y.sm, this.value.y.md, this.value.y.lg, this.value.y.xl, this.value.y.xxl);
          }
        } else {
          if (isNumber(this.value.y)) {
            getUINativeModule().gridRow.setGutter(node,
              this.value.x.xs, this.value.x.sm, this.value.x.md, this.value.x.lg, this.value.x.xl, this.value.x.xxl,
              this.value.y, this.value.y, this.value.y, this.value.y, this.value.y, this.value.y);
          } else {
            getUINativeModule().gridRow.setGutter(node,
              this.value.x.xs, this.value.x.sm, this.value.x.md, this.value.x.lg, this.value.x.xl, this.value.x.xxl,
              this.value.y.xs, this.value.y.sm, this.value.y.md, this.value.y.lg, this.value.y.xl, this.value.y.xxl);
          }
        }
      }
    }
  }
}
SetGutterModifier.identity = Symbol('gridRowGutter');
class ArkGridRowComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onBreakpointChange(callback) {
    throw new Error('Method not implemented.');
  }
  alignItems(value) {
    modifierWithKey(this._modifiersWithKeys, GridRowAlignItemsModifier.identity, GridRowAlignItemsModifier, value);
    return this;
  }
  setDirection(value) {
    modifierWithKey(this._modifiersWithKeys, SetDirectionModifier.identity, SetDirectionModifier, value);
    return this;
  }
  setBreakpoints(value) {
    modifierWithKey(this._modifiersWithKeys, SetBreakpointsModifier.identity, SetBreakpointsModifier, value);
    return this;
  }
  setColumns(value) {
    modifierWithKey(this._modifiersWithKeys, SetColumnsModifier.identity, SetColumnsModifier, value);
    return this;
  }
  setGutter(value) {
    modifierWithKey(this._modifiersWithKeys, SetGutterModifier.identity, SetGutterModifier, value);
    return this;
  }
  initialize(value) {
    if (value[0] !== undefined) {
      this.setGutter(value[0].gutter);
      this.setColumns(value[0].columns);
      this.setBreakpoints(value[0].breakpoints);
      this.setDirection(value[0].direction);
    }
    return this;
  }
}
// @ts-ignore
if (globalThis.GridRow !== undefined) {
  globalThis.GridRow.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGridRowComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.GridRowModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkGridComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  columnsTemplate(value) {
    modifierWithKey(this._modifiersWithKeys, GridColumnsTemplateModifier.identity, GridColumnsTemplateModifier, value);
    return this;
  }
  rowsTemplate(value) {
    modifierWithKey(this._modifiersWithKeys, GridRowsTemplateModifier.identity, GridRowsTemplateModifier, value);
    return this;
  }
  columnsGap(value) {
    modifierWithKey(this._modifiersWithKeys, GridColumnsGapModifier.identity, GridColumnsGapModifier, value);
    return this;
  }
  rowsGap(value) {
    modifierWithKey(this._modifiersWithKeys, GridRowsGapModifier.identity, GridRowsGapModifier, value);
    return this;
  }
  scrollBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, GridScrollBarWidthModifier.identity, GridScrollBarWidthModifier, value);
    return this;
  }
  scrollBarColor(value) {
    modifierWithKey(this._modifiersWithKeys, GridScrollBarColorModifier.identity, GridScrollBarColorModifier, value);
    return this;
  }
  scrollBar(value) {
    modifierWithKey(this._modifiersWithKeys, GridScrollBarModifier.identity, GridScrollBarModifier, value);
    return this;
  }
  onScrollBarUpdate(event) {
    throw new Error('Method not implemented.');
  }
  onScrollIndex(event) {
    throw new Error('Method not implemented.');
  }
  cachedCount(value) {
    modifierWithKey(this._modifiersWithKeys, GridCachedCountModifier.identity, GridCachedCountModifier, value);
    return this;
  }
  editMode(value) {
    modifierWithKey(this._modifiersWithKeys, GridEditModeModifier.identity, GridEditModeModifier, value);
    return this;
  }
  multiSelectable(value) {
    modifierWithKey(this._modifiersWithKeys, GridMultiSelectableModifier.identity, GridMultiSelectableModifier, value);
    return this;
  }
  maxCount(value) {
    modifierWithKey(this._modifiersWithKeys, GridMaxCountModifier.identity, GridMaxCountModifier, value);
    return this;
  }
  minCount(value) {
    modifierWithKey(this._modifiersWithKeys, GridMinCountModifier.identity, GridMinCountModifier, value);
    return this;
  }
  cellLength(value) {
    modifierWithKey(this._modifiersWithKeys, GridCellLengthModifier.identity, GridCellLengthModifier, value);
    return this;
  }
  layoutDirection(value) {
    modifierWithKey(this._modifiersWithKeys, GridLayoutDirectionModifier.identity, GridLayoutDirectionModifier, value);
    return this;
  }
  supportAnimation(value) {
    modifierWithKey(this._modifiersWithKeys, GridSupportAnimationModifier.identity, GridSupportAnimationModifier, value);
    return this;
  }
  onItemDragStart(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragEnter(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragMove(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragLeave(event) {
    throw new Error('Method not implemented.');
  }
  onItemDrop(event) {
    throw new Error('Method not implemented.');
  }
  edgeEffect(value, options) {
    let effect = new ArkGridEdgeEffect();
    effect.value = value;
    effect.options = options;
    modifierWithKey(this._modifiersWithKeys, GridEdgeEffectModifier.identity, GridEdgeEffectModifier, effect);
    return this;
  }
  nestedScroll(value) {
    modifierWithKey(this._modifiersWithKeys, GridNestedScrollModifier.identity, GridNestedScrollModifier, value);
    return this;
  }
  enableScrollInteraction(value) {
    modifierWithKey(this._modifiersWithKeys, GridEnableScrollModifier.identity, GridEnableScrollModifier, value);
    return this;
  }
  friction(value) {
    modifierWithKey(this._modifiersWithKeys, GridFrictionModifier.identity, GridFrictionModifier, value);
    return this;
  }
  onScroll(event) {
    throw new Error('Method not implemented.');
  }
  onReachStart(event) {
    throw new Error('Method not implemented.');
  }
  onReachEnd(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStart(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStop(event) {
    throw new Error('Method not implemented.');
  }
  onScrollFrameBegin(event) {
    throw new Error('Method not implemented.');
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, GridClipModifier.identity, GridClipModifier, value);
    return this;
  }
  flingSpeedLimit(value) {
    modifierWithKey(this._modifiersWithKeys, GridFlingSpeedLimitModifier.identity, GridFlingSpeedLimitModifier, value);
    return this;
  }

}
class GridColumnsTemplateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetColumnsTemplate(node);
    }
    else {
      getUINativeModule().grid.setColumnsTemplate(node, this.value);
    }
  }
}
GridColumnsTemplateModifier.identity = Symbol('gridColumnsTemplate');
class GridRowsTemplateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetRowsTemplate(node);
    }
    else {
      getUINativeModule().grid.setRowsTemplate(node, this.value);
    }
  }
}
GridRowsTemplateModifier.identity = Symbol('gridRowsTemplate');
class GridColumnsGapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetColumnsGap(node);
    }
    else {
      getUINativeModule().grid.setColumnsGap(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GridColumnsGapModifier.identity = Symbol('gridColumnsGap');
class GridRowsGapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetRowsGap(node);
    }
    else {
      getUINativeModule().grid.setRowsGap(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GridRowsGapModifier.identity = Symbol('gridRowsGap');
class GridScrollBarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetScrollBarWidth(node);
    }
    else {
      getUINativeModule().grid.setScrollBarWidth(node, this.value);
    }
  }
}
GridScrollBarWidthModifier.identity = Symbol('gridScrollBarWidth');
class GridScrollBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetScrollBar(node);
    }
    else {
      getUINativeModule().grid.setScrollBar(node, this.value);
    }
  }
}
GridScrollBarModifier.identity = Symbol('gridScrollBar');
class GridScrollBarColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetScrollBarColor(node);
    }
    else {
      getUINativeModule().grid.setScrollBarColor(node, this.value);
    }
  }
}
GridScrollBarColorModifier.identity = Symbol('gridScrollBarColor');
class GridEditModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetEditMode(node);
    }
    else {
      getUINativeModule().grid.setEditMode(node, this.value);
    }
  }
}
GridEditModeModifier.identity = Symbol('gridEditMode');
class GridCachedCountModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetCachedCount(node);
    }
    else {
      getUINativeModule().grid.setCachedCount(node, this.value);
    }
  }
}
GridCachedCountModifier.identity = Symbol('gridCachedCount');
class GridMultiSelectableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetMultiSelectable(node);
    }
    else {
      getUINativeModule().grid.setMultiSelectable(node, this.value);
    }
  }
}
GridMultiSelectableModifier.identity = Symbol('gridMultiSelectable');
class GridEdgeEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().grid.resetEdgeEffect(node);
    }
    else {
      getUINativeModule().grid.setEdgeEffect(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.value, (_b = this.value.options) === null ||
      _b === void 0 ? void 0 : _b.alwaysEnabled);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
GridEdgeEffectModifier.identity = Symbol('gridEdgeEffect');
class GridNestedScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().grid.resetNestedScroll(node);
    }
    else {
      getUINativeModule().grid.setNestedScroll(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.scrollForward, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.scrollBackward);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.scrollForward === this.value.scrollForward) &&
      (this.stageValue.scrollBackward === this.value.scrollBackward));
  }
}
GridNestedScrollModifier.identity = Symbol('gridNestedScroll');
class GridEnableScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetEnableScroll(node);
    }
    else {
      getUINativeModule().grid.setEnableScroll(node, this.value);
    }
  }
}
GridEnableScrollModifier.identity = Symbol('gridEnableScroll');
class GridFrictionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetFriction(node);
    }
    else {
      getUINativeModule().grid.setFriction(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GridFrictionModifier.identity = Symbol('gridFriction');
class GridMaxCountModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetMaxCount(node);
    }
    else {
      getUINativeModule().grid.setMaxCount(node, this.value);
    }
  }
}
GridMaxCountModifier.identity = Symbol('gridMaxCount');
class GridMinCountModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetMinCount(node);
    }
    else {
      getUINativeModule().grid.setMinCount(node, this.value);
    }
  }
}
GridMinCountModifier.identity = Symbol('gridMinCount');
class GridCellLengthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetCellLength(node);
    }
    else {
      getUINativeModule().grid.setCellLength(node, this.value);
    }
  }
}
GridCellLengthModifier.identity = Symbol('gridCellLength');
class GridLayoutDirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetLayoutDirection(node);
    }
    else {
      getUINativeModule().grid.setLayoutDirection(node, this.value);
    }
  }
}
GridLayoutDirectionModifier.identity = Symbol('gridLayoutDirection');
class GridSupportAnimationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().grid.resetSupportAnimation(node);
    }
    else {
      getUINativeModule().grid.setSupportAnimation(node, this.value);
    }
  }
}
GridSupportAnimationModifier.identity = Symbol('gridSupportAnimation');
class GridClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
GridClipModifier.identity = Symbol('gridClip');
class GridFlingSpeedLimitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {    
      getUINativeModule().grid.resetFlingSpeedLimit(node);
    }
    else {
      getUINativeModule().grid.setFlingSpeedLimit(node, this.value);
    }
  }
}
GridFlingSpeedLimitModifier.identity = Symbol('gridFlingSpeedLimit');
// @ts-ignore
if (globalThis.Grid !== undefined) {
  globalThis.Grid.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGridComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.GridModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class GridColSpanModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridCol.resetSpan(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().gridCol.setSpan(node, this.value, this.value, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().gridCol.setSpan(node, this.value.xs, this.value.sm, this.value.md, this.value.lg, this.value.xl, this.value.xxl);
      }
    }
  }
  checkObjectDiff() {
    if (isNumber(this.stageValue) && isNumber(this.value)) {
      return this.stageValue !== this.value;
    }
    else if (isObject(this.stageValue) && isObject(this.value)) {
      return this.stageValue.xs !== this.value.xs ||
        this.stageValue.sm !== this.value.sm ||
        this.stageValue.md !== this.value.md ||
        this.stageValue.lg !== this.value.lg ||
        this.stageValue.xl !== this.value.xl ||
        this.stageValue.xxl !== this.value.xxl;
    }
    else {
      return true;
    }
  }
}
GridColSpanModifier.identity = Symbol('gridColSpan');
class GridColOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridCol.resetGridColOffset(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().gridCol.setGridColOffset(node, this.value, this.value, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().gridCol.setGridColOffset(node, this.value.xs, this.value.sm, this.value.md, this.value.lg, this.value.xl, this.value.xxl);
      }
    }
  }
  checkObjectDiff() {
    if (isNumber(this.stageValue) && isNumber(this.value)) {
      return this.stageValue !== this.value;
    }
    else if (isObject(this.stageValue) && isObject(this.value)) {
      return this.stageValue.xs !== this.value.xs ||
        this.stageValue.sm !== this.value.sm ||
        this.stageValue.md !== this.value.md ||
        this.stageValue.lg !== this.value.lg ||
        this.stageValue.xl !== this.value.xl ||
        this.stageValue.xxl !== this.value.xxl;
    }
    else {
      return true;
    }
  }
}
GridColOffsetModifier.identity = Symbol('gridColOffset');
class GridColOrderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridCol.resetOrder(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().gridCol.setOrder(node, this.value, this.value, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().gridCol.setOrder(node, this.value.xs, this.value.sm, this.value.md, this.value.lg, this.value.xl, this.value.xxl);
      }
    }
  }
  checkObjectDiff() {
    if (isNumber(this.stageValue) && isNumber(this.value)) {
      return this.stageValue !== this.value;
    }
    else if (isObject(this.stageValue) && isObject(this.value)) {
      return this.stageValue.xs !== this.value.xs ||
        this.stageValue.sm !== this.value.sm ||
        this.stageValue.md !== this.value.md ||
        this.stageValue.lg !== this.value.lg ||
        this.stageValue.xl !== this.value.xl ||
        this.stageValue.xxl !== this.value.xxl;
    }
    else {
      return true;
    }
  }
}
GridColOrderModifier.identity = Symbol('gridColOrder');
class ArkGridColComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  span(value) {
    modifierWithKey(this._modifiersWithKeys, GridColSpanModifier.identity, GridColSpanModifier, value);
    return this;
  }
  gridColOffset(value) {
    modifierWithKey(this._modifiersWithKeys, GridColOffsetModifier.identity, GridColOffsetModifier, value);
    return this;
  }
  order(value) {
    modifierWithKey(this._modifiersWithKeys, GridColOrderModifier.identity, GridColOrderModifier, value);
    return this;
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, GridColSpanModifier.identity, GridColSpanModifier, value.span);
      modifierWithKey(this._modifiersWithKeys, GridColOffsetModifier.identity, GridColOffsetModifier, value.offset);
      modifierWithKey(this._modifiersWithKeys, GridColOrderModifier.identity, GridColOrderModifier, value.order);
    }
    return this;
  }
}
// @ts-ignore
if (globalThis.GridCol !== undefined) {
  globalThis.GridCol.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGridColComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.GridColModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ImageColorFilterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetColorFilter(node);
    }
    else {
      getUINativeModule().image.setColorFilter(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ImageColorFilterModifier.identity = Symbol('imageColorFilter');
class ImageFillColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetFillColor(node);
    }
    else {
      getUINativeModule().image.setFillColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ImageFillColorModifier.identity = Symbol('imageFillColor');
class ImageAltModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetAlt(node);
    }
    else {
      getUINativeModule().image.setAlt(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ImageAltModifier.identity = Symbol('imageAlt');
class ImageCopyOptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetCopyOption(node);
    }
    else {
      getUINativeModule().image.setCopyOption(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageCopyOptionModifier.identity = Symbol('imageCopyOption');
class ImageAutoResizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetAutoResize(node);
    }
    else {
      getUINativeModule().image.setAutoResize(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAutoResizeModifier.identity = Symbol('imageAutoResize');
class ImageFitOriginalSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetFitOriginalSize(node);
    }
    else {
      getUINativeModule().image.setFitOriginalSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageFitOriginalSizeModifier.identity = Symbol('imageFitOriginalSize');
class ImageDraggableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetDraggable(node);
    }
    else {
      getUINativeModule().image.setDraggable(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageDraggableModifier.identity = Symbol('imageDraggable');
class ImageInterpolationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetImageInterpolation(node);
    }
    else {
      getUINativeModule().image.setImageInterpolation(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageInterpolationModifier.identity = Symbol('imageInterpolation');
class ImageSourceSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetSourceSize(node);
    }
    else {
      getUINativeModule().image.setSourceSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return this.stageValue.width !== this.value.width ||
      this.stageValue.height !== this.value.height;
  }
}
ImageSourceSizeModifier.identity = Symbol('imageSourceSize');
class ImageMatchTextDirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetMatchTextDirection(node);
    }
    else {
      getUINativeModule().image.setMatchTextDirection(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageMatchTextDirectionModifier.identity = Symbol('imageMatchTextDirection');
class ImageObjectRepeatModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetObjectRepeat(node);
    }
    else {
      getUINativeModule().image.setObjectRepeat(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageObjectRepeatModifier.identity = Symbol('imageObjectRepeat');
class ImageRenderModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetRenderMode(node);
    }
    else {
      getUINativeModule().image.setRenderMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageRenderModeModifier.identity = Symbol('imageRenderMode');
class ImageSyncLoadModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetSyncLoad(node);
    }
    else {
      getUINativeModule().image.setSyncLoad(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageSyncLoadModifier.identity = Symbol('imageSyncLoad');
class ImageObjectFitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetObjectFit(node);
    }
    else {
      getUINativeModule().image.setObjectFit(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageObjectFitModifier.identity = Symbol('imageObjectFit');
class ImageBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetBorderRadius(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().image.setBorderRadius(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().image.setBorderRadius(node, this.value.topLeft, this.value.topRight, this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    }
    else {
      return true;
    }
  }
}
ImageBorderRadiusModifier.identity = Symbol('imageBorderRadius');
class ImageBorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetImageBorder(node);
    } else {
      let widthLeft;
      let widthRight;
      let widthTop;
      let widthBottom;
      if (!isUndefined(this.value.width) && this.value.width != null) {
        if (isNumber(this.value.width) || isString(this.value.width) || isResource(this.value.width)) {
          widthLeft = this.value.width;
          widthRight = this.value.width;
          widthTop = this.value.width;
          widthBottom = this.value.width;
        } else {
          widthLeft = this.value.width.left;
          widthRight = this.value.width.right;
          widthTop = this.value.width.top;
          widthBottom = this.value.width.bottom;
        }
      }
      let leftColor;
      let rightColor;
      let topColor;
      let bottomColor;
      if (!isUndefined(this.value.color) && this.value.color != null) {
        if (isNumber(this.value.color) || isString(this.value.color) || isResource(this.value.color)) {
          leftColor = this.value.color;
          rightColor = this.value.color;
          topColor = this.value.color;
          bottomColor = this.value.color;
        } else {
          leftColor = this.value.color.left;
          rightColor = this.value.color.right;
          topColor = this.value.color.top;
          bottomColor = this.value.color.bottom;
        }
      }
      let topLeft;
      let topRight;
      let bottomLeft;
      let bottomRight;
      if (!isUndefined(this.value.radius) && this.value.radius != null) {
        if (isNumber(this.value.radius) || isString(this.value.radius) || isResource(this.value.radius)) {
          topLeft = this.value.radius;
          topRight = this.value.radius;
          bottomLeft = this.value.radius;
          bottomRight = this.value.radius;
        } else {
          topLeft = this.value.radius.topLeft;
          topRight = this.value.radius.topRight;
          bottomLeft = this.value.radius.bottomLeft;
          bottomRight = this.value.radius.bottomRight;
        }
      }
      let styleTop;
      let styleRight;
      let styleBottom;
      let styleLeft;
      if (!isUndefined(this.value.style) && this.value.style != null) {
        if (isNumber(this.value.style) || isString(this.value.style) || isResource(this.value.style)) {
          styleTop = this.value.style;
          styleRight = this.value.style;
          styleBottom = this.value.style;
          styleLeft = this.value.style;
        } else {
          styleTop = this.value.style.top;
          styleRight = this.value.style.right;
          styleBottom = this.value.style.bottom;
          styleLeft = this.value.style.left;
        }
      }
      getUINativeModule().image.setImageBorder(
        node,
        widthLeft,
        widthRight,
        widthTop,
        widthBottom,
        leftColor,
        rightColor,
        topColor,
        bottomColor,
        topLeft,
        topRight,
        bottomLeft,
        bottomRight,
        styleTop,
        styleRight,
        styleBottom,
        styleLeft
      );
    }
  }
  checkObjectDiff() {
    return (
      !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color) ||
      !isBaseOrResourceEqual(this.stageValue.radius, this.value.radius) ||
      !isBaseOrResourceEqual(this.stageValue.style, this.value.style)
    );
  }
}
ImageBorderModifier.identity = Symbol('imageBorder');
class ImageOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetImageOpacity(node);
    } else {
      getUINativeModule().image.setImageOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ImageOpacityModifier.identity = Symbol('imageOpacity');
class ImageeEdgeAntialiasingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetEdgeAntialiasing(node);
    } else {
      getUINativeModule().image.setEdgeAntialiasing(node, this.value);
    }
  }
}
ImageeEdgeAntialiasingModifier.identity = Symbol('edgeAntialiasing');
class ImageTransitionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetImageTransition(node);
    } else {
      getUINativeModule().image.setImageTransition(node, this.value);
    }
  }
}
ImageTransitionModifier.identity = Symbol('imageTransition');
class ImageeResizableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetResizable(node);
    } else {
      let sliceTop;
      let sliceRight;
      let sliceBottom;
      let sliceLeft;
      if (!isUndefined(this.value.slice)) {
        let tmpSlice = this.value.slice;
        sliceTop = tmpSlice.top;
        sliceRight = tmpSlice.right;
        sliceBottom = tmpSlice.bottom;
        sliceLeft = tmpSlice.left;
      }
      getUINativeModule().image.setResizable(node, sliceTop, sliceRight, sliceBottom, sliceLeft);
    }
  }
}
ImageeResizableModifier.identity = Symbol('resizable');
class ImageDynamicRangeModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetDynamicRangeMode(node);
    }
    else {
      getUINativeModule().image.setDynamicRangeMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageDynamicRangeModeModifier.identity = Symbol('dynamicRangeMode');
class ImageEnhancedImageQualityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.resetEnhancedImageQuality(node);
    }
    else {
      getUINativeModule().image.setEnhancedImageQuality(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageObjectFitModifier.identity = Symbol('enhancedImageQuality');
class ImageSrcModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().image.setImageShowSrc(node, "");
    }
    else {
      getUINativeModule().image.setImageShowSrc(node, this.value);
    }
  }
}
ImageSrcModifier.identity = Symbol('imageShowSrc');

class ArkImageComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] != undefined) {
      modifierWithKey(this._modifiersWithKeys, ImageSrcModifier.identity, ImageSrcModifier, value[0]);
    }
    return this;
  }
  draggable(value) {
    modifierWithKey(this._modifiersWithKeys, ImageDraggableModifier.identity, ImageDraggableModifier, value);
    return this;
  }
  edgeAntialiasing(value) {
    modifierWithKey(this._modifiersWithKeys, ImageeEdgeAntialiasingModifier.identity, ImageeEdgeAntialiasingModifier, value);
    return this;
  }
  resizable(value) {
    modifierWithKey(this._modifiersWithKeys, ImageeResizableModifier.identity, ImageeResizableModifier, value);
    return this;
  }
  alt(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAltModifier.identity, ImageAltModifier, value);
    return this;
  }
  matchTextDirection(value) {
    modifierWithKey(this._modifiersWithKeys, ImageMatchTextDirectionModifier.identity, ImageMatchTextDirectionModifier, value);
    return this;
  }
  fitOriginalSize(value) {
    modifierWithKey(this._modifiersWithKeys, ImageFitOriginalSizeModifier.identity, ImageFitOriginalSizeModifier, value);
    return this;
  }
  fillColor(value) {
    modifierWithKey(this._modifiersWithKeys, ImageFillColorModifier.identity, ImageFillColorModifier, value);
    return this;
  }
  objectFit(value) {
    modifierWithKey(this._modifiersWithKeys, ImageObjectFitModifier.identity, ImageObjectFitModifier, value);
    return this;
  }
  objectRepeat(value) {
    modifierWithKey(this._modifiersWithKeys, ImageObjectRepeatModifier.identity, ImageObjectRepeatModifier, value);
    return this;
  }
  autoResize(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAutoResizeModifier.identity, ImageAutoResizeModifier, value);
    return this;
  }
  renderMode(value) {
    modifierWithKey(this._modifiersWithKeys, ImageRenderModeModifier.identity, ImageRenderModeModifier, value);
    return this;
  }
  interpolation(value) {
    modifierWithKey(this._modifiersWithKeys, ImageInterpolationModifier.identity, ImageInterpolationModifier, value);
    return this;
  }
  sourceSize(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSourceSizeModifier.identity, ImageSourceSizeModifier, value);
    return this;
  }
  syncLoad(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSyncLoadModifier.identity, ImageSyncLoadModifier, value);
    return this;
  }
  colorFilter(value) {
    modifierWithKey(this._modifiersWithKeys, ImageColorFilterModifier.identity, ImageColorFilterModifier, value);
    return this;
  }
  copyOption(value) {
    modifierWithKey(this._modifiersWithKeys, ImageCopyOptionModifier.identity, ImageCopyOptionModifier, value);
    return this;
  }
  borderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, ImageBorderRadiusModifier.identity, ImageBorderRadiusModifier, value);
    return this;
  }
  onComplete(callback) {
    throw new Error('Method not implemented.');
  }
  onError(callback) {
    throw new Error('Method not implemented.');
  }
  onFinish(event) {
    throw new Error('Method not implemented.');
  }
  border(value) {
    modifierWithKey(this._modifiersWithKeys, ImageBorderModifier.identity, ImageBorderModifier, value);
    return this;
  }
  opacity(value) {
    modifierWithKey(this._modifiersWithKeys, ImageOpacityModifier.identity, ImageOpacityModifier, value);
    return this;
  }
  transition(value) {
    modifierWithKey(this._modifiersWithKeys, ImageTransitionModifier.identity, ImageTransitionModifier, value);
    return this;
  }
  dynamicRangeMode(value) {
    modifierWithKey(
      this._modifiersWithKeys, ImageDynamicRangeModeModifier.identity, ImageDynamicRangeModeModifier, value);
    return this;
  }
  enhancedImageQuality(value) {
    modifierWithKey(
      this._modifiersWithKeys, ImageEnhancedImageQualityModifier.identity, ImageEnhancedImageQualityModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Image !== undefined) {
  globalThis.Image.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkImageComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ImageModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ImageAnimatorImagesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetImages(node);
    }
    else {
      let arkImageFrame = this.convertImageFrames(this.value);
      if (!arkImageFrame) {
        getUINativeModule().imageAnimator.resetImages(node);
      }
      else {
        getUINativeModule().imageAnimator.setImages(node, arkImageFrame.arrSrc,
          arkImageFrame.arrWidth, arkImageFrame.arrHeight, arkImageFrame.arrTop,
          arkImageFrame.arrLeft, arkImageFrame.arrDuration, arkImageFrame.arrSrc.length);
      }
    }
  }
  checkObjectDiff() {
    let checkDiff = true;
    if (this.value && this.value.length > 0 &&
      this.stageValue && this.stageValue.length > 0 &&
      this.value.length === this.stageValue.length) {
      let checkItemEqual = false;
      for (let i = 0; i < this.value.length; i++) {
        checkItemEqual = this.isEqual(this.stageValue[i], this.value[i]);
        if (!checkItemEqual) {
          checkDiff = !checkItemEqual;
          break;
        }
      }
    }
    return checkDiff;
  }
  isEqual(one, another) {
    if (!(one.width === another.width &&
      one.height === another.height &&
      one.top === another.top &&
      one.left === another.left &&
      one.duration === another.duration)) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual(one.src, another.src);
    }
  }
  convertImageFrames(value) {
    if (value && value.length > 0) {
      let isFlag = true;
      for (let item of value) {
        if (item.src === undefined || item.src === null) {
          isFlag = false;
          break;
        }
      }
      if (isFlag) {
        let array = new ArkImageFrameInfoToArray();
        for (let item of value) {
          array.arrSrc.push(item.src);
          array.arrWidth.push((item.width === undefined || item.width === null) ? 0 : item.width);
          array.arrHeight.push((item.height === undefined || item.height === null) ? 0 : item.height);
          array.arrTop.push((item.top === undefined || item.top === null) ? 0 : item.top);
          array.arrLeft.push((item.left === undefined || item.left === null) ? 0 : item.left);
          array.arrDuration.push((item.duration === undefined || item.duration === null) ? 0 : item.duration);
        }
        return array;
      }
      else {
        return undefined;
      }
    }
    else {
      return undefined;
    }
  }
}
ImageAnimatorImagesModifier.identity = Symbol('imageAnimatorImages');
class ImageAnimatorDurationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetDuration(node);
    }
    else {
      getUINativeModule().imageAnimator.setDuration(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorDurationModifier.identity = Symbol('imageAnimatorDuration');
class ImageAnimatorReverseModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetReverse(node);
    }
    else {
      getUINativeModule().imageAnimator.setReverse(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorReverseModifier.identity = Symbol('imageAnimatorReverse');
class ImageAnimatorStateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetState(node);
    }
    else {
      getUINativeModule().imageAnimator.setState(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorStateModifier.identity = Symbol('imageAnimatorState');
class ImageAnimatorFixedSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetFixedSize(node);
    }
    else {
      getUINativeModule().imageAnimator.setFixedSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorFixedSizeModifier.identity = Symbol('imageAnimatorFixedSize');
class ImageAnimatorFillModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetFillMode(node);
    }
    else {
      getUINativeModule().imageAnimator.setFillMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorFillModeModifier.identity = Symbol('imageAnimatorFillMode');
class ImageAnimatorIterationsModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageAnimator.resetIterations(node);
    }
    else {
      getUINativeModule().imageAnimator.setIterations(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageAnimatorIterationsModeModifier.identity = Symbol('imageAnimatorIterationsMode');
class ArkImageAnimatorComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  images(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorImagesModifier.identity, ImageAnimatorImagesModifier, value);
    return this;
  }
  state(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorStateModifier.identity, ImageAnimatorStateModifier, value);
    return this;
  }
  duration(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorDurationModifier.identity, ImageAnimatorDurationModifier, value);
    return this;
  }
  reverse(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorReverseModifier.identity, ImageAnimatorReverseModifier, value);
    return this;
  }
  fixedSize(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorFixedSizeModifier.identity, ImageAnimatorFixedSizeModifier, value);
    return this;
  }
  preDecode(value) {
    throw new Error('Method not implemented.');
  }
  fillMode(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorFillModeModifier.identity, ImageAnimatorFillModeModifier, value);
    return this;
  }
  iterations(value) {
    modifierWithKey(this._modifiersWithKeys, ImageAnimatorIterationsModeModifier.identity, ImageAnimatorIterationsModeModifier, value);
    return this;
  }
  onStart(event) {
    throw new Error('Method not implemented.');
  }
  onPause(event) {
    throw new Error('Method not implemented.');
  }
  onRepeat(event) {
    throw new Error('Method not implemented.');
  }
  onCancel(event) {
    throw new Error('Method not implemented.');
  }
  onFinish(event) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.ImageAnimator !== undefined) {
  globalThis.ImageAnimator.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkImageAnimatorComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ImageAnimatorModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ImageSpanObjectFitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageSpan.resetObjectFit(node);
    }
    else {
      getUINativeModule().imageSpan.setObjectFit(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageSpanObjectFitModifier.identity = Symbol('imageSpanObjectFit');
class ImageSpanVerticalAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageSpan.resetVerticalAlign(node);
    }
    else {
      getUINativeModule().imageSpan.setVerticalAlign(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ImageSpanVerticalAlignModifier.identity = Symbol('imageSpanVerticalAlign');
class ImageSpanTextBackgroundStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageSpan.resetTextBackgroundStyle(node);
    }
    else {
      let textBackgroundStyle = new ArkTextBackGroundStyle();
      if (!textBackgroundStyle.convertTextBackGroundStyleOptions(this.value)) {
        getUINativeModule().imageSpan.resetTextBackgroundStyle(node);
      }
      else {
        getUINativeModule().imageSpan.setTextBackgroundStyle(node, textBackgroundStyle.color, textBackgroundStyle.radius.topLeft, textBackgroundStyle.radius.topRight, textBackgroundStyle.radius.bottomLeft, textBackgroundStyle.radius.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    let textBackgroundStyle = new ArkTextBackGroundStyle();
    let stageTextBackGroundStyle = new ArkTextBackGroundStyle();
    if (!textBackgroundStyle.convertTextBackGroundStyleOptions(this.value) || !stageTextBackGroundStyle.convertTextBackGroundStyleOptions(this.stageValue)) {
      return false;
    }
    else {
      return textBackgroundStyle.checkObjectDiff(stageTextBackGroundStyle);
    }
  }
}
ImageSpanTextBackgroundStyleModifier.identity = Symbol('imageSpanTextBackgroundStyle');
class ImageSpanBaselineOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().imageSpan.resetBaselineOffset(node);
    }
    else {
      getUINativeModule().imageSpan.setBaselineOffset(node, this.value);
    }
  }
}
ImageSpanBaselineOffsetModifier.identity = Symbol('imagespanBaselineOffset');
class ArkImageSpanComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  objectFit(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSpanObjectFitModifier.identity, ImageSpanObjectFitModifier, value);
    return this;
  }
  verticalAlign(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSpanVerticalAlignModifier.identity, ImageSpanVerticalAlignModifier, value);
    return this;
  }
  textBackgroundStyle(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSpanTextBackgroundStyleModifier.identity, ImageSpanTextBackgroundStyleModifier, value);
    return this;
  }
  baselineOffset(value) {
    modifierWithKey(this._modifiersWithKeys, ImageSpanBaselineOffsetModifier.identity, ImageSpanBaselineOffsetModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.ImageSpan !== undefined) {
  globalThis.ImageSpan.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkImageSpanComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ImageSpanModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class PatternLockActiveColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetActiveColor(node);
    }
    else {
      getUINativeModule().patternLock.setActiveColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockActiveColorModifier.identity = Symbol('patternLockActiveColor');
class PatternLockSelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetSelectedColor(node);
    }
    else {
      getUINativeModule().patternLock.setSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockSelectedColorModifier.identity = Symbol('patternLockSelectedColor');
class PatternLockPathColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetPathColor(node);
    }
    else {
      getUINativeModule().patternLock.setPathColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockPathColorModifier.identity = Symbol('patternLockPathColor');
class PatternLockRegularColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetRegularColor(node);
    }
    else {
      getUINativeModule().patternLock.setRegularColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockRegularColorModifier.identity = Symbol('patternLockRegularColor');
class PatternLockSideLengthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetSideLength(node);
    }
    else {
      getUINativeModule().patternLock.setSideLength(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockSideLengthModifier.identity = Symbol('patternLockSideLength');
class PatternLockPathStrokeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetPathStrokeWidth(node);
    }
    else {
      getUINativeModule().patternLock.setPathStrokeWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
PatternLockPathStrokeModifier.identity = Symbol('patternLockPathStroke');
class PatternLockCircleRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetCircleRadius(node);
    }
    else {
      getUINativeModule().patternLock.setCircleRadius(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockCircleRadiusModifier.identity = Symbol('patternLockCircleRadius');
class PatternLockAutoResetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetAutoReset(node);
    }
    else {
      getUINativeModule().patternLock.setAutoReset(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
PatternLockAutoResetModifier.identity = Symbol('patternlockautoreset');
class PatternLockActiveCircleColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetActiveCircleColor(node);
    }
    else {
      getUINativeModule().patternLock.setActiveCircleColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockActiveCircleColorModifier.identity = Symbol('patternLockActiveCircleColor');
class PatternLockActiveCircleRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetActiveCircleRadius(node);
    }
    else {
      getUINativeModule().patternLock.setActiveCircleRadius(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PatternLockActiveCircleRadiusModifier.identity = Symbol('patternLockActiveCircleRadius');
class PatternLockEnableWaveEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().patternLock.resetEnableWaveEffect(node);
    }
    else {
      getUINativeModule().patternLock.setEnableWaveEffect(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
PatternLockEnableWaveEffectModifier.identity = Symbol('patternLockEnableWaveEffect');
class ArkPatternLockComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  sideLength(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockSideLengthModifier.identity, PatternLockSideLengthModifier, value);
    return this;
  }
  circleRadius(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockCircleRadiusModifier.identity, PatternLockCircleRadiusModifier, value);
    return this;
  }
  regularColor(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockRegularColorModifier.identity, PatternLockRegularColorModifier, value);
    return this;
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockSelectedColorModifier.identity, PatternLockSelectedColorModifier, value);
    return this;
  }
  activeColor(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockActiveColorModifier.identity, PatternLockActiveColorModifier, value);
    return this;
  }
  pathColor(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockPathColorModifier.identity, PatternLockPathColorModifier, value);
    return this;
  }
  pathStrokeWidth(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockPathStrokeModifier.identity, PatternLockPathStrokeModifier, value);
    return this;
  }
  autoReset(value) {
    modifierWithKey(this._modifiersWithKeys, PatternLockAutoResetModifier.identity, PatternLockAutoResetModifier, value);
    return this;
  }
  onPatternComplete(callback) {
    throw new Error('Method not implemented.');
  }
  onDotConnect(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.PatternLock !== undefined) {
  globalThis.PatternLock.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPatternLockComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PatternLockModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class RichEditorEnableDataDetectorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().richEditor.resetEnableDataDetector(node);
    }
    else {
      getUINativeModule().richEditor.setEnableDataDetector(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
RichEditorEnableDataDetectorModifier.identity = Symbol('richEditorEnableDataDetector');
class RichEditorCopyOptionsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().richEditor.resetCopyOptions(node);
    }
    else {
      getUINativeModule().richEditor.setCopyOptions(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RichEditorCopyOptionsModifier.identity = Symbol('richEditorCopyOptions');

class RichEditorCaretColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().richEditor.resetCaretColor(node);
    }
    else {
      getUINativeModule().richEditor.setCaretColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RichEditorCaretColorModifier.identity = Symbol('richEditorCaretColor');

class RichEditorSelectedBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().richEditor.resetSelectedBackgroundColor(node);
    }
    else {
      getUINativeModule().richEditor.setSelectedBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RichEditorSelectedBackgroundColorModifier.identity = Symbol('richEditorSelectedBackgroundColor');

class ArkRichEditorComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  enableDataDetector(value) {
    modifierWithKey(this._modifiersWithKeys, RichEditorEnableDataDetectorModifier.identity, RichEditorEnableDataDetectorModifier, value);
    return this;
  }
  dataDetectorConfig(config) {
    throw new Error('Method not implemented.');
  }
  copyOptions(value) {
    modifierWithKey(this._modifiersWithKeys, RichEditorCopyOptionsModifier.identity, RichEditorCopyOptionsModifier, value);
    return this;
  }

  caretColor(value) {
    modifierWithKey(this._modifiersWithKeys, RichEditorCaretColorModifier.identity, RichEditorCaretColorModifier, value);
    return this;
  }

  selectedBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, RichEditorSelectedBackgroundColorModifier.identity, RichEditorSelectedBackgroundColorModifier, value);
    return this;
  }

  onPaste(callback) {
    throw new Error('Method not implemented.');
  }
  onReady(callback) {
    throw new Error('Method not implemented.');
  }
  onSelect(callback) {
    throw new Error('Method not implemented.');
  }
  aboutToIMEInput(callback) {
    throw new Error('Method not implemented.');
  }
  onIMEInputComplete(callback) {
    throw new Error('Method not implemented.');
  }
  aboutToDelete(callback) {
    throw new Error('Method not implemented.');
  }
  onDeleteComplete(callback) {
    throw new Error('Method not implemented.');
  }
  bindSelectionMenu(spanType, content, responseType, options) {
    throw new Error('Method not implemented.');
  }
  customKeyboard(value) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.RichEditor !== undefined) {
  globalThis.RichEditor.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRichEditorComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RichEditorModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class RowAlignItemsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().row.resetAlignItems(node);
    }
    else {
      getUINativeModule().row.setAlignItems(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RowAlignItemsModifier.identity = Symbol('rowAlignItems');
class RowJustifyContentlModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().row.resetJustifyContent(node);
    }
    else {
      getUINativeModule().row.setJustifyContent(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RowJustifyContentlModifier.identity = Symbol('rowJustifyContent');

class RowSpaceModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().row.resetSpace(node);
    }
    else {
      getUINativeModule().row.setSpace(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
RowSpaceModifier.identity = Symbol('rowSpace');

class ArkRowComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, RowSpaceModifier.identity, RowSpaceModifier, value[0].space);
    }
    return this
  }
  alignItems(value) {
    modifierWithKey(this._modifiersWithKeys, RowAlignItemsModifier.identity, RowAlignItemsModifier, value);
    return this;
  }
  justifyContent(value) {
    modifierWithKey(this._modifiersWithKeys, RowJustifyContentlModifier.identity, RowJustifyContentlModifier, value);
    return this;
  }
  pointLight(value) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Row !== undefined) {
  globalThis.Row.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRowComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RowModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class RowSplitResizeableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rowSplit.resetResizeable(node);
    }
    else {
      getUINativeModule().rowSplit.setResizeable(node, this.value);
    }
  }
}
RowSplitResizeableModifier.identity = Symbol('rowSplitResizeable');
class RowSplitClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
RowSplitClipModifier.identity = Symbol('rowSplitClip');
class ArkRowSplitComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  resizeable(value) {
    modifierWithKey(this._modifiersWithKeys, RowSplitResizeableModifier.identity, RowSplitResizeableModifier, value);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, RowSplitClipModifier.identity, RowSplitClipModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.RowSplit !== undefined) {
  globalThis.RowSplit.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRowSplitComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RowSplitModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class SearchSelectionMenuHiddenModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSelectionMenuHidden(node);
    }
    else {
      getUINativeModule().search.setSelectionMenuHidden(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
SearchSelectionMenuHiddenModifier.identity = Symbol('searchSelectionMenuHidden');
class SearchCaretStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetCaretStyle(node);
    }
    else {
      getUINativeModule().search.setCaretStyle(node, this.value.width, this.value.color);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color);
  }
}
SearchCaretStyleModifier.identity = Symbol('searchCaretStyle');
class SearchEnableKeyboardOnFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetEnableKeyboardOnFocus(node);
    }
    else {
      getUINativeModule().search.setEnableKeyboardOnFocus(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
SearchEnableKeyboardOnFocusModifier.identity = Symbol('searchEnableKeyboardOnFocus');
class SearchSearchIconModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSearchIcon(node);
    }
    else {
      getUINativeModule().search.setSearchIcon(node, this.value.size, this.value.color, this.value.src);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.size, this.value.size) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color) ||
      !isBaseOrResourceEqual(this.stageValue.src, this.value.src);
  }
}
SearchSearchIconModifier.identity = Symbol('searchSearchIcon');
class SearchPlaceholderFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetPlaceholderFont(node);
    }
    else {
      getUINativeModule().search.setPlaceholderFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    return this.stageValue.weight !== this.value.weight ||
      this.stageValue.style !== this.value.style ||
      !isBaseOrResourceEqual(this.stageValue.size, this.value.size) ||
      !isBaseOrResourceEqual(this.stageValue.family, this.value.family);
  }
}
SearchPlaceholderFontModifier.identity = Symbol('searchPlaceholderFont');
class SearchSearchButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSearchButton(node);
    }
    else {
      getUINativeModule().search.setSearchButton(node, this.value.value, this.value.fontSize, this.value.fontColor);
    }
  }
  checkObjectDiff() {
    return this.stageValue.value !== this.value.value ||
      !isBaseOrResourceEqual(this.stageValue.fontSize, this.value.fontSize) ||
      !isBaseOrResourceEqual(this.stageValue.fontColor, this.value.fontColor);
  }
}
SearchSearchButtonModifier.identity = Symbol('searchSearchButton');
class SearchFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetFontColor(node);
    }
    else {
      getUINativeModule().search.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchFontColorModifier.identity = Symbol('searchFontColor');
class SearchFontFeatureModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetFontFeature(node);
    } else {
      getUINativeModule().search.setFontFeature(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchFontColorModifier.identity = Symbol('searchFontFeature');
class SearchCopyOptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetCopyOption(node);
    }
    else {
      getUINativeModule().search.setCopyOption(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
SearchCopyOptionModifier.identity = Symbol('searchCopyOption');
class SearchTextFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetTextFont(node);
    }
    else {
      getUINativeModule().search.setTextFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    return this.stageValue.weight !== this.value.weight ||
      this.stageValue.style !== this.value.style ||
      !isBaseOrResourceEqual(this.stageValue.size, this.value.size) ||
      !isBaseOrResourceEqual(this.stageValue.family, this.value.family);
  }
}
SearchTextFontModifier.identity = Symbol('searchTextFont');
class SearchPlaceholderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetPlaceholderColor(node);
    }
    else {
      getUINativeModule().search.setPlaceholderColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchPlaceholderColorModifier.identity = Symbol('searchPlaceholderColor');
class SearchCancelButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c;
    if (reset) {
      getUINativeModule().search.resetCancelButton(node);
    }
    else {
      getUINativeModule().search.setCancelButton(node, this.value.style,
        (_a = this.value.icon) === null || _a === void 0 ? void 0 : _a.size,
        (_b = this.value.icon) === null || _b === void 0 ? void 0 : _b.color,
        (_c = this.value.icon) === null || _c === void 0 ? void 0 : _c.src);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f;
    return this.stageValue.style !== this.value.style ||
      !isBaseOrResourceEqual((_a = this.stageValue.icon) === null || _a === void 0 ? void 0 : _a.size, (_b = this.value.icon) === null || _b === void 0 ? void 0 : _b.size) ||
      !isBaseOrResourceEqual((_c = this.stageValue.icon) === null || _c === void 0 ? void 0 : _c.color, (_d = this.value.icon) === null || _d === void 0 ? void 0 : _d.color) ||
      !isBaseOrResourceEqual((_e = this.stageValue.icon) === null || _e === void 0 ? void 0 : _e.src, (_f = this.value.icon) === null || _f === void 0 ? void 0 : _f.src);
  }
}
SearchCancelButtonModifier.identity = Symbol('searchCancelButton');
class SearchTextAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetTextAlign(node);
    }
    else {
      getUINativeModule().search.setTextAlign(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
SearchTextAlignModifier.identity = Symbol('searchTextAlign');
class SearchEnterKeyTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSearchEnterKeyType(node);
    } else {
      getUINativeModule().search.setSearchEnterKeyType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchEnterKeyTypeModifier.identity = Symbol('searchEnterKeyType');
class SearchHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSearchHeight(node);
    } else {
      getUINativeModule().search.setSearchHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchHeightModifier.identity = Symbol('searchHeight');

class SearchIdModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetSearchInspectorId(node);
    } else {
      getUINativeModule().search.setSearchInspectorId(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SearchIdModifier.identity = Symbol('searchId');
class SearchDecorationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().search.resetDecoration(node);
    }
    else {
      getUINativeModule().search.setDecoration(node, this.value.type, this.value.color, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.type !== this.value.type || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (isResource(this.stageValue.color) && isResource(this.value.color)) {
      return !isResourceEqual(this.stageValue.color, this.value.color);
    }
    else if (!isResource(this.stageValue.color) && !isResource(this.value.color)) {
      return !(this.stageValue.color === this.value.color);
    }
    else {
      return true;
    }
  }
}
SearchDecorationModifier.identity = Symbol('searchDecoration');
class SearchLetterSpacingModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetLetterSpacing(node);
        }
        else {
            getUINativeModule().search.setLetterSpacing(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
SearchLetterSpacingModifier.identity = Symbol('searchLetterSpacing');
class SearchLineHeightModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetLineHeight(node);
        }
        else {
            getUINativeModule().search.setLineHeight(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
SearchLineHeightModifier.identity = Symbol('searchLineHeight');
class SearchMinFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetSearchMinFontSize(node);
        }
        else {
            getUINativeModule().search.setSearchMinFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
            
SearchMinFontSizeModifier.identity = Symbol('searchMinFontSize');
class SearchMaxFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetSearchMaxFontSize(node);
        }
        else {
            getUINativeModule().search.setSearchMaxFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
SearchMaxFontSizeModifier.identity = Symbol('searchMaxFontSize');
class SearchSelectedBackgroundColorModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetSelectedBackgroundColor(node);
        } else {
            getUINativeModule().search.setSelectedBackgroundColor(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
SearchSelectedBackgroundColorModifier.identity = Symbol('searchSelectedBackgroundColor');
class SearchTextIndentModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {  
            getUINativeModule().search.resetTextIndent(node);
        } else {
            getUINativeModule().search.setTextIndent(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
SearchTextIndentModifier.identity = Symbol('searchTextIndent');
class SearchInputFilterModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().search.resetInputFilter(node);
        } else {
            getUINativeModule().search.setInputFilter(node, this.value.value, this.value.error);
        }
    }
}
SearchInputFilterModifier.identity = Symbol('searchInputFilter');
class ArkSearchComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onEditChange(callback) {
    throw new Error('Method not implemented.');
  }
  type(value) {
    throw new Error('Method not implemented.');
  }
  maxLength(value) {
    throw new Error('Method not implemented.');
  }
  onEditChanged(callback) {
    throw new Error('Method not implemented.');
  }
  customKeyboard(event) {
    throw new Error('Method not implemented.');
  }
  showUnit(event) {
    throw new Error('Method not implemented.');
  }
  onContentScroll(callback) {
    throw new Error('Method not implemented.');
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  onTextSelectionChange(callback) {
    throw new Error('Method not implemented.');
  }
  onCopy(callback) {
    throw new Error('Method not implemented.');
  }
  onCut(callback) {
    throw new Error('Method not implemented.');
  }
  onSubmit(callback) {
    throw new Error('Method not implemented.');
  }
  onPaste(callback) {
    throw new Error('Method not implemented.');
  }
  showCounter(value) {
    throw new Error('Method not implemented.');
  }
  searchButton(value, option) {
    let searchButton = new ArkSearchButton();
    searchButton.value = value;
    searchButton.fontColor = option === null || option === void 0 ? void 0 : option.fontColor;
    searchButton.fontSize = option === null || option === void 0 ? void 0 : option.fontSize;
    modifierWithKey(this._modifiersWithKeys, SearchSearchButtonModifier.identity, SearchSearchButtonModifier, searchButton);
    return this;
  }
  selectionMenuHidden(value) {
    modifierWithKey(this._modifiersWithKeys, SearchSelectionMenuHiddenModifier.identity, SearchSelectionMenuHiddenModifier, value);
    return this;
  }
  enableKeyboardOnFocus(value) {
    modifierWithKey(this._modifiersWithKeys, SearchEnableKeyboardOnFocusModifier.identity, SearchEnableKeyboardOnFocusModifier, value);
    return this;
  }
  caretStyle(value) {
    modifierWithKey(this._modifiersWithKeys, SearchCaretStyleModifier.identity, SearchCaretStyleModifier, value);
    return this;
  }
  cancelButton(value) {
    modifierWithKey(this._modifiersWithKeys, SearchCancelButtonModifier.identity, SearchCancelButtonModifier, value);
    return this;
  }
  searchIcon(value) {
    modifierWithKey(this._modifiersWithKeys, SearchSearchIconModifier.identity, SearchSearchIconModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, SearchFontColorModifier.identity, SearchFontColorModifier, value);
    return this;
  }
  fontFeature(value) {
    modifierWithKey(this._modifiersWithKeys, SearchFontFeatureModifier.identity, SearchFontFeatureModifier, value);
    return this;
  }
  placeholderColor(value) {
    modifierWithKey(this._modifiersWithKeys, SearchPlaceholderColorModifier.identity, SearchPlaceholderColorModifier, value);
    return this;
  }
  placeholderFont(value) {
    modifierWithKey(this._modifiersWithKeys, SearchPlaceholderFontModifier.identity, SearchPlaceholderFontModifier, value);
    return this;
  }
  textFont(value) {
    modifierWithKey(this._modifiersWithKeys, SearchTextFontModifier.identity, SearchTextFontModifier, value);
    return this;
  }
  copyOption(value) {
    modifierWithKey(this._modifiersWithKeys, SearchCopyOptionModifier.identity, SearchCopyOptionModifier, value);
    return this;
  }
  textAlign(value) {
    modifierWithKey(this._modifiersWithKeys, SearchTextAlignModifier.identity, SearchTextAlignModifier, value);
    return this;
  }
  enterKeyType(value) {
    modifierWithKey(this._modifiersWithKeys, SearchEnterKeyTypeModifier.identity, SearchEnterKeyTypeModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, SearchHeightModifier.identity, SearchHeightModifier, value);
    return this;
  }
  id(value) {
    modifierWithKey(this._modifiersWithKeys, SearchIdModifier.identity, SearchIdModifier, value);
    return this;
  }
  key(value) {
    modifierWithKey(this._modifiersWithKeys, SearchIdModifier.identity, SearchIdModifier, value);
    return this;
  }
  decoration(value) {
    modifierWithKey(this._modifiersWithKeys, SearchDecorationModifier.identity, SearchDecorationModifier, value);
    return this;
  }
  letterSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, SearchLetterSpacingModifier.identity, SearchLetterSpacingModifier, value);
    return this;
  }
  lineHeight(value) {
    modifierWithKey(this._modifiersWithKeys, SearchLineHeightModifier.identity, SearchLineHeightModifier, value);
    return this;
  }
  minFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, SearchMinFontSizeModifier.identity, SearchMinFontSizeModifier, value);
    return this;
  }
  maxFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, SearchMaxFontSizeModifier.identity, SearchMaxFontSizeModifier, value);
    return this;
  }
  selectedBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, SearchSelectedBackgroundColorModifier.identity, SearchSelectedBackgroundColorModifier, value);
    return this;
  }
  textIndent(value) {
    modifierWithKey(this._modifiersWithKeys, SearchTextIndentModifier.identity, SearchTextIndentModifier, value);
    return this;
  }
  inputFilter(value, error) {
    let searchInputFilter = new ArkSearchInputFilter();
    searchInputFilter.value = value;
    searchInputFilter.error = error;

    modifierWithKey(this._modifiersWithKeys, SearchInputFilterModifier.identity, SearchInputFilterModifier, searchInputFilter);
    return this;
  }
}
// @ts-ignore
if (globalThis.Search !== undefined) {
  globalThis.Search.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSearchComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SearchModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class SpanFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFontSize(node);
    }
    else {
      getUINativeModule().span.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanFontSizeModifier.identity = Symbol('spanFontSize');
class SpanFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFontFamily(node);
    }
    else {
      getUINativeModule().span.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanFontFamilyModifier.identity = Symbol('spanFontFamily');
class SpanLineHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetLineHeight(node);
    }
    else {
      getUINativeModule().span.setLineHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanLineHeightModifier.identity = Symbol('spanLineHeight');
class SpanFontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFontStyle(node);
    }
    else {
      getUINativeModule().span.setFontStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanFontStyleModifier.identity = Symbol('spanFontStyle');
class SpanTextCaseModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetTextCase(node);
    }
    else {
      getUINativeModule().span.setTextCase(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanTextCaseModifier.identity = Symbol('spanTextCase');
class SpanTextBackgroundStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetTextBackgroundStyle(node);
    }
    else {
      let textBackgroundStyle = new ArkTextBackGroundStyle();
      if (!textBackgroundStyle.convertTextBackGroundStyleOptions(this.value)) {
        getUINativeModule().span.resetTextBackgroundStyle(node);
      }
      else {
        getUINativeModule().span.setTextBackgroundStyle(node, textBackgroundStyle.color, textBackgroundStyle.radius.topLeft, textBackgroundStyle.radius.topRight, textBackgroundStyle.radius.bottomLeft, textBackgroundStyle.radius.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    let textBackgroundStyle = new ArkTextBackGroundStyle();
    let stageTextBackGroundStyle = new ArkTextBackGroundStyle();
    if (!textBackgroundStyle.convertTextBackGroundStyleOptions(this.value) || !stageTextBackGroundStyle.convertTextBackGroundStyleOptions(this.stageValue)) {
      return false;
    }
    else {
      return textBackgroundStyle.checkObjectDiff(stageTextBackGroundStyle);
    }
  }
}
SpanTextBackgroundStyleModifier.identity = Symbol('spanTextBackgroundStyle');
class SpanTextShadowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetTextShadow(node);
    }
    else {
      let shadow = new ArkShadowInfoToArray();
      if (!shadow.convertShadowOptions(this.value)) {
        getUINativeModule().span.resetTextShadow(node);
      }
      else {
        getUINativeModule().span.setTextShadow(node, shadow.radius, shadow.type, shadow.color,
          shadow.offsetX, shadow.offsetY, shadow.fill, shadow.radius.length);
      }
    }
  }
  checkObjectDiff() {
    let checkDiff = true;
    let arkShadow = new ArkShadowInfoToArray();
    if (Object.getPrototypeOf(this.stageValue).constructor === Object &&
      Object.getPrototypeOf(this.value).constructor === Object) {
      checkDiff = arkShadow.checkDiff(this.stageValue, this.value);
    }
    else if (Object.getPrototypeOf(this.stageValue).constructor === Array &&
      Object.getPrototypeOf(this.value).constructor === Array &&
      this.stageValue.length === this.value.length) {
      let isDiffItem = false;
      for (let i = 0; i < this.value.length; i++) {
        if (arkShadow.checkDiff(this.stageValue[i], this.value[1])) {
          isDiffItem = true;
          break;
        }
      }
      if (!isDiffItem) {
        checkDiff = false;
      }
    }
    return checkDiff;
  }
}
SpanTextShadowModifier.identity = Symbol('spanTextShadow');
class SpanFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFontColor(node);
    }
    else {
      getUINativeModule().span.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpanFontColorModifier.identity = Symbol('spanFontColor');
class SpanLetterSpacingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetLetterSpacing(node);
    }
    else {
      getUINativeModule().span.setLetterSpacing(node, this.value);
    }
  }
}
SpanLetterSpacingModifier.identity = Symbol('spanLetterSpacing');
class SpanBaselineOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetBaselineOffset(node);
    }
    else {
      getUINativeModule().span.setBaselineOffset(node, this.value);
    }
  }
}
SpanBaselineOffsetModifier.identity = Symbol('spanBaselineOffset');
class SpanFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFont(node);
    }
    else {
      getUINativeModule().span.setFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.weight !== this.value.weight || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (((isResource(this.stageValue.size) && isResource(this.value.size) &&
      isResourceEqual(this.stageValue.size, this.value.size)) ||
      (!isResource(this.stageValue.size) && !isResource(this.value.size) &&
        this.stageValue.size === this.value.size)) &&
      ((isResource(this.stageValue.family) && isResource(this.value.family) &&
        isResourceEqual(this.stageValue.family, this.value.family)) ||
        (!isResource(this.stageValue.family) && !isResource(this.value.family) &&
          this.stageValue.family === this.value.family))) {
      return false;
    }
    else {
      return true;
    }
  }
}
SpanFontModifier.identity = Symbol('spanFont');
class SpanDecorationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetDecoration(node);
    }
    else {
      getUINativeModule().span.setDecoration(node, this.value.type, this.value.color, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.type !== this.value.type || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (isResource(this.stageValue.color) && isResource(this.value.color)) {
      return !isResourceEqual(this.stageValue.color, this.value.color);
    }
    else if (!isResource(this.stageValue.color) && !isResource(this.value.color)) {
      return !(this.stageValue.color === this.value.color);
    }
    else {
      return true;
    }
  }
}
SpanDecorationModifier.identity = Symbol('spanDecoration');
class SpanFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.resetFontWeight(node);
    }
    else {
      getUINativeModule().span.setFontWeight(node, this.value);
    }
  }
}
SpanFontWeightModifier.identity = Symbol('spanfontweight');
class SpanInputModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().span.setSpanSrc(node, "");
    }
    else {
      getUINativeModule().span.setSpanSrc(node, this.value);
    }
  }
}
SpanInputModifier.identity = Symbol('spanInput');
class ArkSpanComponent {
  constructor(nativePtr, classType) {
    this._modifiersWithKeys = new Map();
    this.nativePtr = nativePtr;
    this._changed = false;
    this._classType = classType;
    if (classType === ModifierType.STATE) {
      this._weakPtr = getUINativeModule().nativeUtils.createNativeWeakRef(nativePtr);
    }
    this._nativePtrChanged = false;
  }
  initialize(value) {
    if (value[0] != undefined) {
      modifierWithKey(this._modifiersWithKeys, SpanInputModifier.identity, SpanInputModifier, value[0]);
    }
    return this;
  }
  applyModifierPatch() {
    let expiringItemsWithKeys = [];
    this._modifiersWithKeys.forEach((value, key) => {
      if (value.applyStage(this.nativePtr)) {
        expiringItemsWithKeys.push(key);
      }
    });
    expiringItemsWithKeys.forEach(key => {
      this._modifiersWithKeys.delete(key);
    });
  }
  cleanStageValue() {
    if (!this._modifiersWithKeys) {
      return;
    }
    this._modifiersWithKeys.forEach((value, key) => {
        value.stageValue = undefined;
    });
  }
  applyStateUpdatePtr(instance) {
    if (this.nativePtr !== instance.nativePtr) {
      this.nativePtr = instance.nativePtr;
      this._nativePtrChanged = true;
      this._weakPtr = getUINativeModule().nativeUtils.createNativeWeakRef(instance.nativePtr);
    }
  }
  onGestureJudgeBegin(callback) {
    throw new Error('Method not implemented.');
  }
  outline(value) {
    throw new Error('Method not implemented.');
  }
  outlineColor(value) {
    throw new Error('Method not implemented.');
  }
  outlineRadius(value) {
    throw new Error('Method not implemented.');
  }
  outlineStyle(value) {
    throw new Error('Method not implemented.');
  }
  outlineWidth(value) {
    throw new Error('Method not implemented.');
  }
  width(value) {
    throw new Error('Method not implemented.');
  }
  height(value) {
    throw new Error('Method not implemented.');
  }
  expandSafeArea(types, edges) {
    throw new Error('Method not implemented.');
  }
  responseRegion(value) {
    throw new Error('Method not implemented.');
  }
  mouseResponseRegion(value) {
    throw new Error('Method not implemented.');
  }
  size(value) {
    throw new Error('Method not implemented.');
  }
  constraintSize(value) {
    throw new Error('Method not implemented.');
  }
  touchable(value) {
    throw new Error('Method not implemented.');
  }
  hitTestBehavior(value) {
    throw new Error('Method not implemented.');
  }
  layoutWeight(value) {
    throw new Error('Method not implemented.');
  }
  padding(value) {
    throw new Error('Method not implemented.');
  }
  margin(value) {
    throw new Error('Method not implemented.');
  }
  background(builder, options) {
    throw new Error('Method not implemented.');
  }
  backgroundColor(value) {
    throw new Error('Method not implemented.');
  }
  backgroundImage(src, repeat) {
    throw new Error('Method not implemented.');
  }
  backgroundImageSize(value) {
    throw new Error('Method not implemented.');
  }
  backgroundImagePosition(value) {
    throw new Error('Method not implemented.');
  }
  backgroundBlurStyle(value, options) {
    throw new Error('Method not implemented.');
  }
  foregroundBlurStyle(value, options) {
    throw new Error('Method not implemented.');
  }
  opacity(value) {
    throw new Error('Method not implemented.');
  }
  border(value) {
    throw new Error('Method not implemented.');
  }
  borderStyle(value) {
    throw new Error('Method not implemented.');
  }
  borderWidth(value) {
    throw new Error('Method not implemented.');
  }
  borderColor(value) {
    throw new Error('Method not implemented.');
  }
  borderRadius(value) {
    throw new Error('Method not implemented.');
  }
  borderImage(value) {
    throw new Error('Method not implemented.');
  }
  foregroundColor(value) {
    throw new Error('Method not implemented.');
  }
  onClick(event) {
    modifierWithKey(this._modifiersWithKeys, ClickModifier.identity, ClickModifier, event);
    return this;
  }
  onHover(event) {
    throw new Error('Method not implemented.');
  }
  hoverEffect(value) {
    throw new Error('Method not implemented.');
  }
  onMouse(event) {
    throw new Error('Method not implemented.');
  }
  onTouch(event) {
    throw new Error('Method not implemented.');
  }
  onKeyEvent(event) {
    throw new Error('Method not implemented.');
  }
  focusable(value) {
    throw new Error('Method not implemented.');
  }
  onFocus(event) {
    throw new Error('Method not implemented.');
  }
  onBlur(event) {
    throw new Error('Method not implemented.');
  }
  tabIndex(index) {
    throw new Error('Method not implemented.');
  }
  defaultFocus(value) {
    throw new Error('Method not implemented.');
  }
  groupDefaultFocus(value) {
    throw new Error('Method not implemented.');
  }
  focusOnTouch(value) {
    throw new Error('Method not implemented.');
  }
  animation(value) {
    throw new Error('Method not implemented.');
  }
  transition(value) {
    throw new Error('Method not implemented.');
  }
  gesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  priorityGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  parallelGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  blur(value) {
    throw new Error('Method not implemented.');
  }
  linearGradientBlur(value, options) {
    throw new Error('Method not implemented.');
  }
  brightness(value) {
    throw new Error('Method not implemented.');
  }
  contrast(value) {
    throw new Error('Method not implemented.');
  }
  grayscale(value) {
    throw new Error('Method not implemented.');
  }
  colorBlend(value) {
    throw new Error('Method not implemented.');
  }
  saturate(value) {
    throw new Error('Method not implemented.');
  }
  sepia(value) {
    throw new Error('Method not implemented.');
  }
  invert(value) {
    throw new Error('Method not implemented.');
  }
  hueRotate(value) {
    throw new Error('Method not implemented.');
  }
  useEffect(value) {
    throw new Error('Method not implemented.');
  }
  backdropBlur(value) {
    throw new Error('Method not implemented.');
  }
  renderGroup(value) {
    throw new Error('Method not implemented.');
  }
  translate(value) {
    throw new Error('Method not implemented.');
  }
  scale(value) {
    throw new Error('Method not implemented.');
  }
  gridSpan(value) {
    throw new Error('Method not implemented.');
  }
  gridOffset(value) {
    throw new Error('Method not implemented.');
  }
  rotate(value) {
    throw new Error('Method not implemented.');
  }
  transform(value) {
    throw new Error('Method not implemented.');
  }
  onAppear(event) {
    throw new Error('Method not implemented.');
  }
  onDisAppear(event) {
    throw new Error('Method not implemented.');
  }
  onAttach(event) {
    throw new Error('Method not implemented.');
  }
  onDetach(event) {
    throw new Error('Method not implemented.');
  }
  onAreaChange(event) {
    throw new Error('Method not implemented.');
  }
  visibility(value) {
    throw new Error('Method not implemented.');
  }
  flexGrow(value) {
    throw new Error('Method not implemented.');
  }
  flexShrink(value) {
    throw new Error('Method not implemented.');
  }
  flexBasis(value) {
    throw new Error('Method not implemented.');
  }
  alignSelf(value) {
    throw new Error('Method not implemented.');
  }
  displayPriority(value) {
    throw new Error('Method not implemented.');
  }
  zIndex(value) {
    throw new Error('Method not implemented.');
  }
  sharedTransition(id, options) {
    throw new Error('Method not implemented.');
  }
  direction(value) {
    throw new Error('Method not implemented.');
  }
  align(value) {
    throw new Error('Method not implemented.');
  }
  position(value) {
    throw new Error('Method not implemented.');
  }
  markAnchor(value) {
    throw new Error('Method not implemented.');
  }
  offset(value) {
    throw new Error('Method not implemented.');
  }
  enabled(value) {
    throw new Error('Method not implemented.');
  }
  useSizeType(value) {
    throw new Error('Method not implemented.');
  }
  alignRules(value) {
    throw new Error('Method not implemented.');
  }
  aspectRatio(value) {
    throw new Error('Method not implemented.');
  }
  clickEffect(value) {
    throw new Error('Method not implemented.');
  }
  onDragStart(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnter(event) {
    throw new Error('Method not implemented.');
  }
  onDragMove(event) {
    throw new Error('Method not implemented.');
  }
  onDragLeave(event) {
    throw new Error('Method not implemented.');
  }
  onDrop(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnd(event) {
    throw new Error('Method not implemented.');
  }
  allowDrop(value) {
    throw new Error('Method not implemented.');
  }
  draggable(value) {
    throw new Error('Method not implemented.');
  }
  overlay(value, options) {
    throw new Error('Method not implemented.');
  }
  linearGradient(value) {
    throw new Error('Method not implemented.');
  }
  sweepGradient(value) {
    throw new Error('Method not implemented.');
  }
  radialGradient(value) {
    throw new Error('Method not implemented.');
  }
  motionPath(value) {
    throw new Error('Method not implemented.');
  }
  motionBlur(value) {
    throw new Error('Method not implemented.');
  }
  shadow(value) {
    throw new Error('Method not implemented.');
  }
  mask(value) {
    throw new Error('Method not implemented.');
  }
  key(value) {
    throw new Error('Method not implemented.');
  }
  id(value) {
    throw new Error('Method not implemented.');
  }
  geometryTransition(id) {
    throw new Error('Method not implemented.');
  }
  bindPopup(show, popup) {
    throw new Error('Method not implemented.');
  }
  bindMenu(content, options) {
    throw new Error('Method not implemented.');
  }
  bindContextMenu(content, responseType, options) {
    throw new Error('Method not implemented.');
  }
  bindContentCover(isShow, builder, type) {
    throw new Error('Method not implemented.');
  }
  blendMode(value) {
    throw new Error('Method not implemented.');
  }
  clip(value) {
    throw new Error('Method not implemented.');
  }
  bindSheet(isShow, builder, options) {
    throw new Error('Method not implemented.');
  }
  stateStyles(value) {
    throw new Error('Method not implemented.');
  }
  restoreId(value) {
    throw new Error('Method not implemented.');
  }
  onVisibleAreaChange(ratios, event) {
    throw new Error('Method not implemented.');
  }
  sphericalEffect(value) {
    throw new Error('Method not implemented.');
  }
  lightUpEffect(value) {
    throw new Error('Method not implemented.');
  }
  pixelStretchEffect(options) {
    throw new Error('Method not implemented.');
  }
  keyboardShortcut(value, keys, action) {
    throw new Error('Method not implemented.');
  }
  accessibilityGroup(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityText(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityDescription(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityLevel(value) {
    throw new Error('Method not implemented.');
  }
  obscured(reasons) {
    throw new Error('Method not implemented.');
  }
  reuseId(id) {
    throw new Error('Method not implemented.');
  }
  renderFit(fitMode) {
    throw new Error('Method not implemented.');
  }
  attributeModifier(modifier) {
    return this;
  }
  decoration(value) {
    modifierWithKey(this._modifiersWithKeys, SpanDecorationModifier.identity, SpanDecorationModifier, value);
    return this;
  }
  font(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontSizeModifier.identity, SpanFontSizeModifier,
      value === null || value === void 0 ? void 0 : value.size);
    modifierWithKey(this._modifiersWithKeys, SpanFontWeightModifier.identity, SpanFontWeightModifier,
      value === null || value === void 0 ? void 0 : value.weight);
    modifierWithKey(this._modifiersWithKeys, SpanFontFamilyModifier.identity, SpanFontFamilyModifier,
      value === null || value === void 0 ? void 0 : value.family);
    modifierWithKey(this._modifiersWithKeys, SpanFontStyleModifier.identity, SpanFontStyleModifier,
      value === null || value === void 0 ? void 0 : value.style);
    return this;
  }
  lineHeight(value) {
    modifierWithKey(this._modifiersWithKeys, SpanLineHeightModifier.identity, SpanLineHeightModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontSizeModifier.identity, SpanFontSizeModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontColorModifier.identity, SpanFontColorModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontStyleModifier.identity, SpanFontStyleModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontWeightModifier.identity, SpanFontWeightModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, SpanFontFamilyModifier.identity, SpanFontFamilyModifier, value);
    return this;
  }
  letterSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, SpanLetterSpacingModifier.identity, SpanLetterSpacingModifier, value);
    return this;
  }
  baselineOffset(value) {
    modifierWithKey(this._modifiersWithKeys, SpanBaselineOffsetModifier.identity, SpanBaselineOffsetModifier, value);
    return this;
  }
  textCase(value) {
    modifierWithKey(this._modifiersWithKeys, SpanTextCaseModifier.identity, SpanTextCaseModifier, value);
    return this;
  }
  textBackgroundStyle(value) {
    modifierWithKey(this._modifiersWithKeys, SpanTextBackgroundStyleModifier.identity, SpanTextBackgroundStyleModifier, value);
    return this;
  }
  textShadow(value) {
    modifierWithKey(this._modifiersWithKeys, SpanTextShadowModifier.identity, SpanTextShadowModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Span !== undefined) {
  globalThis.Span.attributeModifier = function (modifier) {
    attributeModifierFuncWithoutStateStyles.call(this, modifier, (nativePtr) => {
      return new ArkSpanComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SpanModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class SideBarContainerPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetSideBarPosition(node);
    }
    else {
      getUINativeModule().sideBarContainer.setSideBarPosition(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerPositionModifier.identity = Symbol('sideBarContainerPosition');
class SideBarContainerAutoHideModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetAutoHide(node);
    }
    else {
      getUINativeModule().sideBarContainer.setAutoHide(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerAutoHideModifier.identity = Symbol('sideBarContainerautoHide');
class SideBarContainerShowSideBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetShowSideBar(node);
    }
    else {
      getUINativeModule().sideBarContainer.setShowSideBar(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerShowSideBarModifier.identity = Symbol('sideBarContainerShowSideBar');
class SideBarContainerMaxSideBarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetMaxSideBarWidth(node);
    }
    else {
      getUINativeModule().sideBarContainer.setMaxSideBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerMaxSideBarWidthModifier.identity = Symbol('sideBarContainerMaxSideBarWidth');
class SideBarContainerWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetSideBarWidth(node);
    }
    else {
      getUINativeModule().sideBarContainer.setSideBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerWidthModifier.identity = Symbol('sideBarContainerWidth');
class SideBarContainerMinContentWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetMinContentWidth(node);
    }
    else {
      getUINativeModule().sideBarContainer.setMinContentWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerMinContentWidthModifier.identity = Symbol('sideBarContainerMinContentWidth');
class SideBarContainerShowControlButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetShowControlButton(node);
    }
    else {
      getUINativeModule().sideBarContainer.setShowControlButton(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerShowControlButtonModifier.identity = Symbol('sideBarContainerShowControlButton');
class SideBarContainerMinSideBarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetMinSideBarWidth(node);
    }
    else {
      getUINativeModule().sideBarContainer.setMinSideBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SideBarContainerMinSideBarWidthModifier.identity = Symbol('sideBarContainerMinSideBarWidth');
class SideBarContainerControlButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c;
    if (reset) {
      getUINativeModule().sideBarContainer.resetControlButton(node);
    }
    else {
      getUINativeModule().sideBarContainer.setControlButton(node, this.value.left,
        this.value.top, this.value.width, this.value.height, (_a = this.value.icons) === null ||
        _a === void 0 ? void 0 : _a.shown, (_b = this.value.icons) === null ||
        _b === void 0 ? void 0 : _b.hidden, (_c = this.value.icons) === null ||
        _c === void 0 ? void 0 : _c.switching);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f;
    if (!(this.stageValue.left === this.value.left &&
      this.stageValue.top === this.value.top &&
      this.stageValue.width === this.value.width &&
      this.stageValue.height === this.value.height)) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_a = this.stageValue.icons) === null || _a === void 0 ? void 0 : _a.shown, (_b = this.value.icons) === null ||
      _b === void 0 ? void 0 : _b.shown) ||
        !isBaseOrResourceEqual((_c = this.stageValue.icons) === null || _c === void 0 ? void 0 : _c.hidden, (_d = this.value.icons) === null ||
        _d === void 0 ? void 0 : _d.hidden) ||
        !isBaseOrResourceEqual((_e = this.stageValue.icons) === null || _e === void 0 ? void 0 : _e.switching, (_f = this.value.icons) === null ||
        _f === void 0 ? void 0 : _f.switching);
    }
  }
}
SideBarContainerControlButtonModifier.identity = Symbol('sideBarContainercontrolButton');
class SideBarContainerDividerModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().sideBarContainer.resetDivider(node);
    }
    else {
      if (!this.value || !isObject(this.value) || !this.value.strokeWidth) {
        getUINativeModule().sideBarContainer.resetDivider(node);
      }
      else {
        getUINativeModule().sideBarContainer.setDivider(node, this.value.strokeWidth, this.value.color, this.value.startMargin, this.value.endMargin);
      }
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.strokeWidth, this.value.strokeWidth) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color) ||
      !isBaseOrResourceEqual(this.stageValue.startMargin, this.value.startMargin) ||
      !isBaseOrResourceEqual(this.stageValue.endMargin, this.value.endMargin);
  }
}
SideBarContainerDividerModifier.identity = Symbol('sideBarContainerdivider');
class ArkSideBarContainerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  autoHide(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerAutoHideModifier.identity, SideBarContainerAutoHideModifier, value);
    return this;
  }
  showSideBar(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerShowSideBarModifier.identity, SideBarContainerShowSideBarModifier, value);
    return this;
  }
  maxSideBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerMaxSideBarWidthModifier.identity, SideBarContainerMaxSideBarWidthModifier, value);
    return this;
  }
  minSideBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerMinSideBarWidthModifier.identity, SideBarContainerMinSideBarWidthModifier, value);
    return this;
  }
  minContentWidth(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerMinContentWidthModifier.identity, SideBarContainerMinContentWidthModifier, value);
    return this;
  }
  controlButton(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerControlButtonModifier.identity, SideBarContainerControlButtonModifier, value);
    return this;
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerDividerModifier.identity, SideBarContainerDividerModifier, value);
    return this;
  }
  sideBarPosition(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerPositionModifier.identity, SideBarContainerPositionModifier, value);
    return this;
  }
  sideBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerWidthModifier.identity, SideBarContainerWidthModifier, value);
    return this;
  }
  showControlButton(value) {
    modifierWithKey(this._modifiersWithKeys, SideBarContainerShowControlButtonModifier.identity, SideBarContainerShowControlButtonModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.SideBarContainer !== undefined) {
  globalThis.SideBarContainer.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSideBarContainerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SideBarContainerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkStackComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      this.alignContent(value[0].alignContent);
    }
    return this
  }
  alignContent(value) {
    modifierWithKey(this._modifiersWithKeys, StackAlignContentModifier.identity, StackAlignContentModifier, value);
    return this;
  }
  align(value) {
    modifierWithKey(this._modifiersWithKeys, StackAlignContentModifier.identity, StackAlignContentModifier, value);
    return this;
  }
}
class StackAlignContentModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().stack.resetAlignContent(node);
    }
    else {
      getUINativeModule().stack.setAlignContent(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
StackAlignContentModifier.identity = Symbol('stackAlignContent');
// @ts-ignore
if (globalThis.Stack !== undefined) {
  globalThis.Stack.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkStackComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.StackModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class TextEnableDataDetectorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetEnableDataDetector(node);
    }
    else {
      getUINativeModule().text.setEnableDataDetector(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextEnableDataDetectorModifier.identity = Symbol('textEnableDataDetector');
class FontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontColor(node);
    }
    else {
      getUINativeModule().text.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FontColorModifier.identity = Symbol('textFontColor');
class TextForegroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextForegroundColor(node);
    }
    else {
      getUINativeModule().text.setTextForegroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextForegroundColorModifier.identity = Symbol('textForegroundColor');
class FontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontSize(node);
    }
    else {
      getUINativeModule().text.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FontSizeModifier.identity = Symbol('textFontSize');
class FontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontWeight(node);
    }
    else {
      getUINativeModule().text.setFontWeight(node, this.value);
    }
  }
}
FontWeightModifier.identity = Symbol('textFontWeight');
class FontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontStyle(node);
    }
    else {
      getUINativeModule().text.setFontStyle(node, this.value);
    }
  }
}
FontStyleModifier.identity = Symbol('textFontStyle');
class TextAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextAlign(node);
    }
    else {
      getUINativeModule().text.setTextAlign(node, this.value);
    }
  }
}
TextAlignModifier.identity = Symbol('textAlign');
class TextHeightAdaptivePolicyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetHeightAdaptivePolicy(node);
    }
    else {
      getUINativeModule().text.setHeightAdaptivePolicy(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextHeightAdaptivePolicyModifier.identity = Symbol('textHeightAdaptivePolicy');
class TextDraggableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetDraggable(node);
    }
    else {
      getUINativeModule().text.setDraggable(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextDraggableModifier.identity = Symbol('textDraggable');
class TextWordBreakModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetWordBreak(node);
    }
    else {
      getUINativeModule().text.setWordBreak(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextWordBreakModifier.identity = Symbol('textWordBreak');

class TextLineBreakStrategyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetLineBreakStrategy(node);
    }
    else {
      getUINativeModule().text.setLineBreakStrategy(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextLineBreakStrategyModifier.identity = Symbol('textLineBreakStrategy');

class TextFontFeatureModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontFeature(node);
    } else {
      getUINativeModule().text.setFontFeature(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextWordBreakModifier.identity = Symbol('textFontFeature');

class TextEllipsisModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetEllipsisMode(node);
    }
    else {
      getUINativeModule().text.setEllipsisMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextEllipsisModeModifier.identity = Symbol('textEllipsisMode');
class TextMinFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetMinFontSize(node);
    }
    else if (!isNumber(this.value) && !isString(this.value) && !isResource(this.value)) {
      getUINativeModule().text.resetMinFontSize(node);
    }
    else {
      getUINativeModule().text.setMinFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextMinFontSizeModifier.identity = Symbol('textMinFontSize');
class TextMaxFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetMaxFontSize(node);
    }
    else if (!isNumber(this.value) && !isString(this.value) && !isResource(this.value)) {
      getUINativeModule().text.resetMaxFontSize(node);
    }
    else {
      getUINativeModule().text.setMaxFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextMaxFontSizeModifier.identity = Symbol('textMaxFontSize');
class TextLineHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetLineHeight(node);
    }
    else if (!isNumber(this.value) && !isString(this.value) && !isResource(this.value)) {
      getUINativeModule().text.resetLineHeight(node);
    }
    else {
      getUINativeModule().text.setLineHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextLineHeightModifier.identity = Symbol('textLineHeight');
class TextCopyOptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetCopyOption(node);
    }
    else {
      getUINativeModule().text.setCopyOption(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextCopyOptionModifier.identity = Symbol('textCopyOption');
class TextFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFontFamily(node);
    }
    else if (!isString(this.value) && !isResource(this.value)) {
      getUINativeModule().text.resetFontFamily(node);
    }
    else {
      getUINativeModule().text.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextFontFamilyModifier.identity = Symbol('textFontFamily');
class TextMaxLinesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetMaxLines(node);
    }
    else if (!isNumber(this.value)) {
      getUINativeModule().text.resetMaxLines(node);
    }
    else {
      getUINativeModule().text.setMaxLines(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextMaxLinesModifier.identity = Symbol('textMaxLines');
class TextLetterSpacingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetLetterSpacing(node);
    }
    else if (!isNumber(this.value) && !isString(this.value)) {
      getUINativeModule().text.resetLetterSpacing(node);
    }
    else {
      getUINativeModule().text.setLetterSpacing(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextLetterSpacingModifier.identity = Symbol('textLetterSpacing');
class TextLineSpacingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetLineSpacing(node);
    }
    else if (!isObject(this.value)) {
      getUINativeModule().text.resetLineSpacing(node);
    }
    else {
      getUINativeModule().text.setLineSpacing(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextLineSpacingModifier.identity = Symbol('textLineSpacing');
class TextTextOverflowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextOverflow(node);
    }
    else {
      getUINativeModule().text.setTextOverflow(node, this.value.overflow);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.overflow, this.value.overflow);
  }
}
TextTextOverflowModifier.identity = Symbol('textTextOverflow');
class TextBaselineOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetBaselineOffset(node);
    }
    else if (!isNumber(this.value) && !isString(this.value)) {
      getUINativeModule().text.resetBaselineOffset(node);
    }
    else {
      getUINativeModule().text.setBaselineOffset(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextBaselineOffsetModifier.identity = Symbol('textBaselineOffset');
class TextTextCaseModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextCase(node);
    }
    else {
      getUINativeModule().text.setTextCase(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTextCaseModifier.identity = Symbol('textTextCase');
class TextTextIndentModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextIndent(node);
    }
    else if (!isNumber(this.value) && !isString(this.value) && !isResource(this.value)) {
      getUINativeModule().text.resetTextIndent(node);
    }
    else {
      getUINativeModule().text.setTextIndent(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTextIndentModifier.identity = Symbol('textTextIndent');
class TextTextShadowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetTextShadow(node);
    }
    else {
      let shadow = new ArkShadowInfoToArray();
      if (!shadow.convertShadowOptions(this.value)) {
        getUINativeModule().text.resetTextShadow(node);
      }
      else {
        getUINativeModule().text.setTextShadow(node, shadow.radius, shadow.type, shadow.color,
          shadow.offsetX, shadow.offsetY, shadow.fill, shadow.radius.length);
      }
    }
  }
  checkObjectDiff() {
    let checkDiff = true;
    let arkShadow = new ArkShadowInfoToArray();
    if (Object.getPrototypeOf(this.stageValue).constructor === Object &&
      Object.getPrototypeOf(this.value).constructor === Object) {
      checkDiff = arkShadow.checkDiff(this.stageValue, this.value);
    }
    else if (Object.getPrototypeOf(this.stageValue).constructor === Array &&
      Object.getPrototypeOf(this.value).constructor === Array &&
      this.stageValue.length === this.value.length) {
      let isDiffItem = false;
      for (let i = 0; i < this.value.length; i++) {
        if (arkShadow.checkDiff(this.stageValue[i], this.value[1])) {
          isDiffItem = true;
          break;
        }
      }
      if (!isDiffItem) {
        checkDiff = false;
      }
    }
    return checkDiff;
  }
}
TextTextShadowModifier.identity = Symbol('textTextShadow');
class TextDecorationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetDecoration(node);
    }
    else {
      getUINativeModule().text.setDecoration(node, this.value.type, this.value.color, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.type !== this.value.type || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (isResource(this.stageValue.color) && isResource(this.value.color)) {
      return !isResourceEqual(this.stageValue.color, this.value.color);
    }
    else if (!isResource(this.stageValue.color) && !isResource(this.value.color)) {
      return !(this.stageValue.color === this.value.color);
    }
    else {
      return true;
    }
  }
}
TextDecorationModifier.identity = Symbol('textDecoration');
class TextFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.resetFont(node);
    }
    else {
      getUINativeModule().text.setFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.weight !== this.value.weight || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (((isResource(this.stageValue.size) && isResource(this.value.size) &&
      isResourceEqual(this.stageValue.size, this.value.size)) ||
      (!isResource(this.stageValue.size) && !isResource(this.value.size) &&
        this.stageValue.size === this.value.size)) &&
      ((isResource(this.stageValue.family) && isResource(this.value.family) &&
        isResourceEqual(this.stageValue.family, this.value.family)) ||
        (!isResource(this.stageValue.family) && !isResource(this.value.family) &&
          this.stageValue.family === this.value.family))) {
      return false;
    }
    else {
      return true;
    }
  }
}
TextFontModifier.identity = Symbol('textFont');
class TextClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
TextClipModifier.identity = Symbol('textClip');

class TextContentModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().text.setContent(node, "");
    }
    else {
      getUINativeModule().text.setContent(node, this.value);
    }
  }
}
TextContentModifier.identity = Symbol('textContent');

class ArkTextComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(content) {
    modifierWithKey(this._modifiersWithKeys, TextContentModifier.identity, TextContentModifier, content[0]);
    return this;
  }
  enableDataDetector(value) {
    modifierWithKey(this._modifiersWithKeys, TextEnableDataDetectorModifier.identity, TextEnableDataDetectorModifier, value);
    return this;
  }
  dataDetectorConfig(config) {
    throw new Error('Method not implemented.');
  }
  font(value) {
    modifierWithKey(this._modifiersWithKeys, TextFontModifier.identity, TextFontModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, FontColorModifier.identity, FontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, FontSizeModifier.identity, FontSizeModifier, value);
    return this;
  }
  minFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextMinFontSizeModifier.identity, TextMinFontSizeModifier, value);
    return this;
  }
  maxFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextMaxFontSizeModifier.identity, TextMaxFontSizeModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, FontStyleModifier.identity, FontStyleModifier, value);
    return this;
  }
  fontWeight(value) {
    let fontWeightStr = '400';
    if (isNumber(value)) {
      fontWeightStr = value.toString();
    }
    else if (isString(value)) {
      fontWeightStr = String(value);
    }
    modifierWithKey(this._modifiersWithKeys, FontWeightModifier.identity, FontWeightModifier, fontWeightStr);
    return this;
  }
  textAlign(value) {
    modifierWithKey(this._modifiersWithKeys, TextAlignModifier.identity, TextAlignModifier, value);
    return this;
  }
  lineHeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextLineHeightModifier.identity, TextLineHeightModifier, value);
    return this;
  }
  textOverflow(value) {
    modifierWithKey(this._modifiersWithKeys, TextTextOverflowModifier.identity, TextTextOverflowModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, TextFontFamilyModifier.identity, TextFontFamilyModifier, value);
    return this;
  }
  maxLines(value) {
    modifierWithKey(this._modifiersWithKeys, TextMaxLinesModifier.identity, TextMaxLinesModifier, value);
    return this;
  }
  decoration(value) {
    modifierWithKey(this._modifiersWithKeys, TextDecorationModifier.identity, TextDecorationModifier, value);
    return this;
  }
  letterSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, TextLetterSpacingModifier.identity, TextLetterSpacingModifier, value);
    return this;
  }
  lineSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, TextLineSpacingModifier.identity, TextLineSpacingModifier, value);
    return this;
  }
  textCase(value) {
    modifierWithKey(this._modifiersWithKeys, TextTextCaseModifier.identity, TextTextCaseModifier, value);
    return this;
  }
  baselineOffset(value) {
    modifierWithKey(this._modifiersWithKeys, TextBaselineOffsetModifier.identity, TextBaselineOffsetModifier, value);
    return this;
  }
  copyOption(value) {
    modifierWithKey(this._modifiersWithKeys, TextCopyOptionModifier.identity, TextCopyOptionModifier, value);
    return this;
  }
  draggable(value) {
    modifierWithKey(this._modifiersWithKeys, TextDraggableModifier.identity, TextDraggableModifier, value);
    return this;
  }
  textShadow(value) {
    modifierWithKey(this._modifiersWithKeys, TextTextShadowModifier.identity, TextTextShadowModifier, value);
    return this;
  }
  heightAdaptivePolicy(value) {
    modifierWithKey(this._modifiersWithKeys, TextHeightAdaptivePolicyModifier.identity, TextHeightAdaptivePolicyModifier, value);
    return this;
  }
  textIndent(value) {
    modifierWithKey(this._modifiersWithKeys, TextTextIndentModifier.identity, TextTextIndentModifier, value);
    return this;
  }
  wordBreak(value) {
    modifierWithKey(this._modifiersWithKeys, TextWordBreakModifier.identity, TextWordBreakModifier, value);
    return this;
  }
  lineBreakStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, TextLineBreakStrategyModifier.identity,
      TextLineBreakStrategyModifier, value);
    return this;
  }
  fontFeature(value) {
    modifierWithKey(this._modifiersWithKeys, TextFontFeatureModifier.identity, TextFontFeatureModifier, value);
    return this;
  }
  onCopy(callback) {
    throw new Error('Method not implemented.');
  }
  selection(selectionStart, selectionEnd) {
    throw new Error('Method not implemented.');
  }
  ellipsisMode(value) {
    modifierWithKey(this._modifiersWithKeys, TextEllipsisModeModifier.identity, TextEllipsisModeModifier, value);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, TextClipModifier.identity, TextClipModifier, value);
    return this;
  }
  foregroundColor(value) {
    modifierWithKey(
      this._modifiersWithKeys, TextForegroundColorModifier.identity, TextForegroundColorModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Text !== undefined) {
  globalThis.Text.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class TextAreaFontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontStyle(node);
    }
    else {
      getUINativeModule().textArea.setFontStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontStyleModifier.identity = Symbol('textAreaFontStyle');
class TextAreaDecorationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetDecoration(node);
    }
    else {
      getUINativeModule().textArea.setDecoration(node, this.value.type, this.value.color, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.type !== this.value.type || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (isResource(this.stageValue.color) && isResource(this.value.color)) {
      return !isResourceEqual(this.stageValue.color, this.value.color);
    }
    else if (!isResource(this.stageValue.color) && !isResource(this.value.color)) {
      return !(this.stageValue.color === this.value.color);
    }
    else {
      return true;
    }
  }
}
TextAreaDecorationModifier.identity = Symbol('textAreaDecoration');
class TextAreaLetterSpacingModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetLetterSpacing(node);
        }
        else {
            getUINativeModule().textArea.setLetterSpacing(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaLetterSpacingModifier.identity = Symbol('textAreaLetterSpacing');
class TextAreaLineSpacingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetLineSpacing(node);
    }
    else if (!isObject(this.value)) {
      getUINativeModule().textArea.resetLineSpacing(node);
    }
    else {
      getUINativeModule().textArea.setLineSpacing(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaLineSpacingModifier.identity = Symbol('textAreaLineSpacing');
class TextAreaLineHeightModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetLineHeight(node);
        }
        else {
            getUINativeModule().textArea.setLineHeight(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaLineHeightModifier.identity = Symbol('textAreaLineHeight');
class TextAreaWordBreakModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetWordBreak(node);
        }
        else {
            getUINativeModule().textArea.setWordBreak(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaWordBreakModifier.identity = Symbol('textAreaWordBreak');

class TextAreaLineBreakStrategyModifier extends ModifierWithKey {
  constructor(value) {
      super(value);
  }
  applyPeer(node, reset) {
      if (reset) {
          getUINativeModule().textArea.resetLineBreakStrategy(node);
      }
      else {
          getUINativeModule().textArea.setLineBreakStrategy(node, this.value);
      }
  }
  checkObjectDiff() {
      return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaLineBreakStrategyModifier.identity = Symbol('textAreaLineBreakStrategy');
class TextAreaSelectedBackgroundColorModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetSelectedBackgroundColor(node);
        } else {
            getUINativeModule().textArea.setSelectedBackgroundColor(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaSelectedBackgroundColorModifier.identity = Symbol('textAreaSelectedBackgroundColor');
class TextAreaCaretStyleModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetCaretStyle(node);
        } else {
            getUINativeModule().textArea.setCaretStyle(node, this.value.width, this.value.color);
        }
    }
    checkObjectDiff() {
        return this.stageValue !== this.value;
    }
}
TextAreaCaretStyleModifier.identity = Symbol('textAreaCaretStyle');
class TextAreaTextOverflowModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetTextOverflow(node);
        } else {
            getUINativeModule().textArea.setTextOverflow(node, this.value);
        }
    }
    checkObjectDiff() {
        return this.stageValue !== this.value;
    }
}
TextAreaTextOverflowModifier.identity = Symbol('textAreaTextOverflow');
class TextAreaTextIndentModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetTextIndent(node);
        } else {
            getUINativeModule().textArea.setTextIndent(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaTextIndentModifier.identity = Symbol('textAreaTextIndent');
class TextAreaCopyOptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetCopyOption(node);
    }
    else {
      getUINativeModule().textArea.setCopyOption(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaCopyOptionModifier.identity = Symbol('textAreaCopyOption');
class TextAreaMaxLinesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetMaxLines(node);
    }
    else {
      getUINativeModule().textArea.setMaxLines(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaMaxLinesModifier.identity = Symbol('textAreaMaxLines');
class TextAreaMinFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetMinFontSize(node);
        }
        else {
            getUINativeModule().textArea.setMinFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaMinFontSizeModifier.identity = Symbol('textAreaMinFontSize');
class TextAreaMaxFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetMaxFontSize(node);
        }
        else {
            getUINativeModule().textArea.setMaxFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaMaxFontSizeModifier.identity = Symbol('textAreaMaxFontSize');
class TextAreaHeightAdaptivePolicyModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textArea.resetHeightAdaptivePolicy(node);
        }
        else {
            getUINativeModule().textArea.setHeightAdaptivePolicy(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextAreaHeightAdaptivePolicyModifier.identity = Symbol('textAreaHeightAdaptivePolicy');
class TextAreaFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontSize(node);
    }
    else {
      getUINativeModule().textArea.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontSizeModifier.identity = Symbol('textAreaFontSize');
class TextAreaPlaceholderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetPlaceholderColor(node);
    }
    else {
      getUINativeModule().textArea.setPlaceholderColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaPlaceholderColorModifier.identity = Symbol('textAreaPlaceholderColor');
class TextAreaFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontColor(node);
    }
    else {
      getUINativeModule().textArea.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontColorModifier.identity = Symbol('textAreaFontColor');
class TextAreaFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontWeight(node);
    }
    else {
      getUINativeModule().textArea.setFontWeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontWeightModifier.identity = Symbol('textAreaFontWeight');
class TextAreaBarStateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBarState(node);
    }
    else {
      getUINativeModule().textArea.setBarState(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaBarStateModifier.identity = Symbol('textAreaBarState');
class TextAreaEnableKeyboardOnFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetEnableKeyboardOnFocus(node);
    }
    else {
      getUINativeModule().textArea.setEnableKeyboardOnFocus(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaEnableKeyboardOnFocusModifier.identity = Symbol('textAreaEnableKeyboardOnFocus');
class TextAreaFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontFamily(node);
    }
    else {
      getUINativeModule().textArea.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontFamilyModifier.identity = Symbol('textAreaFontFamily');
class TextAreaFontFeatureModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetFontFeature(node);
    } else {
      getUINativeModule().textArea.setFontFeature(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaFontFamilyModifier.identity = Symbol('textAreaFontFeature');
class TextAreaCaretColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetCaretColor(node);
    }
    else {
      getUINativeModule().textArea.setCaretColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaCaretColorModifier.identity = Symbol('textAreaCaretColor');
class TextAreaMaxLengthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetMaxLength(node);
    }
    else {
      getUINativeModule().textArea.setMaxLength(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaMaxLengthModifier.identity = Symbol('textAreaMaxLength');
class TextAreaStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetStyle(node);
    }
    else {
      getUINativeModule().textArea.setStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaStyleModifier.identity = Symbol('textAreaStyle');
class TextAreaSelectionMenuHiddenModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetSelectionMenuHidden(node);
    }
    else {
      getUINativeModule().textArea.setSelectionMenuHidden(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaSelectionMenuHiddenModifier.identity = Symbol('textAreaSelectionMenuHidden');
class TextAreaPlaceholderFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetPlaceholderFont(node);
    }
    else {
      getUINativeModule().textArea.setPlaceholderFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    if (!(this.stageValue.weight === this.value.weight &&
      this.stageValue.style === this.value.style)) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual(this.stageValue.size, this.value.size) ||
        !isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    }
  }
}
TextAreaPlaceholderFontModifier.identity = Symbol('textAreaPlaceholderFont');
class TextAreaTextAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetTextAlign(node);
    }
    else {
      getUINativeModule().textArea.setTextAlign(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaTextAlignModifier.identity = Symbol('textAreaTextAlign');
class TextAreaShowCounterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetShowCounter(node);
    }
    else {
      getUINativeModule().textArea.setShowCounter(node, this.value.value, this.value.highlightBorder, this.value.thresholdPercentage);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.value, this.value.value) ||
      !isBaseOrResourceEqual(this.stageValue.highlightBorder, this.value.highlightBorder) ||
      !isBaseOrResourceEqual(this.stageValue.thresholdPercentage, this.value.thresholdPercentage);
  }
}
TextAreaShowCounterModifier.identity = Symbol('textAreaShowCounter');
class TextAreaOnChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnChange(node);
    } else {
      getUINativeModule().textArea.setOnChange(node, this.value);
    }
  }
}
TextAreaOnChangeModifier.identity = Symbol('textAreaOnChange');
class TextAreaEnterKeyTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetEnterKeyType(node);
    } else {
      getUINativeModule().textArea.setEnterKeyType(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaEnterKeyTypeModifier.identity = Symbol('textAreaEnterKeyType');
class TextAreaInputFilterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetInputFilter(node);
    }
    else {
      getUINativeModule().textArea.setInputFilter(node, this.value.value, this.value.error);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.value, this.value.value) ||
      !isBaseOrResourceEqual(this.stageValue.error, this.value.error);
  }
}
TextAreaInputFilterModifier.identity = Symbol('textAreaInputFilter');
class TextAreaOnTextSelectionChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnTextSelectionChange(node);
    } else {
      getUINativeModule().textArea.setOnTextSelectionChange(node, this.value);
    }
  }
}
TextAreaOnTextSelectionChangeModifier.identity = Symbol('textAreaOnTextSelectionChange');

class TextAreaOnContentScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnContentScroll(node);
    } else {
      getUINativeModule().textArea.setOnContentScroll(node, this.value);
    }
  }
}
TextAreaOnContentScrollModifier.identity = Symbol('textAreaOnContentScroll');
class TextAreaOnEditChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnEditChange(node);
    } else {
      getUINativeModule().textArea.setOnEditChange(node, this.value);
    }
  }
}
TextAreaOnEditChangeModifier.identity = Symbol('textAreaOnEditChange');
class TextAreaOnCopyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnCopy(node);
    } else {
      getUINativeModule().textArea.setOnCopy(node, this.value);
    }
  }
}
TextAreaOnCopyModifier.identity = Symbol('textAreaOnCopy');
class TextAreaOnCutModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnCut(node);
    } else {
      getUINativeModule().textArea.setOnCut(node, this.value);
    }
  }
}
TextAreaOnCutModifier.identity = Symbol('textAreaOnCut');
class TextAreaOnPasteModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnPaste(node);
    } else {
      getUINativeModule().textArea.setOnPaste(node, this.value);
    }
  }
}
TextAreaOnPasteModifier.identity = Symbol('textAreaOnPaste');
class TextAreaTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetType(node);
    }
    else {
      getUINativeModule().textArea.setType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaTypeModifier.identity = Symbol('textAreaType');
class TextAreaPaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetPadding(node);
    }
    else {
      getUINativeModule().textArea.setPadding(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
TextAreaPaddingModifier.identity = Symbol('textAreaPadding');
class TextAreaBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBackgroundColor(node);
    } else {
      getUINativeModule().textArea.setBackgroundColor(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaBackgroundColorModifier.identity = Symbol('textAreaBackgroundColor');
class TextAreaMarginModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetMargin(node);
    }
    else {
      getUINativeModule().textArea.setMargin(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
TextAreaMarginModifier.identity = Symbol('textAreaMargin');
class TextAreaOnSubmitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetOnSubmit(node);
    } else {
      getUINativeModule().textArea.setOnSubmit(node, this.value);
    }
  }
}
TextAreaOnSubmitModifier.identity = Symbol('textAreaOnSubmit');
class TextAreaContentTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetContentType(node);
    }
    else {
      getUINativeModule().textArea.setContentType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaContentTypeModifier.identity = Symbol('textAreaContentType');
class TextAreaEnableAutoFillModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetEnableAutoFill(node);
    } else {
      getUINativeModule().textArea.setEnableAutoFill(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextAreaEnableAutoFillModifier.identity = Symbol('textAreaEnableAutoFill');
class TextAreaBorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBorder(node);
    } else {
      getUINativeModule().textArea.setBorder(node,
        this.value.arkWidth.left, this.value.arkWidth.right, this.value.arkWidth.top, this.value.arkWidth.bottom,
        this.value.arkColor.leftColor, this.value.arkColor.rightColor, this.value.arkColor.topColor, this.value.arkColor.bottomColor,
        this.value.arkRadius.topLeft, this.value.arkRadius.topRight, this.value.arkRadius.bottomLeft, this.value.arkRadius.bottomRight,
        this.value.arkStyle.top, this.value.arkStyle.right, this.value.arkStyle.bottom, this.value.arkStyle.left);
    }
  }
  checkObjectDiff() {
    return this.value.checkObjectDiff(this.stageValue);
  }
}
TextAreaBorderModifier.identity = Symbol('textAreaBorder');
class TextAreaBorderWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBorderWidth(node);
    } else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().textArea.setBorderWidth(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textArea.setBorderWidth(node, this.value.top, this.value.right,
          this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    } else {
      return true;
    }
  }
}
TextAreaBorderWidthModifier.identity = Symbol('textAreaBorderWidth');
class TextAreaBorderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBorderColor(node);
    } else {
      const valueType = typeof this.value;
      if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
        getUINativeModule().textArea.setBorderColor(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textArea.setBorderColor(node, this.value.top,
          this.value.right, this.value.bottom,
          this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === his.value.bottom);
    } else {
      return true;
    }
  }
}
TextAreaBorderColorModifier.identity = Symbol('textAreaBorderColor');
class TextAreaBorderStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBorderStyle(node);
    } else {
      let type, style, top, right, bottom, left;
      if (isNumber(this.value)) {
        style = this.value;
        type = true;
      } else if (isObject(this.value)) {
        top = this.value?.top;
        right = this.value?.right;
        bottom = this.value?.bottom;
        left = this.value?.left;
        type = true;
      }
      if (type === true) {
        getUINativeModule().textArea.setBorderStyle(node, type, style, top, right, bottom, left);
      } else {
        getUINativeModule().textArea.resetBorderStyle(node);
      }
    }
  }
  checkObjectDiff() {
    return !(this.value?.top === this.stageValue?.top &&
      this.value?.right === this.stageValue?.right &&
      this.value?.bottom === this.stageValue?.bottom &&
      this.value?.left === this.stageValue?.left);
  }
}
TextAreaBorderStyleModifier.identity = Symbol('textAreaBorderStyle');
class TextAreaBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textArea.resetBorderRadius(node);
    } else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().textArea.setBorderRadius(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textArea.setBorderRadius(node, this.value.topLeft, this.value.topRight,
          this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    } else {
      return true;
    }
  }
}
TextAreaBorderRadiusModifier.identity = Symbol('textAreaBorderRadius');
class ArkTextAreaComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  type(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaTypeModifier.identity, TextAreaTypeModifier, value);
    return this;
  }
  placeholderColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaPlaceholderColorModifier.identity, TextAreaPlaceholderColorModifier, value);
    return this;
  }
  placeholderFont(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaPlaceholderFontModifier.identity, TextAreaPlaceholderFontModifier, value);
    return this;
  }
  textAlign(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaTextAlignModifier.identity, TextAreaTextAlignModifier, value);
    return this;
  }
  caretColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaCaretColorModifier.identity, TextAreaCaretColorModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontColorModifier.identity, TextAreaFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontSizeModifier.identity, TextAreaFontSizeModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontStyleModifier.identity, TextAreaFontStyleModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontWeightModifier.identity, TextAreaFontWeightModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontFamilyModifier.identity, TextAreaFontFamilyModifier, value);
    return this;
  }
  fontFeature(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaFontFeatureModifier.identity, TextAreaFontFeatureModifier, value);
    return this;
  }
  inputFilter(value, error) {
    let arkValue = new ArkTextInputFilter();
    arkValue.value = value;
    arkValue.error = error;
    modifierWithKey(this._modifiersWithKeys, TextAreaInputFilterModifier.identity, TextAreaInputFilterModifier, arkValue);
    return this;
  }
  onChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnChangeModifier.identity, TextAreaOnChangeModifier, callback);
    return this;
  }
  onTextSelectionChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnTextSelectionChangeModifier.identity, TextAreaOnTextSelectionChangeModifier, callback);
    return this;
  }
  onContentScroll(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnContentScrollModifier.identity, TextAreaOnContentScrollModifier, callback);
    return this;
  }
  onEditChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnEditChangeModifier.identity, TextAreaOnEditChangeModifier, callback);
    return this;
  }
  onCopy(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnCopyModifier.identity, TextAreaOnCopyModifier, callback);
    return this;
  }
  onCut(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnCutModifier.identity, TextAreaOnCutModifier, callback);
    return this;
  }
  onPaste(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnPasteModifier.identity, TextAreaOnPasteModifier, callback);
    return this;
  }
  copyOption(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaCopyOptionModifier.identity, TextAreaCopyOptionModifier, value);
    return this;
  }
  enableKeyboardOnFocus(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaEnableKeyboardOnFocusModifier.identity, TextAreaEnableKeyboardOnFocusModifier, value);
    return this;
  }
  maxLength(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaMaxLengthModifier.identity, TextAreaMaxLengthModifier, value);
    return this;
  }
  showCounter(value, options) {
    let arkValue = new ArkTextFieldShowCounter();
    arkValue.value = value;
    arkValue.highlightBorder = options?.highlightBorder;
    arkValue.thresholdPercentage = options?.thresholdPercentage;
    modifierWithKey(this._modifiersWithKeys, TextAreaShowCounterModifier.identity, TextAreaShowCounterModifier, arkValue);
    return this;
  }
  style(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaStyleModifier.identity, TextAreaStyleModifier, value);
    return this;
  }
  barState(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBarStateModifier.identity, TextAreaBarStateModifier, value);
    return this;
  }
  selectionMenuHidden(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaSelectionMenuHiddenModifier.identity, TextAreaSelectionMenuHiddenModifier, value);
    return this;
  }
  maxLines(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaMaxLinesModifier.identity, TextAreaMaxLinesModifier, value);
    return this;
  }
  customKeyboard(value) {
    throw new Error('Method not implemented.');
  }
  decoration(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaDecorationModifier.identity, TextAreaDecorationModifier, value);
    return this;
  }
  letterSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaLetterSpacingModifier.identity, TextAreaLetterSpacingModifier, value);
    return this;
  }
  lineSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaLineSpacingModifier.identity, TextAreaLineSpacingModifier, value);
    return this;
  }
  lineHeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaLineHeightModifier.identity, TextAreaLineHeightModifier, value);
    return this;
  }
  wordBreak(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaWordBreakModifier.identity, TextAreaWordBreakModifier, value);
    return this;
  }
  lineBreakStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaLineBreakStrategyModifier.identity,
      TextAreaLineBreakStrategyModifier, value);
    return this;
  }
  minFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaMinFontSizeModifier.identity, TextAreaMinFontSizeModifier, value);
    return this;
  }
  maxFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaMaxFontSizeModifier.identity, TextAreaMaxFontSizeModifier, value);
    return this;
  }
  heightAdaptivePolicy(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaHeightAdaptivePolicyModifier.identity, TextAreaHeightAdaptivePolicyModifier, value);
    return this;
  }
  selectedBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaSelectedBackgroundColorModifier.identity, TextAreaSelectedBackgroundColorModifier, value);
    return this;
  }
  caretStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaCaretStyleModifier.identity, TextAreaCaretStyleModifier, value);
    return this;
  }
  textOverflow(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaTextOverflowModifier.identity, TextAreaTextOverflowModifier, value);
    return this;
  }
  textIndent(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaTextIndentModifier.identity, TextAreaTextIndentModifier, value);
    return this;
  }
  enterKeyType(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaEnterKeyTypeModifier.identity, TextAreaEnterKeyTypeModifier, value);
    return this;
  }
  padding(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, TextAreaPaddingModifier.identity, TextAreaPaddingModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TextAreaPaddingModifier.identity, TextAreaPaddingModifier, undefined);
    }
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBackgroundColorModifier.identity, TextAreaBackgroundColorModifier, value);
    return this;
  }
  margin(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, TextAreaMarginModifier.identity, TextAreaMarginModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TextAreaMarginModifier.identity, TextAreaMarginModifier, undefined);
    }
    return this;
  }
  onSubmit(callback) {
    modifierWithKey(this._modifiersWithKeys, TextAreaOnSubmitModifier.identity, TextAreaOnSubmitModifier, callback);
    return this;
  }
  contentType(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaContentTypeModifier.identity,
      TextAreaContentTypeModifier, value);
    return this;
  }
  enableAutoFill(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaEnableAutoFillModifier.identity,
      TextAreaEnableAutoFillModifier, value);
    return this;
  }
  border(value) {
    let arkBorder = valueToArkBorder(value);
    modifierWithKey(this._modifiersWithKeys, TextAreaBorderModifier.identity, TextAreaBorderModifier, arkBorder);
    return this;
  }
  borderWidth(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBorderWidthModifier.identity, TextAreaBorderWidthModifier, value);
    return this;
  }
  borderColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBorderColorModifier.identity, TextAreaBorderColorModifier, value);
    return this;
  }
  borderStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBorderStyleModifier.identity, TextAreaBorderStyleModifier, value);
    return this;
  }
  borderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, TextAreaBorderRadiusModifier.identity, TextAreaBorderRadiusModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.TextArea !== undefined) {
  globalThis.TextArea.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextAreaComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextAreaModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class TextInputStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetStyle(node);
    }
    else {
      getUINativeModule().textInput.setStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputStyleModifier.identity = Symbol('textInputStyle');
class TextInputMaxLengthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetMaxLength(node);
    }
    else {
      getUINativeModule().textInput.setMaxLength(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputMaxLengthModifier.identity = Symbol('textInputMaxLength');
class TextInputMaxLinesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetMaxLines(node);
    }
    else {
      getUINativeModule().textInput.setMaxLines(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputMaxLinesModifier.identity = Symbol('textInputMaxLines');
class TextInputDecorationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetDecoration(node);
    }
    else {
      getUINativeModule().textInput.setDecoration(node, this.value.type, this.value.color, this.value.style);
    }
  }
  checkObjectDiff() {
    if (this.stageValue.type !== this.value.type || this.stageValue.style !== this.value.style) {
      return true;
    }
    if (isResource(this.stageValue.color) && isResource(this.value.color)) {
      return !isResourceEqual(this.stageValue.color, this.value.color);
    }
    else if (!isResource(this.stageValue.color) && !isResource(this.value.color)) {
      return !(this.stageValue.color === this.value.color);
    }
    else {
      return true;
    }
  }
}
TextInputDecorationModifier.identity = Symbol('textInputDecoration');
class TextInputLetterSpacingModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetLetterSpacing(node);
        }
        else {
            getUINativeModule().textInput.setLetterSpacing(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputLetterSpacingModifier.identity = Symbol('textInputLetterSpacing');
class TextInputLineHeightModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetLineHeight(node);
        }
        else {
            getUINativeModule().textInput.setLineHeight(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputLineHeightModifier.identity = Symbol('textInputLineHeight');
class TextInputUnderlineColorModifier extends ModifierWithKey {
  constructor(value) {
      super(value);
  }
  applyPeer(node, reset) {
      if (reset) {
          getUINativeModule().textInput.resetUnderlineColor(node);
      }
      else {
          const valueType = typeof this.value;
          if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
              getUINativeModule().textInput.setUnderlineColor(node, this.value, undefined, undefined, undefined, undefined);
          }
          else {
              getUINativeModule().textInput.setUnderlineColor(node, undefined, this.value.normal, this.value.typing, this.value.error, this.value.disable);
          }
      }
  }
  checkObjectDiff() {
      if (isResource(this.stageValue) && isResource(this.value)) {
          return !isBaseOrResourceEqual(this.stageValue, this.value);
      }
      else if (!isResource(this.stageValue) && !isResource(this.value)) {
          return !(this.stageValue.normal === this.value.normal &&
              this.stageValue.typing === this.value.typing &&
              this.stageValue.error === this.value.error &&
              this.stageValue.disable === this.value.disable);
      }
      else {
          return true;
      }
  }
}
TextInputUnderlineColorModifier.identity = Symbol('textInputUnderlineColor');
class TextInputWordBreakModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetWordBreak(node);
        }
        else {
            getUINativeModule().textInput.setWordBreak(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputWordBreakModifier.identity = Symbol('textInputWordBreak');

class TextInputLineBreakStrategyModifier extends ModifierWithKey {
  constructor(value) {
      super(value);
  }
  applyPeer(node, reset) {
      if (reset) {
          getUINativeModule().textInput.resetLineBreakStrategy(node);
      }
      else {
          getUINativeModule().textInput.setLineBreakStrategy(node, this.value);
      }
  }
  checkObjectDiff() {
      return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputLineBreakStrategyModifier.identity = Symbol('textInputLineBreakStrategy');

class TextInputMinFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetMinFontSize(node);
        }
        else {
            getUINativeModule().textInput.setMinFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputMinFontSizeModifier.identity = Symbol('textInputMinFontSize');
class TextInputMaxFontSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetMaxFontSize(node);
        }
        else {
            getUINativeModule().textInput.setMaxFontSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputMaxFontSizeModifier.identity = Symbol('textInputMaxFontSize');
class TextInputHeightAdaptivePolicyModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetHeightAdaptivePolicy(node);
        }
        else {
            getUINativeModule().textInput.setHeightAdaptivePolicy(node, this.value);
        }
    }
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputHeightAdaptivePolicyModifier.identity = Symbol('textInputHeightAdaptivePolicy');
class TextInputTextOverflowModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetTextOverflow(node);
        } else {
            getUINativeModule().textInput.setTextOverflow(node, this.value);
        }
    }
    checkObjectDiff() {
        return this.stageValue !== this.value;
    }
}
TextInputTextOverflowModifier.identity = Symbol('textInputTextOverflow');
class TextInputTextIndentModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().textInput.resetTextIndent(node);
        } else {
            getUINativeModule().textInput.setTextIndent(node, this.value);
        }
    }
    
    checkObjectDiff() {
        return !isBaseOrResourceEqual(this.stageValue, this.value);
    }
}
TextInputTextIndentModifier.identity = Symbol('textInputTextIndent');
class TextInputShowPasswordIconModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetShowPasswordIcon(node);
    }
    else {
      getUINativeModule().textInput.setShowPasswordIcon(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputShowPasswordIconModifier.identity = Symbol('textInputShowPasswordIcon');
class TextInputShowPasswordModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetShowPassword(node);
    }
    else {
      getUINativeModule().textInput.setShowPassword(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputShowPasswordModifier.identity = Symbol('textInputShowPassword');
class TextInputTextAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetTextAlign(node);
    }
    else {
      getUINativeModule().textInput.setTextAlign(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputTextAlignModifier.identity = Symbol('textInputTextAlign');
class TextInputPlaceholderFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetPlaceholderFont(node);
    }
    else {
      getUINativeModule().textInput.setPlaceholderFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    if (!(this.stageValue.weight === this.value.weight &&
      this.stageValue.style === this.value.style)) {
      return true;
    }
    else {
      if (((isResource(this.stageValue.size) && isResource(this.value.size) &&
        isResourceEqual(this.stageValue.size, this.value.size)) ||
        (!isResource(this.stageValue.size) && !isResource(this.value.size) &&
          this.stageValue.size === this.value.size)) &&
        ((isResource(this.stageValue.family) && isResource(this.value.family) &&
          isResourceEqual(this.stageValue.family, this.value.family)) ||
          (!isResource(this.stageValue.family) && !isResource(this.value.family) &&
            this.stageValue.family === this.value.family))) {
        return false;
      }
      else {
        return true;
      }
    }
  }
}
TextInputPlaceholderFontModifier.identity = Symbol('textInputPlaceholderFont');
class TextInputPlaceholderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetPlaceholderColor(node);
    }
    else {
      getUINativeModule().textInput.setPlaceholderColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputPlaceholderColorModifier.identity = Symbol('textInputPlaceholderColor');
class TextInputPasswordIconModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetPasswordIcon(node);
    }
    else {
      getUINativeModule().textInput.setPasswordIcon(node, this.value.onIconSrc, this.value.offIconSrc);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.onIconSrc, this.value.onIconSrc) ||
      !isBaseOrResourceEqual(this.stageValue.offIconSrc, this.value.offIconSrc);
  }
}
TextInputPasswordIconModifier.identity = Symbol('textInputPasswordIcon');
class TextInputSelectedBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetSelectedBackgroundColor(node);
    }
    else {
      getUINativeModule().textInput.setSelectedBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputSelectedBackgroundColorModifier.identity = Symbol('textInputSelectedBackgroundColor');
class TextInputSelectionMenuHiddenModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetSelectionMenuHidden(node);
    }
    else {
      getUINativeModule().textInput.setSelectionMenuHidden(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputSelectionMenuHiddenModifier.identity = Symbol('textInputSelectionMenuHidden');
class TextInputShowUnderlineModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetShowUnderline(node);
    }
    else {
      getUINativeModule().textInput.setShowUnderline(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputShowUnderlineModifier.identity = Symbol('textInputShowUnderLine');
class TextInputPasswordRulesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetPasswordRules(node);
    } else {
      getUINativeModule().textInput.setPasswordRules(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputPasswordRulesModifier.identity = Symbol('textInputPasswordRules');
class TextInputEnableAutoFillModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetEnableAutoFill(node);
    } else {
      getUINativeModule().textInput.setEnableAutoFill(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputEnableAutoFillModifier.identity = Symbol('textInputEnableAutoFill');
class TextInputFontFeatureModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontFeature(node);
    } else {
      getUINativeModule().textInput.setFontFeature(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputShowUnderlineModifier.identity = Symbol('textInputFontFeature');
class TextInputShowErrorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetShowError(node);
    }
    else {
      getUINativeModule().textInput.setShowError(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputShowErrorModifier.identity = Symbol('textInputShowError');
class TextInputTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetType(node);
    }
    else {
      getUINativeModule().textInput.setType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputTypeModifier.identity = Symbol('textInputType');
class TextInputCaretPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetCaretPosition(node);
    }
    else {
      getUINativeModule().textInput.setCaretPosition(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputCaretPositionModifier.identity = Symbol('textInputCaretPosition');
class TextInputCopyOptionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetCopyOption(node);
    }
    else {
      getUINativeModule().textInput.setCopyOption(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputCopyOptionModifier.identity = Symbol('textInputCopyOption');
class TextInputEnableKeyboardOnFocusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetEnableKeyboardOnFocus(node);
    }
    else {
      getUINativeModule().textInput.setEnableKeyboardOnFocus(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputEnableKeyboardOnFocusModifier.identity = Symbol('textInputEnableKeyboardOnFocus');
class TextInputCaretStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetCaretStyle(node);
    }
    else {
      getUINativeModule().textInput.setCaretStyle(node, this.value.width, this.value.color);
    }
  }
  checkObjectDiff() {
    if (isObject(this.stageValue) && isObject(this.value)) {
      return !isBaseOrResourceEqual(this.stageValue.width, this.value.width);
    }
    else {
      return true;
    }
  }
}
TextInputCaretStyleModifier.identity = Symbol('textInputCaretStyle');
class TextInputEnterKeyTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetEnterKeyType(node);
    }
    else {
      getUINativeModule().textInput.setEnterKeyType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputEnterKeyTypeModifier.identity = Symbol('textInputEnterKeyType');
class TextInputBarStateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBarState(node);
    }
    else {
      getUINativeModule().textInput.setBarState(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputBarStateModifier.identity = Symbol('textInputBarState');
class TextInputCaretColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetCaretColor(node);
    }
    else {
      getUINativeModule().textInput.setCaretColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputCaretColorModifier.identity = Symbol('textinputCaretColor');
class TextInputFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontColor(node);
    }
    else {
      getUINativeModule().textInput.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputFontColorModifier.identity = Symbol('textInputFontColor');
class TextInputFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontSize(node);
    }
    else {
      getUINativeModule().textInput.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputFontSizeModifier.identity = Symbol('textInputFontSize');
class TextInputFontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontStyle(node);
    }
    else {
      getUINativeModule().textInput.setFontStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputFontStyleModifier.identity = Symbol('textInputFontStyle');
class TextInputFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontWeight(node);
    }
    else {
      getUINativeModule().textInput.setFontWeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputFontWeightModifier.identity = Symbol('textInputFontWeight');
class TextInputFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetFontFamily(node);
    }
    else {
      getUINativeModule().textInput.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputFontFamilyModifier.identity = Symbol('textInputFontFamily');
class TextInputCancelButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetCancelButton(node);
    }
    else {
      let _a, _b, _c;
      getUINativeModule().textInput.setCancelButton(node, this.value.style,
        (_a = this.value.icon) === null || _a === void 0 ? void 0 : _a.size,
        (_b = this.value.icon) === null || _b === void 0 ? void 0 : _b.color,
        (_c = this.value.icon) === null || _c === void 0 ? void 0 : _c.src);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f;
    return this.stageValue.style !== this.value.style ||
      !isBaseOrResourceEqual((_a = this.stageValue.icon) === null || _a === void 0 ? void 0 : _a.size, (_b = this.value.icon) === null || _b === void 0 ? void 0 : _b.size) ||
      !isBaseOrResourceEqual((_c = this.stageValue.icon) === null || _c === void 0 ? void 0 : _c.color, (_d = this.value.icon) === null || _d === void 0 ? void 0 : _d.color) ||
      !isBaseOrResourceEqual((_e = this.stageValue.icon) === null || _e === void 0 ? void 0 : _e.src, (_f = this.value.icon) === null || _f === void 0 ? void 0 : _f.src);
  }
}
TextInputCancelButtonModifier.identity = Symbol('textInputCancelButton');
class TextInputSelectAllModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetSelectAll(node);
    }
    else {
      getUINativeModule().textInput.setSelectAll(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputSelectAllModifier.identity = Symbol('textInputSelectAll');
class TextInputShowCounterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetShowCounter(node);
    }
    else {
      getUINativeModule().textInput.setShowCounter(node, this.value.value, this.value.highlightBorder, this.value.thresholdPercentage);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.value, this.value.value) ||
      !isBaseOrResourceEqual(this.stageValue.highlightBorder, this.value.highlightBorder) ||
      !isBaseOrResourceEqual(this.stageValue.thresholdPercentage, this.value.thresholdPercentage);
  }
}
TextInputShowCounterModifier.identity = Symbol('textInputShowCounter');
class TextInputOnEditChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnEditChange(node);
    } else {
      getUINativeModule().textInput.setOnEditChange(node, this.value);
    }
  }
}
TextInputOnEditChangeModifier.identity = Symbol('textInputOnEditChange');
class TextInputFilterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetInputFilter(node);
    }
    else {
      getUINativeModule().textInput.setInputFilter(node, this.value.value, this.value.error);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.value, this.value.value) ||
      !isBaseOrResourceEqual(this.stageValue.error, this.value.error);
  }
}
TextInputFilterModifier.identity = Symbol('textInputFilter');
class TextInputOnSubmitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnSubmit(node);
    } else {
      getUINativeModule().textInput.setOnSubmit(node, this.value);
    }
  }
}
TextInputOnSubmitModifier.identity = Symbol('textInputOnSubmit');
class TextInputOnChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnChange(node);
    } else {
      getUINativeModule().textInput.setOnChange(node, this.value);
    }
  }
}
TextInputOnChangeModifier.identity = Symbol('textInputOnChange');
class TextInputOnTextSelectionChangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnTextSelectionChange(node);
    } else {
      getUINativeModule().textInput.setOnTextSelectionChange(node, this.value);
    }
  }
}
TextInputOnTextSelectionChangeModifier.identity = Symbol('textInputOnTextSelectionChange');
class TextInputOnContentScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnContentScroll(node);
    } else {
      getUINativeModule().textInput.setOnContentScroll(node, this.value);
    }
  }
}
TextInputOnContentScrollModifier.identity = Symbol('textInputOnContentScroll');
class TextInputOnCopyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnCopy(node);
    } else {
      getUINativeModule().textInput.setOnCopy(node, this.value);
    }
  }
}
TextInputOnCopyModifier.identity = Symbol('textInputOnCopy');
class TextInputOnCutModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnCut(node);
    } else {
      getUINativeModule().textInput.setOnCut(node, this.value);
    }
  }
}
TextInputOnCutModifier.identity = Symbol('textInputOnCut');
class TextInputOnPasteModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetOnPaste(node);
    } else {
      getUINativeModule().textInput.setOnPaste(node, this.value);
    }
  }
}
TextInputOnPasteModifier.identity = Symbol('textInputOnPaste');
class TextInputPaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetPadding(node);
    }
    else {
      getUINativeModule().textInput.setPadding(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
TextInputPaddingModifier.identity = Symbol('textInputPadding');
class TextInputContentTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetContentType(node);
    }
    else {
      getUINativeModule().textInput.setContentType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputContentTypeModifier.identity = Symbol('textInputContentType');
class TextInputBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBackgroundColor(node);
    } else {
      getUINativeModule().textInput.setBackgroundColor(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextInputBackgroundColorModifier.identity = Symbol('textInputBackgroundColor');
class TextInputMarginModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetMargin(node);
    }
    else {
      getUINativeModule().textInput.setMargin(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
TextInputMarginModifier.identity = Symbol('textInputMargin');
class TextInputBorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBorder(node);
    } else {
      getUINativeModule().textInput.setBorder(node,
        this.value.arkWidth.left, this.value.arkWidth.right, this.value.arkWidth.top, this.value.arkWidth.bottom,
        this.value.arkColor.leftColor, this.value.arkColor.rightColor, this.value.arkColor.topColor, this.value.arkColor.bottomColor,
        this.value.arkRadius.topLeft, this.value.arkRadius.topRight, this.value.arkRadius.bottomLeft, this.value.arkRadius.bottomRight,
        this.value.arkStyle.top, this.value.arkStyle.right, this.value.arkStyle.bottom, this.value.arkStyle.left);
    }
  }
  checkObjectDiff() {
    return this.value.checkObjectDiff(this.stageValue);
  }
}
TextInputBorderModifier.identity = Symbol('textInputBorder');
class TextInputBorderWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBorderWidth(node);
    } else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().textInput.setBorderWidth(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textInput.setBorderWidth(node, this.value.top, this.value.right,
          this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    } else {
      return true;
    }
  }
}
TextInputBorderWidthModifier.identity = Symbol('textInputBorderWidth');
class TextInputBorderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBorderColor(node);
    } else {
      const valueType = typeof this.value;
      if (valueType === 'number' || valueType === 'string' || isResource(this.value)) {
        getUINativeModule().textInput.setBorderColor(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textInput.setBorderColor(node, this.value.top,
          this.value.right, this.value.bottom, this.value.left);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    } else {
      return true;
    }
  }
}
TextInputBorderColorModifier.identity = Symbol('textInputBorderColor');
class TextInputBorderStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBorderStyle(node);
    } else {
      let type, style, top, right, bottom, left;
      if (isNumber(this.value)) {
        style = this.value;
        type = true;
      } else if (isObject(this.value)) {
        top = this.value?.top;
        right = this.value?.right;
        bottom = this.value?.bottom;
        left = this.value?.left;
        type = true;
      }
      if (type === true) {
        getUINativeModule().textInput.setBorderStyle(node, type, style, top, right, bottom, left);
      } else {
        getUINativeModule().textInput.resetBorderStyle(node);
      }
    }
  }
  checkObjectDiff() {
    return !(this.value?.top === this.stageValue?.top &&
      this.value?.right === this.stageValue?.right &&
      this.value?.bottom === this.stageValue?.bottom &&
      this.value?.left === this.stageValue?.left);
  }
}
TextInputBorderStyleModifier.identity = Symbol('textInputBorderStyle');
class TextInputBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textInput.resetBorderRadius(node);
    } else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().textInput.setBorderRadius(node, this.value, this.value, this.value, this.value);
      } else {
        getUINativeModule().textInput.setBorderRadius(node, this.value.topLeft, this.value.topRight,
          this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    } else {
      return true;
    }
  }
}
TextInputBorderRadiusModifier.identity = Symbol('textInputBorderRadius');
class ArkTextInputComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  cancelButton(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputCancelButtonModifier.identity, TextInputCancelButtonModifier, value);
    return this;
  }
  selectAll(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputSelectAllModifier.identity, TextInputSelectAllModifier, value);
    return this;
  }
  enableAutoFill(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputEnableAutoFillModifier.identity, TextInputEnableAutoFillModifier, value);
    return this;
  }
  passwordRules(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputPasswordRulesModifier.identity, TextInputPasswordRulesModifier, value);
    return this;
  }
  showCounter(value, options) {
    let arkValue = new ArkTextFieldShowCounter();
    arkValue.value = value;
    arkValue.highlightBorder = options?.highlightBorder;
    arkValue.thresholdPercentage = options?.thresholdPercentage;
    modifierWithKey(this._modifiersWithKeys, TextInputShowCounterModifier.identity, TextInputShowCounterModifier, arkValue);
    return this;
  }
  type(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputTypeModifier.identity, TextInputTypeModifier, value);
    return this;
  }
  placeholderColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputPlaceholderColorModifier.identity, TextInputPlaceholderColorModifier, value);
    return this;
  }
  placeholderFont(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputPlaceholderFontModifier.identity, TextInputPlaceholderFontModifier, value);
    return this;
  }
  enterKeyType(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputEnterKeyTypeModifier.identity, TextInputEnterKeyTypeModifier, value);
    return this;
  }
  caretColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputCaretColorModifier.identity, TextInputCaretColorModifier, value);
    return this;
  }
  onEditChanged(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnEditChangeModifier.identity, TextInputOnEditChangeModifier, callback);
    return this;
  }
  onEditChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnEditChangeModifier.identity, TextInputOnEditChangeModifier, callback);
    return this;
  }
  onSubmit(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnSubmitModifier.identity, TextInputOnSubmitModifier, callback);
    return this;
  }
  onChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnChangeModifier.identity, TextInputOnChangeModifier, callback);
    return this;
  }
  onTextSelectionChange(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnTextSelectionChangeModifier.identity, TextInputOnTextSelectionChangeModifier, callback);
    return this;
  }
  onContentScroll(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnContentScrollModifier.identity, TextInputOnContentScrollModifier, callback);
    return this;
  }
  maxLength(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputMaxLengthModifier.identity, TextInputMaxLengthModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontColorModifier.identity, TextInputFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontSizeModifier.identity, TextInputFontSizeModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontStyleModifier.identity, TextInputFontStyleModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontWeightModifier.identity, TextInputFontWeightModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontFamilyModifier.identity, TextInputFontFamilyModifier, value);
    return this;
  }
  inputFilter(value, error) {
    let arkValue = new ArkTextInputFilter();
    arkValue.value = value;
    arkValue.error = error;
    modifierWithKey(this._modifiersWithKeys, TextInputFilterModifier.identity, TextInputFilterModifier, arkValue);
    return this;
  }
  onCopy(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnCopyModifier.identity, TextInputOnCopyModifier, callback);
    return this;
  }
  onCut(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnCutModifier.identity, TextInputOnCutModifier, callback);
    return this;
  }
  onPaste(callback) {
    modifierWithKey(this._modifiersWithKeys, TextInputOnPasteModifier.identity, TextInputOnPasteModifier, callback);
    return this;
  }
  copyOption(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputCopyOptionModifier.identity, TextInputCopyOptionModifier, value);
    return this;
  }
  showPasswordIcon(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputShowPasswordIconModifier.identity, TextInputShowPasswordIconModifier, value);
    return this;
  }
  showPassword(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputShowPasswordModifier.identity, TextInputShowPasswordModifier, value);
    return this;
  }
  textAlign(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputTextAlignModifier.identity, TextInputTextAlignModifier, value);
    return this;
  }
  style(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputStyleModifier.identity, TextInputStyleModifier, value);
    return this;
  }
  caretStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputCaretStyleModifier.identity, TextInputCaretStyleModifier, value);
    return this;
  }
  selectedBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputSelectedBackgroundColorModifier.identity, TextInputSelectedBackgroundColorModifier, value);
    return this;
  }
  caretPosition(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputCaretPositionModifier.identity, TextInputCaretPositionModifier, value);
    return this;
  }
  enableKeyboardOnFocus(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputEnableKeyboardOnFocusModifier.identity, TextInputEnableKeyboardOnFocusModifier, value);
    return this;
  }
  passwordIcon(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputPasswordIconModifier.identity, TextInputPasswordIconModifier, value);
    return this;
  }
  showError(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputShowErrorModifier.identity, TextInputShowErrorModifier, value);
    return this;
  }
  showUnit(event) {
    throw new Error('Method not implemented.');
  }
  showUnderline(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputShowUnderlineModifier.identity, TextInputShowUnderlineModifier, value);
    return this;
  }
  fontFeature(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputFontFeatureModifier.identity, TextInputFontFeatureModifier, value);
    return this;
  }
  selectionMenuHidden(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputSelectionMenuHiddenModifier.identity, TextInputSelectionMenuHiddenModifier, value);
    return this;
  }
  barState(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBarStateModifier.identity, TextInputBarStateModifier, value);
    return this;
  }
  maxLines(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputMaxLinesModifier.identity, TextInputMaxLinesModifier, value);
    return this;
  }
  customKeyboard(event) {
    throw new Error('Method not implemented.');
  }
  decoration(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputDecorationModifier.identity, TextInputDecorationModifier, value);
    return this;
  }
  letterSpacing(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputLetterSpacingModifier.identity, TextInputLetterSpacingModifier, value);
    return this;
  }
  lineHeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputLineHeightModifier.identity, TextInputLineHeightModifier, value);
    return this;
  }
  underlineColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputUnderlineColorModifier.identity, TextInputUnderlineColorModifier, value);
    return this;
  }
  wordBreak(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputWordBreakModifier.identity, TextInputWordBreakModifier, value);
    return this;
  }
  lineBreakStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputLineBreakStrategyModifier.identity,
      TextInputLineBreakStrategyModifier, value);
    return this;
  }
  minFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputMinFontSizeModifier.identity, TextInputMinFontSizeModifier, value);
    return this;
  }
  maxFontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputMaxFontSizeModifier.identity, TextInputMaxFontSizeModifier, value);
    return this;
  }
  heightAdaptivePolicy(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputHeightAdaptivePolicyModifier.identity, TextInputHeightAdaptivePolicyModifier, value);
    return this;
  }
  textOverflow(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputTextOverflowModifier.identity, TextInputTextOverflowModifier, value);
    return this;
  }
  textIndent(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputTextIndentModifier.identity, TextInputTextIndentModifier, value);
    return this;
  }
  padding(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, TextInputPaddingModifier.identity, TextInputPaddingModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TextInputPaddingModifier.identity, TextInputPaddingModifier, undefined);
    }
    return this;
  }
  contentType(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputContentTypeModifier.identity, TextInputContentTypeModifier, value);
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBackgroundColorModifier.identity, TextInputBackgroundColorModifier, value);
    return this;
  }
  margin(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, TextInputMarginModifier.identity, TextInputMarginModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, TextInputMarginModifier.identity, TextInputMarginModifier, undefined);
    }
    return this;
  }
  border(value) {
    let arkBorder = valueToArkBorder(value);
    modifierWithKey(this._modifiersWithKeys, TextInputBorderModifier.identity, TextInputBorderModifier, arkBorder);
    return this;
  }
  borderWidth(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBorderWidthModifier.identity, TextInputBorderWidthModifier, value);
    return this;
  }
  borderColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBorderColorModifier.identity, TextInputBorderColorModifier, value);
    return this;
  }
  borderStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBorderStyleModifier.identity, TextInputBorderStyleModifier, value);
    return this;
  }
  borderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, TextInputBorderRadiusModifier.identity, TextInputBorderRadiusModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.TextInput !== undefined) {
  globalThis.TextInput.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextInputComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextInputModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class VideoObjectFitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetObjectFit(node);
    }
    else {
      getUINativeModule().video.setObjectFit(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoObjectFitModifier.identity = Symbol('videoObjectFit');
class VideoAutoPlayModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetAutoPlay(node);
    }
    else {
      getUINativeModule().video.setAutoPlay(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoAutoPlayModifier.identity = Symbol('videoAutoPlayr');
class VideoControlsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetControls(node);
    }
    else {
      getUINativeModule().video.setControls(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoControlsModifier.identity = Symbol('videoControls');
class VideoLoopModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetLoop(node);
    }
    else {
      getUINativeModule().video.setLoop(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoLoopModifier.identity = Symbol('videoLoop');
class VideoMutedModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetMuted(node);
    }
    else {
      getUINativeModule().video.setMuted(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoMutedModifier.identity = Symbol('videoMuted');
class VideoOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetOpacity(node);
    }
    else {
      getUINativeModule().video.setOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
VideoOpacityModifier.identity = Symbol('videoOpacity');
class VideoTransitionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().video.resetTransition(node);
    }
    else {
      getUINativeModule().video.setTransition(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
VideoTransitionModifier.identity = Symbol('videoTransition');
class ArkVideoComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  muted(value) {
    modifierWithKey(this._modifiersWithKeys, VideoMutedModifier.identity, VideoMutedModifier, value);
    return this;
  }
  autoPlay(value) {
    modifierWithKey(this._modifiersWithKeys, VideoAutoPlayModifier.identity, VideoAutoPlayModifier, value);
    return this;
  }
  controls(value) {
    modifierWithKey(this._modifiersWithKeys, VideoControlsModifier.identity, VideoControlsModifier, value);
    return this;
  }
  loop(value) {
    modifierWithKey(this._modifiersWithKeys, VideoLoopModifier.identity, VideoLoopModifier, value);
    return this;
  }
  objectFit(value) {
    modifierWithKey(this._modifiersWithKeys, VideoObjectFitModifier.identity, VideoObjectFitModifier, value);
    return this;
  }
  opacity(value) {
    modifierWithKey(this._modifiersWithKeys, VideoOpacityModifier.identity, VideoOpacityModifier, value);
    return this;
  }
  transition(value) {
    modifierWithKey(this._modifiersWithKeys, VideoTransitionModifier.identity, VideoTransitionModifier, value);
    return this;
  }
  onStart(callback) {
    throw new Error('Method not implemented.');
  }
  onPause(callback) {
    throw new Error('Method not implemented.');
  }
  onFinish(event) {
    throw new Error('Method not implemented.');
  }
  onFullscreenChange(callback) {
    throw new Error('Method not implemented.');
  }
  onPrepared(callback) {
    throw new Error('Method not implemented.');
  }
  onSeeking(callback) {
    throw new Error('Method not implemented.');
  }
  onSeeked(callback) {
    throw new Error('Method not implemented.');
  }
  onUpdate(callback) {
    throw new Error('Method not implemented.');
  }
  onError(callback) {
    throw new Error('Method not implemented.');
  }
  onStop(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Video !== undefined) {
  globalThis.Video.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkVideoComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.VideoModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkBorderStyle {
  constructor() {
    this.type = undefined;
    this.style = undefined;
    this.top = undefined;
    this.right = undefined;
    this.bottom = undefined;
    this.left = undefined;
  }
  isEqual(another) {
    return (this.type === another.type &&
      this.style === another.style &&
      this.top === another.top &&
      this.right === another.right &&
      this.bottom === another.bottom &&
      this.left === another.left);
  }
  parseBorderStyle(value) {
    if (typeof value === 'number') {
      this.style = value;
      this.type = true;
      return true;
    }
    else if (typeof value === 'object') {
      return this.parseEdgeStyles(value);
    }
    return false;
  }
  parseEdgeStyles(options) {
    this.top = options.top;
    this.right = options.right;
    this.bottom = options.bottom;
    this.left = options.left;
    this.type = true;
    return true;
  }
}
class ArkBorderColor {
  constructor() {
    this.leftColor = undefined;
    this.rightColor = undefined;
    this.topColor = undefined;
    this.bottomColor = undefined;
  }
  isEqual(another) {
    return (this.leftColor === another.leftColor &&
      this.rightColor === another.rightColor &&
      this.topColor === another.topColor &&
      this.bottomColor === another.bottomColor);
  }
}
class ArkPosition {
  constructor() {
    this.x = undefined;
    this.y = undefined;
  }
  isEqual(another) {
    return this.x === another.x && this.y === another.y;
  }
}
class ArkBorderWidth {
  constructor() {
    this.left = undefined;
    this.right = undefined;
    this.top = undefined;
    this.bottom = undefined;
  }
  isEqual(another) {
    return (this.left === another.left &&
      this.right === another.right &&
      this.top === another.top &&
      this.bottom === another.bottom);
  }
}
class ArkBorderRadius {
  constructor() {
    this.topLeft = undefined;
    this.topRight = undefined;
    this.bottomLeft = undefined;
    this.bottomRight = undefined;
  }
  isEqual(another) {
    return (this.topLeft === another.topLeft &&
      this.topRight === another.topRight &&
      this.bottomLeft === another.bottomLeft &&
      this.bottomRight === another.bottomRight);
  }
}
class ArkLabelFont {
  constructor() {
    this.size = undefined;
    this.weight = undefined;
    this.family = undefined;
    this.style = undefined;
  }
  isEqual(another) {
    return (this.size === another.size &&
      this.weight === another.weight &&
      this.family === another.family &&
      this.style === another.style);
  }
}
function deepCompareArrays(arr1, arr2) {
  return (Array.isArray(arr1) &&
    Array.isArray(arr2) &&
    arr1.length === arr2.length &&
    arr1.every((value, index) => {
      if (Array.isArray(value) && Array.isArray(arr2[index])) {
        return deepCompareArrays(value, arr2[index]);
      }
      else {
        return value === arr2[index];
      }
    }));
}
class ArkLinearGradient {
  constructor(angle, direction, colors, repeating) {
    this.angle = angle;
    this.direction = direction;
    this.colors = colors;
    this.repeating = repeating;
  }
  isEqual(another) {
    return (this.angle === another.angle &&
      this.direction === another.direction &&
      deepCompareArrays(this.colors, another.colors) &&
      this.repeating === another.repeating);
  }
}
class ArkSweepGradient {
  constructor(center, start, end, rotation, colors, repeating) {
    this.center = center;
    this.start = start;
    this.end = end;
    this.rotation = rotation;
    this.colors = colors;
    this.repeating = repeating;
  }
  isEqual(another) {
    return (deepCompareArrays(this.center, another.center) &&
      this.start === another.start &&
      this.end === another.end &&
      this.rotation === another.rotation &&
      deepCompareArrays(this.colors, another.colors) &&
      this.repeating === another.repeating);
  }
}
class ArkForegroundBlurStyle {
  constructor() {
    this.blurStyle = undefined;
    this.colorMode = undefined;
    this.adaptiveColor = undefined;
    this.scale = undefined;
    this.blurOptions = undefined;
  }
  isEqual(another) {
    return (this.blurStyle === another.blurStyle &&
      this.colorMode === another.colorMode &&
      this.adaptiveColor === another.adaptiveColor &&
      this.scale === another.scale &&
      this.blurOptions === another.blurOptions);
  }
}
class ArkLinearGradientBlur {
  constructor() {
    this.blurRadius = undefined;
    this.fractionStops = undefined;
    this.direction = undefined;
  }
  isEqual(another) {
    return (this.blurRadius === another.blurRadius &&
      deepCompareArrays(this.fractionStops, another.fractionStops) &&
      this.direction === another.direction);
  }
}
class ArkOverlay {
  constructor() {
    this.value = undefined;
    this.align = undefined;
    this.offsetX = undefined;
    this.offsetY = undefined;
    this.hasOptions = undefined;
    this.hasOffset = undefined;
  }
  splitOption(options) {
    if (isUndefined(options)) {
      return true;
    }
    this.hasOptions = true;
    this.align = options.align;
    if (isUndefined(options.offset)) {
      return true;
    }
    this.hasOffset = true;
    this.offsetX = options.offset.x;
    this.offsetY = options.offset.y;
    return true;
  }
  splitOverlayValue(value, options) {
    if (typeof value === 'string') {
      this.value = value;
      return this.splitOption(options);
    }
    return false;
  }
  isEqual(another) {
    return ((this.value === another.value) && (this.align === another.align) &&
      (this.offsetX === another.offsetX) && (this.offsetY === another.offsetY) &&
      (this.hasOptions === another.hasOptions) && (this.hasOffset === another.hasOffset));
  }
  checkObjectDiff(another) {
    return !this.isEqual(another);
  }
}
class ArkSharedTransition {
  constructor() {
    this.id = undefined;
    this.options = undefined;
  }
  isEqual(another) {
    return (this.id === another.id) && (this.options === another.options);
  }
}
class ArkListEdgeEffect {
  constructor() {
    this.value = undefined;
    this.options = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.options === another.options);
  }
}
class ArkScrollEdgeEffect {
  constructor() {
    this.value = undefined;
    this.options = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.options === another.options);
  }
}
class ArkBlurOptions {
  constructor() {
    this.value = undefined;
    this.options = undefined;
  }
}
class InvertOptions {
  constructor() {
    this.high = undefined;
    this.low = undefined;
    this.threshold = undefined;
    this.thresholdRange = undefined;
  }
}
class ArkMenuAlignType {
  constructor(alignType, offset) {
    this.alignType = alignType;
    if (!isUndefined(offset) && isObject(offset)) {
      this.dx = offset.dx;
      this.dy = offset.dy;
    }
  }
  isEqual(another) {
    return this.alignType === another.alignType && this.dx === another.dx && this.dy === another.dy;
  }
}
class ArkSliderTips {
  constructor(value, content) {
    this.showTip = value;
    this.tipText = content;
  }
  isEqual(another) {
    return this.showTip === another.showTip && this.tipText === another.tipText;
  }
}
class ArkStarStyle {
  constructor() {
    this.backgroundUri = undefined;
    this.foregroundUri = undefined;
    this.secondaryUri = undefined;
  }
  isEqual(another) {
    return (this.backgroundUri === another.backgroundUri &&
      this.foregroundUri === another.foregroundUri &&
      this.secondaryUri === another.secondaryUri);
  }
}
class ArkBackgroundBlurStyle {
  constructor() {
    this.blurStyle = undefined;
    this.colorMode = undefined;
    this.adaptiveColor = undefined;
    this.scale = undefined;
    this.blurOptions = undefined;
  }
  isEqual(another) {
    return (this.blurStyle === another.blurStyle &&
      this.colorMode === another.colorMode &&
      this.adaptiveColor === another.adaptiveColor &&
      this.scale === another.scale &&
      this.blurOptions === another.blurOptions);
  }
}
class ArkBorder {
  constructor() {
    this.arkWidth = new ArkBorderWidth();
    this.arkColor = new ArkBorderColor();
    this.arkRadius = new ArkBorderRadius();
    this.arkStyle = new ArkBorderStyle();
  }
  isEqual(another) {
    return (this.arkWidth.isEqual(another.arkWidth) &&
      this.arkColor.isEqual(another.arkColor) &&
      this.arkRadius.isEqual(another.arkRadius) &&
      this.arkStyle.isEqual(another.arkStyle));
  }
  checkObjectDiff(another) {
    return !this.isEqual(another);
  }
}
class ArkBackgroundImageSize {
  constructor() {
    this.imageSize = undefined;
    this.width = undefined;
    this.height = undefined;
  }
  isEqual(another) {
    return this.imageSize === another.imageSize && this.width === another.width && this.height === another.height;
  }
}
class ArkBackgroundImage {
  constructor() {
    this.src = undefined;
    this.repeat = undefined;
  }
  isEqual(another) {
    return this.src === another.src && this.repeat === another.repeat;
  }
}
class ArkGridColColumnOption {
  constructor() {
    this.xs = undefined;
    this.sm = undefined;
    this.md = undefined;
    this.lg = undefined;
    this.xl = undefined;
    this.xxl = undefined;
  }
  isEqual(another) {
    return (this.xs === another.xs &&
      this.sm === another.sm &&
      this.md === another.md &&
      this.lg === another.lg &&
      this.xl === another.xl &&
      this.xxl === another.xxl);
  }
}
class ArkPadding {
  constructor() {
    this.top = undefined;
    this.right = undefined;
    this.bottom = undefined;
    this.left = undefined;
  }
  isEqual(another) {
    return (this.top === another.top &&
      this.right === another.right &&
      this.bottom === another.bottom &&
      this.left === another.left);
  }
}
class ArkPositionType {
  constructor() {
    this.useEdges = false;
    this.x = undefined;
    this.y = undefined;
    this.top = undefined;
    this.left = undefined;
    this.right = undefined;
    this.bottom = undefined;
  }

  parsePositionType(value) {
    if (isUndefined(value)) {
      return false;
    }
    if (('x' in value) || ('y' in value)) {
      this.useEdges = false;
      this.x = value.x;
      this.y = value.y;
      return true;
    } else if (('top' in value) || ('left' in value) || ('bottom' in value) || ('right' in value)) {
      this.useEdges = true;
      this.top = value.top;
      this.left = value.left;
      this.bottom = value.bottom;
      this.right = value.right;
      return true;
    } else {
      return false;
    }
  }
}
class ArkBarMode {
  isEqual(another) {
    return (this.barMode === another.barMode) && (this.options === another.options);
  }
}
class ArkDivider {
  isEqual(another) {
    return (this.divider === another.divider);
  }
}
class ArkBarGridAlign {
  isEqual(another) {
    return (this.barGridAlign === another.barGridAlign);
  }
}
class ArkScrollableBarModeOptions {
  isEqual(another) {
    return (this.value === another.value);
  }
}
class ArkAlignRules {
  constructor() {
    this.left = undefined;
    this.middle = undefined;
    this.right = undefined;
    this.top = undefined;
    this.center = undefined;
    this.bottom = undefined;
  }
  isEqual(another) {
    return (this.left === another.left &&
      this.middle === another.middle &&
      this.right === another.right &&
      this.top === another.top &&
      this.center === another.center &&
      this.bottom === another.bottom);
  }
}
class ArkSafeAreaExpandOpts {
  constructor() {
    this.type = undefined;
    this.edges = undefined;
  }
  isEqual(another) {
    return (this.type === another.type) && (this.edges === another.edges);
  }
}
class ArkButtonStyle {
  constructor() {
    this.left = 16;
    this.top = 48;
    this.width = 24;
    this.height = 24;
    this.icons = {
      shown: undefined,
      hidden: undefined,
      switching: undefined
    };
  }
  isEqual(another) {
    return (this.left === another.left &&
      this.top === another.top &&
      this.width === another.width &&
      this.height === another.height &&
      this.icons === another.icons);
  }
}
class ArkShadowInfoToArray {
  constructor() {
    this.radius = [];
    this.type = [];
    this.color = [];
    this.offsetX = [];
    this.offsetX = [];
    this.offsetY = [];
    this.fill = [];
  }
  isEqual(another) {
    return (this.radius === another.radius) &&
      (this.color === another.color) &&
      (this.offsetX === another.offsetX) &&
      (this.offsetY === another.offsetY) &&
      (this.fill === another.fill);
  }
  convertShadowOptions(value) {
    if (Object.getPrototypeOf(value).constructor === Object) {
      if (value.radius === null || value.radius === undefined) {
        return false;
      }
      else {
        this.radius.push(value.radius);
        this.type.push(value.type);
        this.color.push(value.color);
        this.offsetX.push((value.offsetX === undefined ||
          value.offsetX === null) ? 0 : value.offsetX);
        this.offsetY.push((value.offsetY === undefined ||
          value.offsetY === null) ? 0 : value.offsetY);
        this.fill.push((value.fill === undefined ||
          value.fill === null) ? false : value.fill);
        return true;
      }
    }
    else if (Object.getPrototypeOf(value).constructor === Array) {
      let isFlag = true;
      for (let item of value) {
        if (item.radius === undefined || item.radius === null) {
          isFlag = false;
          break;
        }
      }
      if (isFlag) {
        for (let objValue of value) {
          this.radius.push(objValue.radius);
          this.type.push(objValue.type);
          this.color.push(objValue.color);
          this.offsetX.push((objValue.offsetX === undefined || objValue.offsetX === null) ? 0 : objValue.offsetX);
          this.offsetY.push((objValue.offsetY === undefined || objValue.offsetY === null) ? 0 : objValue.offsetY);
          this.fill.push((objValue.fill === undefined || objValue.fill === null) ? false : objValue.fill);
        }
        return true;
      }
      else {
        return false;
      }
    }
  }
  checkDiff(value, stageValue) {
    if (!value || !stageValue || !value.radius || !stageValue.radius) {
      return true;
    }
    if (!((isResource(stageValue.radius) && isResource(value.radius) &&
      isResourceEqual(stageValue.radius, value.radius)) ||
      (isNumber(stageValue.radius) && isNumber(value.radius) &&
        stageValue.radius === value.radius))) {
      return true;
    }
    if (!(isNumber(stageValue.type) && isNumber(value.type) &&
      stageValue.type === value.type)) {
      return true;
    }
    if (!((isResource(stageValue.color) && isResource(value.color) &&
      isResourceEqual(stageValue.color, value.color)) ||
      (!isResource(stageValue.color) && !isResource(value.color) &&
        stageValue.color === value.color))) {
      return true;
    }
    if (!((isResource(stageValue.offsetX) && isResource(value.offsetX) &&
      isResourceEqual(stageValue.offsetX, value.offsetX)) ||
      (isNumber(stageValue.offsetX) && isNumber(value.offsetX) &&
        stageValue.offsetX === value.offsetX))) {
      return true;
    }
    if (!((isResource(stageValue.offsetY) && isResource(value.offsetY) &&
      isResourceEqual(stageValue.offsetY, value.offsetY)) ||
      (isNumber(stageValue.offsetY) && isNumber(value.offsetY) &&
        stageValue.offsetY === value.offsetY))) {
      return true;
    }
    if (!(isBoolean(stageValue.fill) && isBoolean(value.fill) &&
      stageValue.fill === value.fill)) {
      return true;
    }
    return false;
  }
}
class ArkTextBackGroundStyle {
  constructor() {
    this.color = undefined;
    this.radius = new ArkBorderRadius();
  }
  isEqual(another) {
    return (this.color === another.color &&
      this.radius.isEqual(another.arkRadius));
  }
  checkObjectDiff(another) {
    return !this.isEqual(another);
  }
  convertTextBackGroundStyleOptions(value) {
    let _a, _b, _c, _d;
    if (isUndefined(value)) {
      return false;
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.color) && (value === null || value === void 0 ? void 0 : value.color) !== null) {
      if (isNumber(value.color) || isString(value.color) || isResource(value.color)) {
        this.color = value.color;
      }
    }

    if (!isUndefined(value === null || value === void 0 ? void 0 : value.radius) && (value === null || value === void 0 ? void 0 : value.radius) !== null) {
      if (isNumber(value.radius) || isString(value.radius) || isResource(value.radius)) {
        this.radius.topLeft = value.radius;
        this.radius.topRight = value.radius;
        this.radius.bottomLeft = value.radius;
        this.radius.bottomRight = value.radius;
      }
      else {
        this.radius.topLeft = (_a = value.radius) === null || _a === void 0 ? void 0 : _a.topLeft;
        this.radius.topRight = (_b = value.radius) === null || _b === void 0 ? void 0 : _b.topRight;
        this.radius.bottomLeft = (_c = value.radius) === null || _c === void 0 ? void 0 : _c.bottomLeft;
        this.radius.bottomRight = (_d = value.radius) === null || _d === void 0 ? void 0 : _d.bottomRight;
      }
    }
    return true;
  }
}
class ArkSearchButton {
  constructor() {
    this.value = undefined;
    this.fontSize = undefined;
    this.fontColor = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.fontSize === another.fontSize) &&
      (this.fontColor === another.fontColor);
  }
}
class ArkSearchInputFilter {
  constructor() {
    this.value = undefined;
    this.error = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
    (this.error === another.error);
  }
}
class ArkImageFrameInfoToArray {
  constructor() {
    this.arrSrc = [];
    this.arrWidth = [];
    this.arrHeight = [];
    this.arrTop = [];
    this.arrLeft = [];
    this.arrDuration = [];
  }
  isEqual(another) {
    return (this.arrSrc.toString() === another.arrSrc.toString()) &&
      (this.arrWidth.toString() === another.arrWidth.toString()) &&
      (this.arrHeight.toString() === another.arrHeight.toString()) &&
      (this.arrTop.toString() === another.arrTop.toString()) &&
      (this.arrLeft.toString() === another.arrLeft.toString()) &&
      (this.arrDuration.toString() === another.arrDuration.toString());
  }
}
class ArkEdgeAlign {
  constructor() {
    this.alignType = undefined;
    this.offset = undefined;
  }
  isEqual(another) {
    return (this.alignType === another.alignType && this.offset === another.offset);
  }
}
class ArkKeyBoardShortCut {
  constructor() {
    this.value = undefined;
    this.keys = undefined;
    this.action = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) && (this.keys === another.keys) &&
      (this.action === another.action);
  }
}

class ArkCustomProperty {
  constructor() {
    this.key = undefined;
    this.value = undefined;
  }
}

class ArkBlendMode {
  constructor() {
    this.blendMode = undefined;
    this.blendApplyType = undefined;
  }
  isEqual(another) {
    return (this.blendMode === another.blendMode) && (this.blendApplyType === another.blendApplyType);
  }
}
class ArkAlignStyle {
  constructor() {
    this.indexerAlign = undefined;
    this.offset = undefined;
  }
  isEqual(another) {
    return (this.indexerAlign === another.indexerAlign && this.offset === another.offset);
  }
}
class ArkNestedScrollOptions {
  constructor() {
    this.scrollForward = undefined;
    this.scrollBackward = undefined;
  }
  isEqual(another) {
    return ((this.scrollForward === another.scrollForward) && (this.scrollBackward === another.scrollBackward));
  }
}
class ArkConstraintSizeOptions {
  constructor() {
    this.minWidth = undefined;
    this.maxWidth = undefined;
    this.minHeight = undefined;
    this.maxHeight = undefined;
  }
  isEqual(another) {
    return (this.minWidth === another.minWidth &&
      this.maxWidth === another.maxWidth &&
      this.minHeight === another.minHeight &&
      this.maxHeight === another.maxHeight);
  }
}
class ArkTextFieldShowCounter {
  constructor() {
    this.value = undefined;
    this.highlightBorder = undefined;
    this.thresholdPercentage = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.highlightBorder === another.highlightBorder) &&
      (this.thresholdPercentage === another.thresholdPercentage);
  }
}
class ArkTextInputFilter {
  constructor() {
    this.value = undefined;
    this.error = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.error === another.error);
  }
}
class ArkDotIndicator extends DotIndicator {
  constructor() {
    super();
    this.type = undefined;
    this.leftValue = undefined;
    this.topValue = undefined;
    this.rightValue = undefined;
    this.bottomValue = undefined;
    this.itemWidthValue = undefined;
    this.itemHeightValue = undefined;
    this.selectedItemWidthValue = undefined;
    this.selectedItemHeightValue = undefined;
    this.maskValue = undefined;
    this.colorValue = undefined;
    this.selectedColorValue = undefined;
  }
  isEqual(another) {
    return (this.type === another.type &&
      this.leftValue === another.leftValue &&
      this.topValue === another.topValue &&
      this.rightValue === another.rightValue &&
      this.bottomValue === another.bottomValue &&
      this.itemWidthValue === another.itemWidthValue &&
      this.itemHeightValue === another.itemHeightValue &&
      this.selectedItemWidthValue === another.selectedItemWidthValue &&
      this.selectedItemHeightValue === another.selectedItemHeightValue &&
      this.maskValue === another.maskValue &&
      this.colorValue === another.colorValue &&
      this.selectedColorValue === another.selectedColorValue);
  }
}
class ArkDigitIndicator extends DigitIndicator {
  constructor() {
    super();
    this.type = undefined;
    this.leftValue = undefined;
    this.topValue = undefined;
    this.rightValue = undefined;
    this.bottomValue = undefined;
    this.fontColorValue = undefined;
    this.selectedFontColorValue = undefined;
    this.digitFontValue = undefined;
    this.selectedDigitFontValue = undefined;
  }
  isEqual(another) {
    return (this.type === another.type &&
      this.leftValue === another.leftValue &&
      this.topValue === another.topValue &&
      this.rightValue === another.rightValue &&
      this.bottomValue === another.bottomValue &&
      this.digitFontValue === another.digitFontValue &&
      this.selectedDigitFontValue === another.selectedDigitFontValue);
  }
}
class ArkDigitFont {
  constructor() {
    this.size = undefined;
    this.weight = undefined;
  }
  isEqual(another) {
    return this.size === another.size && this.weight === another.weight;
  }
  parseFontWeight(value) {
    const valueWeightMap = {
      [0]: 'lighter',
      [1]: 'normal',
      [2]: 'regular',
      [3]: 'medium',
      [4]: 'bold',
      [5]: 'bolder'
    };
    if (isUndefined(value)) {
      this.weight = '-';
    }
    else if (value in valueWeightMap) {
      this.weight = valueWeightMap[value];
    }
    else {
      this.weight = value.toString();
    }
    return this.weight;
  }
}
class ArkDisplayArrow {
  constructor() {
    this.value = undefined;
    this.isHoverShow = undefined;
  }
  isEqual(another) {
    return this.value === another.value && this.isHoverShow === another.isHoverShow;
  }
}
class ArkDisplayCount {
  constructor() {
    this.value = undefined;
    this.swipeByGroup = undefined;
  }
  isEqual(another) {
    return this.value === another.value && this.swipeByGroup === another.swipeByGroup;
  }
}
class ArkGridEdgeEffect {
  constructor() {
    this.value = undefined;
    this.options = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.options === another.options);
  }
}

class ArkWaterFlowEdgeEffect {
  constructor() {
    this.value = undefined;
    this.options = undefined;
  }
  isEqual(another) {
    return (this.value === another.value) &&
      (this.options === another.options);
  }
}
class ArkMesh {
  constructor() {
    this.value = undefined;
    this.column = undefined;
    this.row = undefined;
  }
  isEqual(another) {
    return (deepCompareArrays(this.value, another.value) &&
      this.column === another.column &&
      this.row === another.row);
  }
}
class ArkLanesOpt {
  constructor() {
    this.lanesNum = undefined;
    this.minLength = undefined;
    this.maxLength = undefined;
    this.gutter = undefined;
  }
  isEqual(another) {
    return (this.lanesNum === another.lanesNum && this.minLength === another.minLength
      && this.maxLength === another.maxLength && this.gutter === another.gutter);
  }
}
class ArkScrollSnapOptions {
  constructor() {
    this.snapAlign = undefined;
    this.snapPagination = undefined;
    this.enableSnapToStart = undefined;
    this.enableSnapToEnd = undefined;
  }
  isEqual(another) {
    return ((this.snapAlign === another.snapAlign)
      && (this.snapPagination === another.snapPagination)
      && (this.enableSnapToStart === another.enableSnapToStart)
      && (this.enableSnapToEnd === another.enableSnapToEnd));
  }
}
class ArkGeometryTransition {
  constructor() {
      this.id = undefined;
      this.options = undefined;
  }
  isEqual(another) {
      return (this.id === another.id && this.options === another.options);
  }
}
class ArkSymbolEffect {
  constructor() {
    this.symbolEffect = undefined;
    this.action = undefined;
  }
  isEqual(another) {
    return (this.symbolEffect === another.symbolEffect) &&
      (this.action === another.action);
  }
}
/// <reference path='./import.ts' />
/// <reference path='./ArkComponent.ts' />
const FontWeightMap = {
  0: 'lighter',
  1: 'normal',
  2: 'regular',
  3: 'medium',
  4: 'bold',
  5: 'bolder',
  100: '100',
  200: '200',
  300: '300',
  400: '400',
  500: '500',
  600: '600',
  700: '700',
  800: '800',
  900: '900',
};
class ArkButtonComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonBackgroundColorModifier.identity, ButtonBackgroundColorModifier, value);
    return this;
  }
  type(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonTypeModifier.identity, ButtonTypeModifier, value);
    return this;
  }
  stateEffect(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonStateEffectModifier.identity, ButtonStateEffectModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonFontColorModifier.identity, ButtonFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonFontSizeModifier.identity, ButtonFontSizeModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonFontWeightModifier.identity, ButtonFontWeightModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonFontStyleModifier.identity, ButtonFontStyleModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonFontFamilyModifier.identity, ButtonFontFamilyModifier, value);
    return this;
  }
  labelStyle(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonLabelStyleModifier.identity, ButtonLabelStyleModifier, value);
    return this;
  }
  borderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonBorderRadiusModifier.identity, ButtonBorderRadiusModifier, value);
    return this;
  }
  border(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonBorderModifier.identity, ButtonBorderModifier, value);
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonSizeModifier.identity, ButtonSizeModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().button.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().button.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, buttonConfiguration) {
    buttonConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.buttonNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.buttonNode = new xNode.BuilderNode(context);
      this.buttonNode.build(this.builder, buttonConfiguration);
      this.needRebuild = false;
    } else {
      this.buttonNode.update(buttonConfiguration);
    }
    return this.buttonNode.getFrameNode();
  }
  role(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonRoleModifier.identity, ButtonRoleModifier, value);
    return this;
  }
  buttonStyle(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonStyleModifier.identity, ButtonStyleModifier, value);
    return this;
  }
  controlSize(value) {
    modifierWithKey(this._modifiersWithKeys, ButtonControlSizeModifier.identity, ButtonControlSizeModifier, value);
    return this;
  }
}
class ButtonBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetBackgroundColor(node);
    }
    else {
      getUINativeModule().button.setBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonBackgroundColorModifier.identity = Symbol('buttonBackgroundColor');
class ButtonRoleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonRole(node);
    } else {
      getUINativeModule().button.setButtonRole(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonRoleModifier.identity = Symbol('buttonRole');
class ButtonStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonStyle(node);
    } else {
      getUINativeModule().button.setButtonStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonStyleModifier.identity = Symbol('buttonStyle');
class ButtonControlSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonControlSize(node);
    } else {
      getUINativeModule().button.setButtonControlSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonControlSizeModifier.identity = Symbol('buttonControlSize');
class ButtonStateEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetStateEffect(node);
    }
    else {
      getUINativeModule().button.setStateEffect(node, this.value);
    }
  }
}
ButtonStateEffectModifier.identity = Symbol('buttonStateEffect');
class ButtonFontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetFontStyle(node);
    }
    else {
      getUINativeModule().button.setFontStyle(node, this.value);
    }
  }
}
ButtonFontStyleModifier.identity = Symbol('buttonFontStyle');
class ButtonFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetFontFamily(node);
    }
    else {
      getUINativeModule().button.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonFontFamilyModifier.identity = Symbol('buttonFontFamily');
class ButtonLabelStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetLabelStyle(node);
    }
    else {
      let textOverflow = this.value.overflow; // number(enum) -> Ace::TextOverflow
      let maxLines = this.value.maxLines; // number -> uint32_t
      let minFontSize = this.value.minFontSize; // number | string | Resource -> Dimension
      let maxFontSize = this.value.maxFontSize; // number | string | Resource -> Dimension
      let heightAdaptivePolicy = this.value.heightAdaptivePolicy; // number(enum) -> Ace::TextHeightAdaptivePolicy
      let fontSize; // number | string | Resource -> Dimension
      let fontWeight; // number | string | Ace::FontWeight -> string -> Ace::FontWeight
      let fontStyle; // number(enum) -> Ace::FontStyle
      let fontFamily; // string -> std::vector<std::string>
      if (isObject(this.value.font)) {
        fontSize = this.value.font.size;
        fontStyle = this.value.font.style;
        fontFamily = this.value.font.family;
        fontWeight = this.value.font.weight;
      }
      getUINativeModule().button.setLabelStyle(node, textOverflow, maxLines, minFontSize,
        maxFontSize, heightAdaptivePolicy, fontSize, fontWeight, fontStyle, fontFamily);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.value.overflow === this.stageValue.overflow &&
        this.value.maxLines === this.stageValue.maxLines &&
        this.value.minFontSize === this.stageValue.minFontSize &&
        this.value.maxFontSize === this.stageValue.maxFontSize &&
        this.value.heightAdaptivePolicy === this.stageValue.heightAdaptivePolicy &&
        this.value.font === this.stageValue.font);
    }
    else {
      return true;
    }
  }
}
ButtonLabelStyleModifier.identity = Symbol('buttonLabelStyle');
class ButtonTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetType(node);
    }
    else {
      getUINativeModule().button.setType(node, this.value);
    }
  }
}
ButtonTypeModifier.identity = Symbol('buttonType');
class ButtonFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetFontColor(node);
    }
    else {
      getUINativeModule().button.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonFontColorModifier.identity = Symbol('buttonFontColor');
class ButtonFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetFontSize(node);
    }
    else {
      getUINativeModule().button.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ButtonFontSizeModifier.identity = Symbol('buttonFontSize');
class ButtonFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetFontWeight(node);
    }
    else {
      getUINativeModule().button.setFontWeight(node, this.value);
    }
  }
}
ButtonFontWeightModifier.identity = Symbol('buttonFontWeight');
class ButtonBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonBorderRadius(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().button.setButtonBorderRadius(node, this.value, this.value, this.value, this.value);
      }
      else {
        getUINativeModule().button.setButtonBorderRadius(node, this.value.topLeft, this.value.topRight, this.value.bottomLeft, this.value.bottomRight);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    }
    else {
      return true;
    }
  }
}
ButtonBorderRadiusModifier.identity = Symbol('buttonBorderRadius');
class ButtonBorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonBorder(node);
    } else {
      let widthLeft;
      let widthRight;
      let widthTop;
      let widthBottom;
      if (!isUndefined(this.value.width) && this.value.width != null) {
        if (isNumber(this.value.width) || isString(this.value.width) || isResource(this.value.width)) {
          widthLeft = this.value.width;
          widthRight = this.value.width;
          widthTop = this.value.width;
          widthBottom = this.value.width;
        } else {
          widthLeft = this.value.width.left;
          widthRight = this.value.width.right;
          widthTop = this.value.width.top;
          widthBottom = this.value.width.bottom;
        }
      }
      let leftColor;
      let rightColor;
      let topColor;
      let bottomColor;
      if (!isUndefined(this.value.color) && this.value.color != null) {
        if (isNumber(this.value.color) || isString(this.value.color) || isResource(this.value.color)) {
          leftColor = this.value.color;
          rightColor = this.value.color;
          topColor = this.value.color;
          bottomColor = this.value.color;
        } else {
          leftColor = this.value.color.left;
          rightColor = this.value.color.right;
          topColor = this.value.color.top;
          bottomColor = this.value.color.bottom;
        }
      }
      let topLeft;
      let topRight;
      let bottomLeft;
      let bottomRight;
      if (!isUndefined(this.value.radius) && this.value.radius != null) {
        if (isNumber(this.value.radius) || isString(this.value.radius) || isResource(this.value.radius)) {
          topLeft = this.value.radius;
          topRight = this.value.radius;
          bottomLeft = this.value.radius;
          bottomRight = this.value.radius;
        } else {
          topLeft = this.value.radius.topLeft;
          topRight = this.value.radius.topRight;
          bottomLeft = this.value.radius.bottomLeft;
          bottomRight = this.value.radius.bottomRight;
        }
      }
      let styleTop;
      let styleRight;
      let styleBottom;
      let styleLeft;
      if (!isUndefined(this.value.style) && this.value.style != null) {
        if (isNumber(this.value.style) || isString(this.value.style) || isResource(this.value.style)) {
          styleTop = this.value.style;
          styleRight = this.value.style;
          styleBottom = this.value.style;
          styleLeft = this.value.style;
        } else {
          styleTop = this.value.style.top;
          styleRight = this.value.style.right;
          styleBottom = this.value.style.bottom;
          styleLeft = this.value.style.left;
        }
      }
      getUINativeModule().button.setButtonBorder(
        node,
        widthLeft,
        widthRight,
        widthTop,
        widthBottom,
        leftColor,
        rightColor,
        topColor,
        bottomColor,
        topLeft,
        topRight,
        bottomLeft,
        bottomRight,
        styleTop,
        styleRight,
        styleBottom,
        styleLeft
      );
    }
  }
  checkObjectDiff() {
    return (
      !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.color, this.value.color) ||
      !isBaseOrResourceEqual(this.stageValue.radius, this.value.radius) ||
      !isBaseOrResourceEqual(this.stageValue.style, this.value.style)
    );
  }
}
ButtonBorderModifier.identity = Symbol('buttonBorder');
class ButtonSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().button.resetButtonSize(node);
    } else {
      getUINativeModule().button.setButtonSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return (
      !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height)
    );
  }
}
ButtonSizeModifier.identity = Symbol('buttonSize');
// @ts-ignore
if (globalThis.Button !== undefined) {
  globalThis.Button.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkButtonComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ButtonModifier(nativePtr, classType);
    });
  };
  // @ts-ignore
  globalThis.Button.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkButtonComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkLoadingProgressComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, LoadingProgressColorModifier.identity, LoadingProgressColorModifier, value);
    return this;
  }
  enableLoading(value) {
    modifierWithKey(this._modifiersWithKeys, LoadingProgressEnableLoadingModifier.identity, LoadingProgressEnableLoadingModifier, value);
    return this;
  }
  foregroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, LoadingProgressForegroundColorModifier.identity,
      LoadingProgressForegroundColorModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().loadingProgress.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().loadingProgress.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, loadingProgressConfiguration) {
    loadingProgressConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.loadingProgressNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.loadingProgressNode = new xNode.BuilderNode(context);
      this.loadingProgressNode.build(this.builder, loadingProgressConfiguration);
      this.needRebuild = false;
    } else {
      this.loadingProgressNode.update(loadingProgressConfiguration);
    }
    return this.loadingProgressNode.getFrameNode();
  }
}
class LoadingProgressColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().loadingProgress.resetColor(node);
    }
    else {
      getUINativeModule().loadingProgress.setColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
LoadingProgressColorModifier.identity = Symbol('loadingProgressColor');
class LoadingProgressForegroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().loadingProgress.resetForegroundColor(node);
    }
    else {
      getUINativeModule().loadingProgress.setForegroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
LoadingProgressForegroundColorModifier.identity = Symbol('loadingProgressForegroundColor');
class LoadingProgressEnableLoadingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().loadingProgress.resetEnableLoading(node);
    }
    else {
      getUINativeModule().loadingProgress.setEnableLoading(node, this.value);
    }
  }
}
LoadingProgressEnableLoadingModifier.identity = Symbol('loadingProgressEnableLoading');
// @ts-ignore
if (globalThis.LoadingProgress !== undefined) {
  globalThis.LoadingProgress.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkLoadingProgressComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.LoadingProgressModifier(nativePtr, classType);
    });
  };
}

globalThis.LoadingProgress.contentModifier = function (modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return new ArkLoadingProgressComponent(nativeNode);
  });
  component.setContentModifier(modifier);
};

/// <reference path='./import.ts' />
class ArkRefreshComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onStateChange(callback) {
    throw new Error('Method not implemented.');
  }
  onRefreshing(callback) {
    throw new Error('Method not implemented.');
  }
  refreshOffset(value) {
    modifierWithKey(this._modifiersWithKeys, RefreshOffsetModifier.identity, RefreshOffsetModifier, value);
    return this;
  }
  pullToRefresh(value) {
    modifierWithKey(this._modifiersWithKeys, PullToRefreshModifier.identity, PullToRefreshModifier, value);
    return this;
  }
}
class RefreshOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().refresh.resetRefreshOffset(node);
    }
    else {
      getUINativeModule().refresh.setRefreshOffset(node, this.value);
    }
  }
}
RefreshOffsetModifier.identity = Symbol('refreshOffset');
class PullToRefreshModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().refresh.resetPullToRefresh(node);
    }
    else {
      getUINativeModule().refresh.setPullToRefresh(node, this.value);
    }
  }
}
PullToRefreshModifier.identity = Symbol('pullToRefresh');
// @ts-ignore
if (globalThis.Refresh !== undefined) {
  globalThis.Refresh.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRefreshComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RefreshModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ScrollNestedScrollModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetNestedScroll(node);
    }
    else {
      getUINativeModule().scroll.setNestedScroll(node, this.value.scrollForward, this.value.scrollBackward);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.scrollForward, this.value.scrollForward) ||
      !isBaseOrResourceEqual(this.stageValue.scrollBackward, this.value.scrollBackward);
  }
}
ScrollNestedScrollModifier.identity = Symbol('nestedScroll');
class ScrollEnableScrollInteractionModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetEnableScroll(node);
    }
    else {
      getUINativeModule().scroll.setEnableScroll(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ScrollEnableScrollInteractionModifier.identity = Symbol('enableScrollInteraction');
class ScrollEnablePagingModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetEnablePaging(node);
    } else {
      getUINativeModule().scroll.setEnablePaging(node, this.value);
    }
  }
}
ScrollEnablePagingModifier.identity = Symbol('scrollEnablePaging');
class ScrollFrictionModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetFriction(node);
    }
    else {
      getUINativeModule().scroll.setFriction(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ScrollFrictionModifier.identity = Symbol('friction');
class ScrollScrollSnapModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetScrollSnap(node);
    }
    else {
      let snapPagination = [];
      let isArray = true;
      if (Array.isArray(this.value.snapPagination)) {
        for (let i = 0; i < this.value.snapPagination.length; i++) {
          let item = this.value.snapPagination[i];
          snapPagination.push(item);
        }
      }
      else {
        isArray = false;
      }
      if (isArray) {
        getUINativeModule().scroll.setScrollSnap(node, this.value.snapAlign, snapPagination,
          this.value.enableSnapToStart, this.value.enableSnapToEnd);
      }
      else {
        getUINativeModule().scroll.setScrollSnap(node, this.value.snapAlign, this.value.snapPagination,
          this.value.enableSnapToStart, this.value.enableSnapToEnd);
      }
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.snapAlign === this.value.snapAlign) &&
      (this.stageValue.enableSnapToStart === this.value.enableSnapToStart) &&
      (this.stageValue.enableSnapToEnd === this.value.enableSnapToEnd) &&
      (this.stageValue.snapPagination === this.value.snapPagination));
  }
}
ScrollScrollSnapModifier.identity = Symbol('scrollSnap');
class ScrollScrollBarModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetScrollBar(node);
    }
    else {
      getUINativeModule().scroll.setScrollBar(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ScrollScrollBarModifier.identity = Symbol('scrollBar');
class ScrollScrollableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetScrollable(node);
    }
    else {
      getUINativeModule().scroll.setScrollable(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ScrollScrollableModifier.identity = Symbol('scrollable');
class ScrollEdgeEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a;
    if (reset) {
      getUINativeModule().scroll.resetEdgeEffect(node);
    }
    else {
      getUINativeModule().scroll.setEdgeEffect(node, this.value.value, (_a = this.value.options) === null || _a ===
      void 0 ? void 0 : _a.alwaysEnabled);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
ScrollEdgeEffectModifier.identity = Symbol('edgeEffect');
class ScrollScrollBarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetScrollBarWidth(node);
    }
    else {
      getUINativeModule().scroll.setScrollBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ScrollScrollBarWidthModifier.identity = Symbol('scrollBarWidth');
class ScrollScrollBarColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().scroll.resetScrollBarColor(node);
    }
    else {
      getUINativeModule().scroll.setScrollBarColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ScrollScrollBarColorModifier.identity = Symbol('scrollBarColor');
class ScrollClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ScrollClipModifier.identity = Symbol('scrollClip');
class ArkScrollComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  scrollable(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollScrollableModifier.identity, ScrollScrollableModifier, value);
    return this;
  }
  onScroll(event) {
    throw new Error('Method not implemented.');
  }
  onScrollEdge(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStart(event) {
    throw new Error('Method not implemented.');
  }
  onScrollEnd(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStop(event) {
    throw new Error('Method not implemented.');
  }
  scrollBar(value) {
    if (value in BarState) {
      modifierWithKey(this._modifiersWithKeys, ScrollScrollBarModifier.identity, ScrollScrollBarModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, ScrollScrollBarModifier.identity, ScrollScrollBarModifier, undefined);
    }
    return this;
  }
  scrollBarColor(color) {
    modifierWithKey(this._modifiersWithKeys, ScrollScrollBarColorModifier.identity, ScrollScrollBarColorModifier, color);
    return this;
  }
  scrollBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollScrollBarWidthModifier.identity, ScrollScrollBarWidthModifier, value);
    return this;
  }
  edgeEffect(value, options) {
    let effect = new ArkScrollEdgeEffect();
    effect.value = value;
    effect.options = options;
    modifierWithKey(this._modifiersWithKeys, ScrollEdgeEffectModifier.identity, ScrollEdgeEffectModifier, effect);
    return this;
  }
  onScrollFrameBegin(event) {
    throw new Error('Method not implemented.');
  }
  nestedScroll(value) {
    let options = new ArkNestedScrollOptions();
    if (value) {
      if (value.scrollForward) {
        options.scrollForward = value.scrollForward;
      }
      if (value.scrollBackward) {
        options.scrollBackward = value.scrollBackward;
      }
      modifierWithKey(this._modifiersWithKeys, ScrollNestedScrollModifier.identity, ScrollNestedScrollModifier, options);
    }
    return this;
  }
  enableScrollInteraction(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollEnableScrollInteractionModifier.identity, ScrollEnableScrollInteractionModifier, value);
    return this;
  }
  enablePaging(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollEnablePagingModifier.identity, ScrollEnablePagingModifier, value);
    return this;
  }
  friction(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollFrictionModifier.identity, ScrollFrictionModifier, value);
    return this;
  }
  scrollSnap(value) {
    let options = new ArkScrollSnapOptions();
    if (value) {
      if (value.snapAlign) {
        options.snapAlign = value.snapAlign;
      }
      if (value.snapPagination) {
        options.snapPagination = value.snapPagination;
      }
      if (value.enableSnapToStart) {
        options.enableSnapToStart = value.enableSnapToStart;
      }
      if (value.enableSnapToEnd) {
        options.enableSnapToEnd = value.enableSnapToEnd;
      }
      modifierWithKey(this._modifiersWithKeys, ScrollScrollSnapModifier.identity, ScrollScrollSnapModifier, options);
    }
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollClipModifier.identity, ScrollClipModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Scroll !== undefined) {
  globalThis.Scroll.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkScrollComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ScrollModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkToggleComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleSelectedColorModifier.identity, ToggleSelectedColorModifier, value);
    return this;
  }
  switchPointColor(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleSwitchPointColorModifier.identity, ToggleSwitchPointColorModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleHeightModifier.identity, ToggleHeightModifier, value);
    return this;
  }
  responseRegion(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleResponseRegionModifier.identity, ToggleResponseRegionModifier, value);
    return this;
  }
  padding(value) {
    modifierWithKey(this._modifiersWithKeys, TogglePaddingModifier.identity, TogglePaddingModifier, value);
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleBackgroundColorModifier.identity, ToggleBackgroundColorModifier, value);
    return this;
  }
  hoverEffect(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleHoverEffectModifier.identity, ToggleHoverEffectModifier, value);
    return this;
  }
  switchStyle(value) {
    modifierWithKey(this._modifiersWithKeys, ToggleSwitchStyleModifier.identity, ToggleSwitchStyleModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().toggle.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().toggle.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, toggleConfiguration) {
    toggleConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.toggleNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.toggleNode = new xNode.BuilderNode(context);
      this.toggleNode.build(this.builder, toggleConfiguration);
      this.needRebuild = false;
    } else {
      this.toggleNode.update(toggleConfiguration);
    }
    return this.toggleNode.getFrameNode();
  }
}
class ToggleSelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetSelectedColor(node);
    }
    else {
      getUINativeModule().toggle.setSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ToggleSelectedColorModifier.identity = Symbol('toggleSelectedColor');
class ToggleSwitchPointColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetSwitchPointColor(node);
    }
    else {
      getUINativeModule().toggle.setSwitchPointColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ToggleSwitchPointColorModifier.identity = Symbol('toggleSwitchPointColor');
class ToggleHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetHeight(node);
    }
    else {
      getUINativeModule().toggle.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ToggleHeightModifier.identity = Symbol('toggleHeight');
class ToggleResponseRegionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().toggle.resetResponseRegion(node);
    }
    else {
      let responseRegion = [];
      if (Array.isArray(this.value)) {
        for (let i = 0; i < this.value.length; i++) {
          responseRegion.push((_a = this.value[i].x) !== null && _a !== void 0 ? _a : 'PLACEHOLDER');
          responseRegion.push((_b = this.value[i].y) !== null && _b !== void 0 ? _b : 'PLACEHOLDER');
          responseRegion.push((_c = this.value[i].width) !== null && _c !== void 0 ? _c : 'PLACEHOLDER');
          responseRegion.push((_d = this.value[i].height) !== null && _d !== void 0 ? _d : 'PLACEHOLDER');
        }
      }
      else {
        responseRegion.push((_e = this.value.x) !== null && _e !== void 0 ? _e : 'PLACEHOLDER');
        responseRegion.push((_f = this.value.y) !== null && _f !== void 0 ? _f : 'PLACEHOLDER');
        responseRegion.push((_g = this.value.width) !== null && _g !== void 0 ? _g : 'PLACEHOLDER');
        responseRegion.push((_h = this.value.height) !== null && _h !== void 0 ? _h : 'PLACEHOLDER');
      }
      getUINativeModule().toggle.setResponseRegion(node, responseRegion, responseRegion.length);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.stageValue) && Array.isArray(this.value)) {
      if (this.value.length !== this.stageValue.length) {
        return true;
      }
      else {
        for (let i = 0; i < this.value.length; i++) {
          if (!(isBaseOrResourceEqual(this.stageValue[i].x, this.value[i].x) &&
            isBaseOrResourceEqual(this.stageValue[i].y, this.value[i].y) &&
            isBaseOrResourceEqual(this.stageValue[i].width, this.value[i].width) &&
            isBaseOrResourceEqual(this.stageValue[i].height, this.value[i].height))) {
            return true;
          }
        }
        return false;
      }
    }
    else if (typeof this.stageValue === 'object' && typeof this.value === 'object') {
      return !(this.stageValue.x === this.value.x &&
        this.stageValue.y === this.value.y &&
        this.stageValue.height === this.value.height &&
        this.stageValue.width === this.value.width);
    }
    else {
      return true;
    }
  }
}
ToggleResponseRegionModifier.identity = Symbol('toggleResponseRegion');
class TogglePaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetPadding(node);
    }
    else {
      let top = undefined;
      let right = undefined;
      let bottom = undefined;
      let left = undefined;
      if (isLengthType(this.value) || isResource(this.value)) {
        top = this.value;
        right = this.value;
        bottom = this.value;
        left = this.value;
      }
      else if (typeof this.value === 'object') {
        top = this.value.top;
        right = this.value.right;
        bottom = this.value.bottom;
        left = this.value.left;
      }
      getUINativeModule().toggle.setPadding(node, top, right, bottom, left);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      if (typeof this.stageValue === 'object' && typeof this.value === 'object') {
        return !(this.stageValue.left === this.value.left &&
          this.stageValue.right === this.value.right &&
          this.stageValue.top === this.value.top &&
          this.stageValue.bottom === this.value.bottom);
      }
      else {
        return !(this.stageValue === this.value);
      }
    }
    return true;
  }
}
TogglePaddingModifier.identity = Symbol('togglePadding');
class ToggleBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetBackgroundColor(node);
    }
    else {
      getUINativeModule().toggle.setBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ToggleBackgroundColorModifier.identity = Symbol('toggleBackgroundColor');
class ToggleHoverEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().toggle.resetHoverEffect(node);
    }
    else {
      getUINativeModule().toggle.setHoverEffect(node, this.value);
    }
  }
}
ToggleHoverEffectModifier.identity = Symbol('toggleHoverEffect');
class ToggleSwitchStyleModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().toggle.resetSwitchStyle(node);
        }
        else {
            getUINativeModule().toggle.setSwitchStyle(node, this.value.pointRadius, this.value.unselectedColor, this.value.pointColor, this.value.trackBorderRadius);
        }
    }
    checkObjectDiff() {
        if (!isResource(this.stageValue) && !isResource(this.value)) {
            return !(this.stageValue.pointRadius === this.value.pointRadius &&
                this.stageValue.unselectedColor === this.value.unselectedColor &&
                this.stageValue.pointColor === this.value.pointColor &&
                this.stageValue.trackBorderRadius === this.value.trackBorderRadius);
        }
        else if (isResource(this.stageValue) && isResource(this.value)){
          return !(isResourceEqual(this.stageValue.pointRadius, this.value.pointRadius) && 
          isResourceEqual(this.stageValue.unselectedColor, this.value.unselectedColor) && 
          isResourceEqual(this.stageValue.pointColor, this.value.pointColor) &&
          isResourceEqual(this.stageValue.trackBorderRadius, this.value.trackBorderRadius));
        }
        else {
            return true;
        }
    }
}
ToggleSwitchStyleModifier.identity = Symbol('toggleSwitchStyle');
// @ts-ignore
if (globalThis.Toggle !== undefined) {
  globalThis.Toggle.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkToggleComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ToggleModifier(nativePtr, classType);
    });
  };
}
// @ts-ignore
globalThis.Toggle.contentModifier = function (modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return new ArkToggleComponent(nativeNode);
  });
  component.setContentModifier(modifier);
};

/// <reference path='./import.ts' />
class ArkSelectComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  optionWidth(value) {
    modifierWithKey(this._modifiersWithKeys, SelectOptionWidthModifier.identity, SelectOptionWidthModifier, value);
    return this;
  }
  optionHeight(value) {
    modifierWithKey(this._modifiersWithKeys, SelectOptionHeightModifier.identity, SelectOptionHeightModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, SelectWidthModifier.identity, SelectWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, SelectHeightModifier.identity, SelectHeightModifier, value);
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, SelectSizeModifier.identity, SelectSizeModifier, value);
    return this;
  }
  selected(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedModifier.identity, SelectedModifier, value);
    return this;
  }
  value(value) {
    modifierWithKey(this._modifiersWithKeys, ValueModifier.identity, ValueModifier, value);
    return this;
  }
  font(value) {
    modifierWithKey(this._modifiersWithKeys, FontModifier.identity, FontModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectFontColorModifier.identity, SelectFontColorModifier, value);
    return this;
  }
  selectedOptionBgColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedOptionBgColorModifier.identity, SelectedOptionBgColorModifier, value);
    return this;
  }
  selectedOptionFont(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedOptionFontModifier.identity, SelectedOptionFontModifier, value);
    return this;
  }
  selectedOptionFontColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedOptionFontColorModifier.identity, SelectedOptionFontColorModifier, value);
    return this;
  }
  optionBgColor(value) {
    modifierWithKey(this._modifiersWithKeys, OptionBgColorModifier.identity, OptionBgColorModifier, value);
    return this;
  }
  optionFont(value) {
    modifierWithKey(this._modifiersWithKeys, OptionFontModifier.identity, OptionFontModifier, value);
    return this;
  }
  optionFontColor(value) {
    modifierWithKey(this._modifiersWithKeys, OptionFontColorModifier.identity, OptionFontColorModifier, value);
    return this;
  }
  onSelect(callback) {
    throw new Error('Method not implemented.');
  }
  space(value) {
    modifierWithKey(this._modifiersWithKeys, SpaceModifier.identity, SpaceModifier, value);
    return this;
  }
  arrowPosition(value) {
    modifierWithKey(this._modifiersWithKeys, ArrowPositionModifier.identity, ArrowPositionModifier, value);
    return this;
  }
  menuAlign(alignType, offset) {
    let menuAlign = new ArkMenuAlignType(alignType, offset);
    modifierWithKey(this._modifiersWithKeys, MenuAlignModifier.identity, MenuAlignModifier, menuAlign);
    return this;
  }
  controlSize(controlSize) {
    modifierWithKey(this._modifiersWithKeys, ControlSizeModifier.identity, ControlSizeModifier, controlSize);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().select.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().select.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, menuItemConfiguration) {
    menuItemConfiguration.contentModifier = this.modifier;
    const index = menuItemConfiguration.index;
    const xNode = globalThis.requireNapi('arkui.node');
    this.menuItemNodes = new xNode.BuilderNode(context);
    this.menuItemNodes.build(this.builder, menuItemConfiguration);
    return this.menuItemNodes.getFrameNode();
  }
}
class FontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetFont(node);
    }
    else {
      getUINativeModule().select.setFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
FontModifier.identity = Symbol('selectFont');
class OptionFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetOptionFont(node);
    }
    else {
      getUINativeModule().select.setOptionFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
OptionFontModifier.identity = Symbol('selectOptionFont');
class SelectedOptionFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSelectedOptionFont(node);
    }
    else {
      getUINativeModule().select.setSelectedOptionFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
SelectedOptionFontModifier.identity = Symbol('selectSelectedOptionFont');
class MenuAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetMenuAlign(node);
    }
    else {
      getUINativeModule().select.setMenuAlign(node, this.value.alignType, this.value.dx, this.value.dy);
    }
  }
  checkObjectDiff() {
    let alignTypeEQ = this.stageValue.alignType === this.value.alignType;
    let dxEQ = isBaseOrResourceEqual(this.stageValue, this.value);
    let dyEQ = isBaseOrResourceEqual(this.stageValue, this.value);
    return !alignTypeEQ || !dxEQ || !dyEQ;
  }
  isEqual(stageValue, value) {
    if ((!isUndefined(stageValue) && isResource(stageValue)) &&
      (!isUndefined(value) && isResource(value))) {
      return !isResourceEqual(stageValue, value);
    }
    else {
      return stageValue !== value;
    }
  }
}
MenuAlignModifier.identity = Symbol('selectMenuAlign');
class ControlSizeModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().select.resetControlSize(node);
        }
        else {
            getUINativeModule().select.setControlSize(node, this.value);
        }
    }
    checkObjectDiff() {
        return this.stageValue !== this.value;
    }
}
ControlSizeModifier.identity = Symbol('controlSize');
class ArrowPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetArrowPosition(node);
    }
    else {
      getUINativeModule().select.setArrowPosition(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ArrowPositionModifier.identity = Symbol('selectArrowPosition');
class SpaceModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSpace(node);
    }
    else {
      getUINativeModule().select.setSpace(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SpaceModifier.identity = Symbol('selectSpace');
class ValueModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetValue(node);
    }
    else {
      getUINativeModule().select.setValue(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ValueModifier.identity = Symbol('selectValue');
class SelectedModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSelected(node);
    }
    else {
      getUINativeModule().select.setSelected(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectedModifier.identity = Symbol('selectSelected');
class SelectFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetFontColor(node);
    }
    else {
      getUINativeModule().select.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectFontColorModifier.identity = Symbol('selectFontColor');
class SelectedOptionBgColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSelectedOptionBgColor(node);
    }
    else {
      getUINativeModule().select.setSelectedOptionBgColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectedOptionBgColorModifier.identity = Symbol('selectSelectedOptionBgColor');
class OptionBgColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetOptionBgColor(node);
    }
    else {
      getUINativeModule().select.setOptionBgColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
OptionBgColorModifier.identity = Symbol('selectOptionBgColor');
class OptionFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetOptionFontColor(node);
    }
    else {
      getUINativeModule().select.setOptionFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
OptionFontColorModifier.identity = Symbol('selectOptionFontColor');
class SelectedOptionFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSelectedOptionFontColor(node);
    }
    else {
      getUINativeModule().select.setSelectedOptionFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectedOptionFontColorModifier.identity = Symbol('selectSelectedOptionFontColor');
class SelectOptionWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetOptionWidth(node);
    } else {
      getUINativeModule().select.setOptionWidth(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectOptionWidthModifier.identity = Symbol('selectOptionWidth');
class SelectOptionHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetOptionHeight(node);
    } else {
      getUINativeModule().select.setOptionHeight(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectOptionHeightModifier.identity = Symbol('selectOptionHeight');
class SelectWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetWidth(node);
    } else {
      getUINativeModule().select.setWidth(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectWidthModifier.identity = Symbol('selectWidth');
class SelectHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetHeight(node);
    } else {
      getUINativeModule().select.setHeight(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectHeightModifier.identity = Symbol('selectHeight');
class SelectSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().select.resetSize(node);
    } else {
      getUINativeModule().select.setSize(node, this.value.width, this.value.height);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
SelectSizeModifier.identity = Symbol('selectSize');
// @ts-ignore
if (globalThis.Select !== undefined) {
  globalThis.Select.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSelectComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SelectModifier(nativePtr, classType);
    });
  };

  globalThis.Select.menuItemContentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkSelectComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkRadioComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  checked(value) {
    modifierWithKey(this._modifiersWithKeys, RadioCheckedModifier.identity, RadioCheckedModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  radioStyle(value) {
    modifierWithKey(this._modifiersWithKeys, RadioStyleModifier.identity, RadioStyleModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, RadioWidthModifier.identity, RadioWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, RadioHeightModifier.identity, RadioHeightModifier, value);
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, RadioSizeModifier.identity, RadioSizeModifier, value);
    return this;
  }
  hoverEffect(value) {
    modifierWithKey(this._modifiersWithKeys, RadioHoverEffectModifier.identity, RadioHoverEffectModifier, value);
    return this;
  }
  padding(value) {
    modifierWithKey(this._modifiersWithKeys, RadioPaddingModifier.identity, RadioPaddingModifier, value);
    return this;
  }
  responseRegion(value) {
    modifierWithKey(this._modifiersWithKeys, RadioResponseRegionModifier.identity, RadioResponseRegionModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().radio.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().radio.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, radioConfiguration) {
    radioConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.radioNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.radioNode = new xNode.BuilderNode(context);
      this.radioNode.build(this.builder, radioConfiguration);
      this.needRebuild = false;
    } else {
      this.radioNode.update(radioConfiguration);
    }
    return this.radioNode.getFrameNode();
  }
}
class RadioCheckedModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioChecked(node);
    }
    else {
      getUINativeModule().radio.setRadioChecked(node, this.value);
    }
  }
}
RadioCheckedModifier.identity = Symbol('radioChecked');
class RadioStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioStyle(node);
    }
    else {
      getUINativeModule().radio.setRadioStyle(node, this.value.checkedBackgroundColor, this.value.uncheckedBorderColor, this.value.indicatorColor);
    }
  }
  checkObjectDiff() {
    let checkedBackgroundColorEQ = isBaseOrResourceEqual(this.stageValue.checkedBackgroundColor, this.value.checkedBackgroundColor);
    let uncheckedBorderColorEQ = isBaseOrResourceEqual(this.stageValue.uncheckedBorderColor, this.value.uncheckedBorderColor);
    let indicatorColorEQ = isBaseOrResourceEqual(this.stageValue.indicatorColor, this.value.indicatorColor);
    return !checkedBackgroundColorEQ ||
      !uncheckedBorderColorEQ ||
      !indicatorColorEQ;
  }
}
RadioStyleModifier.identity = Symbol('radioStyle');
class RadioWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioWidth(node);
    }
    else {
      getUINativeModule().radio.setRadioWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
RadioWidthModifier.identity = Symbol('radioWidth');
class RadioHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioHeight(node);
    }
    else {
      getUINativeModule().radio.setRadioHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
RadioHeightModifier.identity = Symbol('radioHeight');
class RadioSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioSize(node);
    }
    else {
      getUINativeModule().radio.setRadioSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
RadioSizeModifier.identity = Symbol('radioSize');
class RadioHoverEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioHoverEffect(node);
    }
    else {
      getUINativeModule().radio.setRadioHoverEffect(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
RadioHoverEffectModifier.identity = Symbol('radioHoverEffect');
class RadioPaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().radio.resetRadioPadding(node);
    }
    else {
      let paddingTop;
      let paddingRight;
      let paddingBottom;
      let paddingLeft;
      if (this.value !== null && this.value !== undefined) {
        if (isLengthType(this.value) || isResource(this.value)) {
          paddingTop = this.value;
          paddingRight = this.value;
          paddingBottom = this.value;
          paddingLeft = this.value;
        }
        else {
          paddingTop = this.value.top;
          paddingRight = this.value.right;
          paddingBottom = this.value.bottom;
          paddingLeft = this.value.left;
        }
      }
      getUINativeModule().radio.setRadioPadding(node, paddingTop, paddingRight, paddingBottom, paddingLeft);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    } else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.left === this.value.left &&
        this.stageValue.right === this.value.right &&
        this.stageValue.top === this.value.top &&
        this.stageValue.bottom === this.value.bottom);
    } else {
      return true;
    }
  }
}
RadioPaddingModifier.identity = Symbol('radioPadding');
class RadioResponseRegionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().radio.resetRadioResponseRegion(node);
    }
    else {
      let responseRegion = [];
      if (Array.isArray(this.value)) {
        for (let i = 0; i < this.value.length; i++) {
          responseRegion.push((_a = this.value[i].x) !== null && _a !== void 0 ? _a : 'PLACEHOLDER');
          responseRegion.push((_b = this.value[i].y) !== null && _b !== void 0 ? _b : 'PLACEHOLDER');
          responseRegion.push((_c = this.value[i].width) !== null && _c !== void 0 ? _c : 'PLACEHOLDER');
          responseRegion.push((_d = this.value[i].height) !== null && _d !== void 0 ? _d : 'PLACEHOLDER');
        }
      }
      else {
        responseRegion.push((_e = this.value.x) !== null && _e !== void 0 ? _e : 'PLACEHOLDER');
        responseRegion.push((_f = this.value.y) !== null && _f !== void 0 ? _f : 'PLACEHOLDER');
        responseRegion.push((_g = this.value.width) !== null && _g !== void 0 ? _g : 'PLACEHOLDER');
        responseRegion.push((_h = this.value.height) !== null && _h !== void 0 ? _h : 'PLACEHOLDER');
      }
      getUINativeModule().radio.setRadioResponseRegion(node, responseRegion, responseRegion.length);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.value) && Array.isArray(this.stageValue)) {
      if (this.value.length !== this.stageValue.length) {
        return true;
      }
      else {
        for (let i = 0; i < this.value.length; i++) {
          if (!(isBaseOrResourceEqual(this.stageValue[i].x, this.value[i].x) &&
            isBaseOrResourceEqual(this.stageValue[i].y, this.value[i].y) &&
            isBaseOrResourceEqual(this.stageValue[i].width, this.value[i].width) &&
            isBaseOrResourceEqual(this.stageValue[i].height, this.value[i].height))) {
            return true;
          }
        }
        return false;
      }
    }
    else if (!Array.isArray(this.value) && !Array.isArray(this.stageValue)) {
      return (!(isBaseOrResourceEqual(this.stageValue.x, this.value.x) &&
        isBaseOrResourceEqual(this.stageValue.y, this.value.y) &&
        isBaseOrResourceEqual(this.stageValue.width, this.value.width) &&
        isBaseOrResourceEqual(this.stageValue.height, this.value.height)));
    }
    else {
      return true;
    }
  }
}
RadioResponseRegionModifier.identity = Symbol('radioResponseRegion');
// @ts-ignore
if (globalThis.Radio !== undefined) {
  globalThis.Radio.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRadioComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RadioModifier(nativePtr, classType);
    });
  };
}

// @ts-ignore
globalThis.Radio.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkRadioComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };

/// <reference path='./import.ts' />
class ArkTimePickerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  loop(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerLoopModifier.identity, TimepickerLoopModifier, value);
    return this;
  }
  useMilitaryTime(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerUseMilitaryTimeModifier.identity, TimepickerUseMilitaryTimeModifier, value);
    return this;
  }
  disappearTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerDisappearTextStyleModifier.identity, TimepickerDisappearTextStyleModifier, value);
    return this;
  }
  textStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerTextStyleModifier.identity, TimepickerTextStyleModifier, value);
    return this;
  }
  selectedTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerSelectedTextStyleModifier.identity, TimepickerSelectedTextStyleModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  dateTimeOptions(value) {
    modifierWithKey(this._modifiersWithKeys, TimepickerDateTimeOptionsModifier.identity, TimepickerDateTimeOptionsModifier, value);
    return this;
  }
}
class TimepickerTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().timepicker.resetTextStyle(node);
    }
    else {
      getUINativeModule().timepicker.setTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined,
      (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null ||
        _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null ||
        _t === void 0 ? void 0 : _t.family);
    }
  }
}
TimepickerTextStyleModifier.identity = Symbol('textStyle');
class TimepickerSelectedTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().timepicker.resetSelectedTextStyle(node);
    }
    else {
      getUINativeModule().timepicker.setSelectedTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined,
      (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null || _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null || _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null || _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null || _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null || _t === void 0 ? void 0 : _t.family);
    }
  }
}
TimepickerSelectedTextStyleModifier.identity = Symbol('selectedTextStyle');
class TimepickerDisappearTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().timepicker.resetDisappearTextStyle(node);
    }
    else {
      getUINativeModule().timepicker.setDisappearTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined, 
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined, 
      (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined, 
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ?
      void 0 : _b.weight) === ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ?
        void 0 : _f.style) === ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null ||
        _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color,
      (_k = this.value) === null || _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null ||
        _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null ||
        _t === void 0 ? void 0 : _t.family);
    }
  }
}
TimepickerDisappearTextStyleModifier.identity = Symbol('disappearTextStyle');
class TimepickerUseMilitaryTimeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().timepicker.resetTimepickerUseMilitaryTime(node);
    }
    else {
      getUINativeModule().timepicker.setTimepickerUseMilitaryTime(node, this.value);
    }
  }
}
TimepickerUseMilitaryTimeModifier.identity = Symbol('timepickerUseMilitaryTime');

class TimepickerLoopModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().timepicker.resetTimepickerLoop(node);
    }
    else {
      getUINativeModule().timepicker.setTimepickerLoop(node, this.value);
    }
  }
}
TimepickerLoopModifier.identity = Symbol('timepickerLoop');

class TimepickerDateTimeOptionsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().timepicker.resetTimepickerDateTimeOptions(node);
    }
    else {
      getUINativeModule().timepicker.setTimepickerDateTimeOptions(node, this.value.hour, this.value.minute, this.value.second);
    }
  }
}
TimepickerDateTimeOptionsModifier.identity = Symbol('timepickerDateTimeOptions');

// @ts-ignore
if (globalThis.TimePicker !== undefined) {
  globalThis.TimePicker.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTimePickerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TimePickerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkTextPickerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  defaultPickerItemHeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerDefaultPickerItemHeightModifier.identity, TextpickerDefaultPickerItemHeightModifier, value);
    return this;
  }
  canLoop(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerCanLoopModifier.identity, TextpickerCanLoopModifier, value);
    return this;
  }
  disappearTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerDisappearTextStyleModifier.identity, TextpickerDisappearTextStyleModifier, value);
    return this;
  }
  textStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerTextStyleModifier.identity, TextpickerTextStyleModifier, value);
    return this;
  }
  selectedTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerSelectedTextStyleModifier.identity, TextpickerSelectedTextStyleModifier, value);
    return this;
  }
  onAccept(callback) {
    throw new Error('Method not implemented.');
  }
  onCancel(callback) {
    throw new Error('Method not implemented.');
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  selectedIndex(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerSelectedIndexModifier.identity, TextpickerSelectedIndexModifier, value);
    return this;
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerDividerModifier.identity, TextpickerDividerModifier, value);
    return this;
  }
  gradientHeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextpickerGradientHeightModifier.identity, TextpickerGradientHeightModifier, value);
    return this;
  }
}
class TextpickerCanLoopModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textpicker.resetCanLoop(node);
    }
    else {
      getUINativeModule().textpicker.setCanLoop(node, this.value);
    }
  }
}
TextpickerCanLoopModifier.identity = Symbol('textpickerCanLoop');
class TextpickerSelectedIndexModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textpicker.resetSelectedIndex(node);
    }
    else {
      getUINativeModule().textpicker.setSelectedIndex(node, this.value);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.stageValue) && Array.isArray(this.value)) {
      return !deepCompareArrays(this.stageValue, this.value);
    }
    else if (Array.isArray(this.stageValue) || Array.isArray(this.value)) {
      return true;
    }
    else {
      return this.stageValue !== this.value;
    }
  }
}
TextpickerSelectedIndexModifier.identity = Symbol('textpickerSelectedIndex');
class TextpickerDividerModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        var _a, _b, _c, _d;
        if (reset) {
            getUINativeModule().textpicker.resetDivider(node);
        }
        else {
            getUINativeModule().textpicker.setDivider(node, (_a = this.value) === null || _a === void 0 ? void 0 : _a.strokeWidth, (_b = this.value) === null || _b === void 0 ? void 0 : _b.color, (_c = this.value) === null || _c === void 0 ? void 0 : _c.startMargin, (_d = this.value) === null || _d === void 0 ? void 0 : _d.endMargin);
        }
    }
    checkObjectDiff() {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        return !(((_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.strokeWidth) === ((_b = this.value) === null || _b === void 0 ? void 0 : _b.strokeWidth) &&
            ((_c = this.stageValue) === null || _c === void 0 ? void 0 : _c.color) === ((_d = this.value) === null || _d === void 0 ? void 0 : _d.color) &&
            ((_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.startMargin) === ((_f = this.value) === null || _f === void 0 ? void 0 : _f.startMargin) &&
            ((_g = this.stageValue) === null || _g === void 0 ? void 0 : _g.endMargin) === ((_h = this.value) === null || _h === void 0 ? void 0 : _h.endMargin));
    }
}
TextpickerDividerModifier.identity = Symbol('textpickerDivider');

class TextpickerGradientHeightModifier extends ModifierWithKey {
  constructor(value) {
      super(value);
  }
  applyPeer(node, reset) {
      if (reset) {
          getUINativeModule().textpicker.resetGradientHeight(node);
      }
      else {
          getUINativeModule().textpicker.setGradientHeight(node, this.value);
      }
  }
  checkObjectDiff() {
      return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextpickerGradientHeightModifier.identity = Symbol('textpickerGradientHeight');
class TextpickerTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().textpicker.resetTextStyle(node);
    }
    else {
      getUINativeModule().textpicker.setTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined, (_e =
      (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined, (_h =
      (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined, 
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null ||
        _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null ||
        _t === void 0 ? void 0 : _t.family);
    }
  }
}
TextpickerTextStyleModifier.identity = Symbol('textpickerTextStyle');
class TextpickerSelectedTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().textpicker.resetSelectedTextStyle(node);
    }
    else {
      getUINativeModule().textpicker.setSelectedTextStyle(node, (_b =
        (_a = this.value) === null || _a === void 0 ? void 0 : _a.color) !== null &&
        _b !== void 0 ? _b : undefined, (_e = (_d = (_c = this.value) === null ||
        _c === void 0 ? void 0 : _c.font) === null ||
        _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined,
        (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
        _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
        (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
        _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
        (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
        _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null ||
        _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null ||
        _t === void 0 ? void 0 : _t.family);
    }
  }
}
TextpickerSelectedTextStyleModifier.identity = Symbol('textpickerSelectedTextStyle');
class TextpickerDisappearTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().textpicker.resetDisappearTextStyle(node);
    }
    else {
      getUINativeModule().textpicker.setDisappearTextStyle(node, (_b =
        (_a = this.value) === null || _a === void 0 ? void 0 : _a.color) !== null &&
        _b !== void 0 ? _b : undefined, (_e = (_d = (_c = this.value) === null ||
        _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.size) !== null &&
        _e !== void 0 ? _e : undefined, (_h = (_g = (_f = this.value) === null ||
        _f === void 0 ? void 0 : _f.font) === null || _g === void 0 ? void 0 : _g.weight) !== null &&
        _h !== void 0 ? _h : undefined, (_l = (_k = (_j = this.value) === null ||
        _j === void 0 ? void 0 : _j.font) === null || _k === void 0 ? void 0 : _k.family) !== null &&
        _l !== void 0 ? _l : undefined, (_p = (_o = (_m = this.value) === null ||
        _m === void 0 ? void 0 : _m.font) === null || _o === void 0 ? void 0 : _o.style) !== null &&
        _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) === ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) === ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null || _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null || _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null || _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null || _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null || _t === void 0 ? void 0 : _t.family);
    }
  }
}
TextpickerDisappearTextStyleModifier.identity = Symbol('textpickerDisappearTextStyle');
class TextpickerDefaultPickerItemHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textpicker.resetDefaultPickerItemHeight(node);
    }
    else {
      getUINativeModule().textpicker.setDefaultPickerItemHeight(node, this.value);
    }
  }
}
TextpickerDefaultPickerItemHeightModifier.identity = Symbol('textpickerDefaultPickerItemHeight');
// @ts-ignore
if (globalThis.TextPicker !== undefined) {
  globalThis.TextPicker.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextPickerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextPickerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkSliderComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  blockColor(value) {
    modifierWithKey(this._modifiersWithKeys, BlockColorModifier.identity, BlockColorModifier, value);
    return this;
  }
  trackColor(value) {
    modifierWithKey(this._modifiersWithKeys, TrackColorModifier.identity, TrackColorModifier, value);
    return this;
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectColorModifier.identity, SelectColorModifier, value);
    return this;
  }
  minLabel(value) {
    throw new Error('Method not implemented.');
  }
  maxLabel(value) {
    throw new Error('Method not implemented.');
  }
  showSteps(value) {
    modifierWithKey(this._modifiersWithKeys, ShowStepsModifier.identity, ShowStepsModifier, value);
    return this;
  }
  showTips(value, content) {
    let showTips = new ArkSliderTips(value, content);
    modifierWithKey(this._modifiersWithKeys, ShowTipsModifier.identity, ShowTipsModifier, showTips);
    return this;
  }
  trackThickness(value) {
    modifierWithKey(this._modifiersWithKeys, TrackThicknessModifier.identity, TrackThicknessModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  blockBorderColor(value) {
    modifierWithKey(this._modifiersWithKeys, BlockBorderColorModifier.identity, BlockBorderColorModifier, value);
    return this;
  }
  blockBorderWidth(value) {
    modifierWithKey(this._modifiersWithKeys, BlockBorderWidthModifier.identity, BlockBorderWidthModifier, value);
    return this;
  }
  stepColor(value) {
    modifierWithKey(this._modifiersWithKeys, StepColorModifier.identity, StepColorModifier, value);
    return this;
  }
  trackBorderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, TrackBorderRadiusModifier.identity, TrackBorderRadiusModifier, value);
    return this;
  }
  blockSize(value) {
    modifierWithKey(this._modifiersWithKeys, BlockSizeModifier.identity, BlockSizeModifier, value);
    return this;
  }
  blockStyle(value) {
    modifierWithKey(this._modifiersWithKeys, BlockStyleModifier.identity, BlockStyleModifier, value);
    return this;
  }
  stepSize(value) {
    modifierWithKey(this._modifiersWithKeys, StepSizeModifier.identity, StepSizeModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().slider.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().slider.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, sliderConfiguration) {
    sliderConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.sliderNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.sliderNode = new xNode.BuilderNode(context);
      this.sliderNode.build(this.builder, sliderConfiguration);
      this.needRebuild = false;
    } else {
      this.sliderNode.update(sliderConfiguration);
    }
    return this.sliderNode.getFrameNode();
  }
}
class BlockStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetBlockStyle(node);
    }
    else {
      getUINativeModule().slider.setBlockStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.type === this.value.type &&
      this.stageValue.image === this.value.image &&
      this.stageValue.shape === this.value.shape);
  }
}
BlockStyleModifier.identity = Symbol('sliderBlockStyle');
class ShowTipsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a;
    if (reset) {
      getUINativeModule().slider.resetShowTips(node);
    }
    else {
      getUINativeModule().slider.setShowTips(node, this.value.showTip, (_a = this.value) === null || _a === void 0 ? void 0 : _a.tipText);
    }
  }
  checkObjectDiff() {
    let showTipDiff = this.stageValue.showTip !== this.value.showTip;
    let tipTextDiff = !isBaseOrResourceEqual(this.stageValue.tipText, this.value.tipText);
    return showTipDiff || tipTextDiff;
  }
}
ShowTipsModifier.identity = Symbol('sliderShowTips');
class StepSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetStepSize(node);
    }
    else {
      getUINativeModule().slider.setStepSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StepSizeModifier.identity = Symbol('sliderStepSize');
class BlockSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetBlockSize(node);
    }
    else {
      getUINativeModule().slider.setBlockSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue.height) && isResource(this.value.height) && isResource(this.stageValue.width) && isResource(this.value.width)) {
      return !(isResourceEqual(this.stageValue.height, this.value.height) && isResourceEqual(this.stageValue.width, this.value.width));
    }
    else {
      return true;
    }
  }
}
BlockSizeModifier.identity = Symbol('sliderBlockSize');
class TrackBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetTrackBorderRadius(node);
    }
    else {
      getUINativeModule().slider.setTrackBorderRadius(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TrackBorderRadiusModifier.identity = Symbol('sliderTrackBorderRadius');
class StepColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetStepColor(node);
    }
    else {
      getUINativeModule().slider.setStepColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StepColorModifier.identity = Symbol('sliderStepColor');
class BlockBorderColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetBlockBorderColor(node);
    }
    else {
      getUINativeModule().slider.setBlockBorderColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlockBorderColorModifier.identity = Symbol('sliderBlockBorderColor');
class BlockBorderWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetBlockBorderWidth(node);
    }
    else {
      getUINativeModule().slider.setBlockBorderWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlockBorderWidthModifier.identity = Symbol('sliderBlockBorderWidth');
class BlockColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetBlockColor(node);
    }
    else {
      getUINativeModule().slider.setBlockColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BlockColorModifier.identity = Symbol('sliderBlockColor');
class TrackColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetTrackBackgroundColor(node);
    }
    else {
      getUINativeModule().slider.setTrackBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TrackColorModifier.identity = Symbol('sliderTrackColor');
class SelectColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetSelectColor(node);
    }
    else {
      getUINativeModule().slider.setSelectColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectColorModifier.identity = Symbol('sliderSelectColor');
class ShowStepsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetShowSteps(node);
    }
    else {
      getUINativeModule().slider.setShowSteps(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ShowStepsModifier.identity = Symbol('sliderShowSteps');
class TrackThicknessModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().slider.resetThickness(node);
    }
    else {
      getUINativeModule().slider.setThickness(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TrackThicknessModifier.identity = Symbol('sliderTrackThickness');
// @ts-ignore
if (globalThis.Slider !== undefined) {
  globalThis.Slider.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSliderComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SliderModifier(nativePtr, classType);
    });
  };
  globalThis.Slider.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkSliderComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class RatingStarsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rating.resetStars(node);
    }
    else {
      getUINativeModule().rating.setStars(node, this.value);
    }
  }
}
RatingStarsModifier.identity = Symbol('ratingStars');
class RatingStepSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rating.resetStepSize(node);
    }
    else {
      getUINativeModule().rating.setStepSize(node, this.value);
    }
  }
}
RatingStepSizeModifier.identity = Symbol('ratingStepSize');
class RatingStarStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c;
    if (reset) {
      getUINativeModule().rating.resetStarStyle(node);
    }
    else {
      getUINativeModule().rating.setStarStyle(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.backgroundUri, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.foregroundUri, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.secondaryUri);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f;
    return ((_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.backgroundUri) !==
      ((_b = this.value) === null || _b === void 0 ? void 0 : _b.backgroundUri) ||
      ((_c = this.stageValue) === null || _c === void 0 ? void 0 : _c.foregroundUri) !==
      ((_d = this.value) === null || _d === void 0 ? void 0 : _d.foregroundUri) ||
      ((_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.secondaryUri) !==
      ((_f = this.value) === null || _f === void 0 ? void 0 : _f.secondaryUri);
  }
}
RatingStarStyleModifier.identity = Symbol('ratingStarStyle');
class ArkRatingComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  stars(value) {
    modifierWithKey(this._modifiersWithKeys, RatingStarsModifier.identity, RatingStarsModifier, value);
    return this;
  }
  stepSize(value) {
    modifierWithKey(this._modifiersWithKeys, RatingStepSizeModifier.identity, RatingStepSizeModifier, value);
    return this;
  }
  starStyle(value) {
    let starStyle = new ArkStarStyle();
    if (!isUndefined(value)) {
      starStyle.backgroundUri = value.backgroundUri;
      starStyle.foregroundUri = value.foregroundUri;
      starStyle.secondaryUri = value.secondaryUri;
      modifierWithKey(this._modifiersWithKeys, RatingStarStyleModifier.identity, RatingStarStyleModifier, value);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, RatingStarStyleModifier.identity, RatingStarStyleModifier, undefined);
    }
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().rating.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().rating.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, ratingConfiguration) {
    ratingConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.ratingNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.ratingNode = new xNode.BuilderNode(context);
      this.ratingNode.build(this.builder, ratingConfiguration);
      this.needRebuild = false;
    } else {
      this.ratingNode.update(ratingConfiguration);
    }
    return this.ratingNode.getFrameNode();
  }
}
// @ts-ignore
if (globalThis.Rating !== undefined) {
  globalThis.Rating.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRatingComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RatingModifier(nativePtr, classType);
    });
  };
  globalThis.Rating.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkRatingComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkCheckboxComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  shape(value) {
    throw new Error('Method not implemented.');
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxWidthModifier.identity, CheckboxWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxHeightModifier.identity, CheckboxHeightModifier, value);
    return this;
  }
  select(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxSelectModifier.identity, CheckboxSelectModifier, value);
    return this;
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxSelectedColorModifier.identity, CheckboxSelectedColorModifier, value);
    return this;
  }
  unselectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxUnselectedColorModifier.identity, CheckboxUnselectedColorModifier, value);
    return this;
  }
  mark(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxMarkModifier.identity, CheckboxMarkModifier, value);
    return this;
  }
  padding(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, CheckBoxPaddingModifier.identity, CheckBoxPaddingModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, CheckBoxPaddingModifier.identity, CheckBoxPaddingModifier, undefined);
    }
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, CheckBoxSizeModifier.identity, CheckBoxSizeModifier, value);
    return this;
  }
  responseRegion(value) {
    modifierWithKey(this._modifiersWithKeys, CheckBoxResponseRegionModifier.identity, CheckBoxResponseRegionModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().checkbox.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().checkbox.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, checkBoxConfiguration) {
    checkBoxConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.checkboxNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.checkboxNode = new xNode.BuilderNode(context);
      this.checkboxNode.build(this.builder, checkBoxConfiguration);
      this.needRebuild = false;
    } else {
      this.checkboxNode.update(checkBoxConfiguration);
    }
    return this.checkboxNode.getFrameNode();
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
}
class CheckBoxResponseRegionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().checkbox.resetCheckboxResponseRegion(node);
    }
    else {
      let responseRegion = [];
      if (Array.isArray(this.value)) {
        for (let i = 0; i < this.value.length; i++) {
          responseRegion.push((_a = this.value[i].x) !== null && _a !== void 0 ? _a : 'PLACEHOLDER');
          responseRegion.push((_b = this.value[i].y) !== null && _b !== void 0 ? _b : 'PLACEHOLDER');
          responseRegion.push((_c = this.value[i].width) !== null && _c !== void 0 ? _c : 'PLACEHOLDER');
          responseRegion.push((_d = this.value[i].height) !== null && _d !== void 0 ? _d : 'PLACEHOLDER');
        }
      }
      else {
        responseRegion.push((_e = this.value.x) !== null && _e !== void 0 ? _e : 'PLACEHOLDER');
        responseRegion.push((_f = this.value.y) !== null && _f !== void 0 ? _f : 'PLACEHOLDER');
        responseRegion.push((_g = this.value.width) !== null && _g !== void 0 ? _g : 'PLACEHOLDER');
        responseRegion.push((_h = this.value.height) !== null && _h !== void 0 ? _h : 'PLACEHOLDER');
      }
      getUINativeModule().checkbox.setCheckboxResponseRegion(node, responseRegion, responseRegion.length);
    }
  }
  checkObjectDiff() {
    if (Array.isArray(this.value) && Array.isArray(this.stageValue)) {
      if (this.value.length !== this.stageValue.length) {
        return true;
      }
      else {
        for (let i = 0; i < this.value.length; i++) {
          if (!(isBaseOrResourceEqual(this.stageValue[i].x, this.value[i].x) &&
            isBaseOrResourceEqual(this.stageValue[i].y, this.value[i].y) &&
            isBaseOrResourceEqual(this.stageValue[i].width, this.value[i].width) &&
            isBaseOrResourceEqual(this.stageValue[i].height, this.value[i].height))) {
            return true;
          }
        }
        return false;
      }
    }
    else if (!Array.isArray(this.value) && !Array.isArray(this.stageValue)) {
      return (!(isBaseOrResourceEqual(this.stageValue.x, this.value.x) &&
        isBaseOrResourceEqual(this.stageValue.y, this.value.y) &&
        isBaseOrResourceEqual(this.stageValue.width, this.value.width) &&
        isBaseOrResourceEqual(this.stageValue.height, this.value.height)));
    }
    else {
      return true;
    }
  }
}
CheckBoxResponseRegionModifier.identity = Symbol('responseRegion');
class CheckBoxSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetCheckboxSize(node);
    }
    else {
      getUINativeModule().checkbox.setCheckboxSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
CheckBoxSizeModifier.identity = Symbol('size');
class CheckBoxPaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetCheckboxPadding(node);
    }
    else {
      getUINativeModule().checkbox.setCheckboxPadding(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
CheckBoxPaddingModifier.identity = Symbol('padding');
class CheckboxMarkModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c;
    if (reset) {
      getUINativeModule().checkbox.resetMark(node);
    }
    else {
      getUINativeModule().checkbox.setMark(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.strokeColor, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.size, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.strokeWidth);
    }
  }
  checkObjectDiff() {
    let colorEQ = isBaseOrResourceEqual(this.stageValue.strokeColor, this.value.strokeColor);
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let widthEQ = isBaseOrResourceEqual(this.stageValue.strokeWidth, this.value.strokeWidth);
    return !colorEQ || !sizeEQ || !widthEQ;
  }
}
CheckboxMarkModifier.identity = Symbol('checkboxMark');
class CheckboxSelectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetSelect(node);
    }
    else {
      getUINativeModule().checkbox.setSelect(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
CheckboxSelectModifier.identity = Symbol('checkboxSelect');
class CheckboxHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetHeight(node);
    }
    else {
      getUINativeModule().checkbox.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxHeightModifier.identity = Symbol('checkboxHeight');
class CheckboxWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetWidth(node);
    }
    else {
      getUINativeModule().checkbox.setWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxWidthModifier.identity = Symbol('checkboxWidth');
class CheckboxSelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetSelectedColor(node);
    }
    else {
      getUINativeModule().checkbox.setSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxSelectedColorModifier.identity = Symbol('checkboxSelectedColor');
class CheckboxUnselectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkbox.resetUnSelectedColor(node);
    }
    else {
      getUINativeModule().checkbox.setUnSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxUnselectedColorModifier.identity = Symbol('checkboxUnselectedColor');
// @ts-ignore
if (globalThis.Checkbox !== undefined) {
  globalThis.Checkbox.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCheckboxComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CheckboxModifier(nativePtr, classType);
    });
  };
  globalThis.Checkbox.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkCheckboxComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkNavDestinationComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  title(value) {
    throw new Error('Method not implemented.');
  }
  hideTitleBar(value) {
    modifierWithKey(this._modifiersWithKeys, HideTitleBarModifier.identity, HideTitleBarModifier, value);
    return this;
  }
  onShown(callback) {
    throw new Error('Method not implemented.');
  }
  onHidden(callback) {
    throw new Error('Method not implemented.');
  }
  onBackPressed(callback) {
    throw new Error('Method not implemented.');
  }
}
class HideTitleBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navDestination.resetHideTitleBar(node);
    }
    else {
      getUINativeModule().navDestination.setHideTitleBar(node, this.value);
    }
  }
}
HideTitleBarModifier.identity = Symbol('hideTitleBar');
//@ts-ignore
if (globalThis.NavDestination !== undefined) {
  globalThis.NavDestination.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkNavDestinationComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.NavDestinationModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkCounterComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onInc(event) {
    throw new Error('Method not implemented.');
  }
  onDec(event) {
    throw new Error('Method not implemented.');
  }
  enableDec(value) {
    modifierWithKey(this._modifiersWithKeys, EnableDecModifier.identity, EnableDecModifier, value);
    return this;
  }
  enableInc(value) {
    modifierWithKey(this._modifiersWithKeys, EnableIncModifier.identity, EnableIncModifier, value);
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, CounterBackgroundColorModifier.identity, CounterBackgroundColorModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, CounterWidthModifier.identity, CounterWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, CounterHeightModifier.identity, CounterHeightModifier, value);
    return this;
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, CounterSizeModifier.identity, CounterSizeModifier, value);
    return this;
  }
}
class CounterHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetCounterHeight(node);
    }
    else {
      getUINativeModule().counter.setCounterHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CounterHeightModifier.identity = Symbol('CounterHeight');
class CounterWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetCounterWidth(node);
    }
    else {
      getUINativeModule().counter.setCounterWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CounterWidthModifier.identity = Symbol('CounterWidth');
class CounterBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetCounterBackgroundColor(node);
    }
    else {
      getUINativeModule().counter.setCounterBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CounterBackgroundColorModifier.identity = Symbol('CounterBackgroundColor');
class CounterSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetCounterSize(node);
    }
    else {
      getUINativeModule().counter.setCounterSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
CounterSizeModifier.identity = Symbol('CounterSize');
class EnableIncModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetEnableInc(node);
    }
    else {
      getUINativeModule().counter.setEnableInc(node, this.value);
    }
  }
}
EnableIncModifier.identity = Symbol('enableInc');
class EnableDecModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().counter.resetEnableDec(node);
    }
    else {
      getUINativeModule().counter.setEnableDec(node, this.value);
    }
  }
}
EnableDecModifier.identity = Symbol('enableDec');
// @ts-ignore
if (globalThis.Counter !== undefined) {
  globalThis.Counter.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCounterComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CounterModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class CheckboxGroupSelectAllModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupSelectAll(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupSelectAll(node, this.value);
    }
  }
}
CheckboxGroupSelectAllModifier.identity = Symbol('checkboxgroupSelectAll');
class CheckboxGroupSelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupSelectedColor(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxGroupSelectedColorModifier.identity = Symbol('checkboxgroupSelectedColor');
class CheckboxGroupUnselectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupUnSelectedColor(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupUnSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxGroupUnselectedColorModifier.identity = Symbol('checkboxgroupUnselectedColor');
class CheckboxGroupMarkModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c;
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupMark(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupMark(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.strokeColor, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.size, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.strokeWidth);
    }
  }
  checkObjectDiff() {
    let colorEQ = isBaseOrResourceEqual(this.stageValue.strokeColor, this.value.strokeColor);
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let widthEQ = isBaseOrResourceEqual(this.stageValue.strokeWidth, this.value.strokeWidth);
    return !colorEQ || !sizeEQ || !widthEQ;
  }
}
CheckboxGroupMarkModifier.identity = Symbol('checkboxgroupMark');
class CheckboxGroupWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupWidth(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxGroupWidthModifier.identity = Symbol('checkboxGroupWidth');
class CheckboxGroupSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupSize(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
CheckboxGroupSizeModifier.identity = Symbol('checkboxGroupSize');
class CheckboxGroupHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupHeight(node);
    }
    else {
      getUINativeModule().checkboxgroup.setCheckboxGroupHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxGroupHeightModifier.identity = Symbol('checkboxGroupHeight');
class CheckboxGroupStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().checkboxgroup.resetCheckboxGroupStyle(node);
    } else {
      getUINativeModule().checkboxgroup.setCheckboxGroupStyle(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CheckboxGroupStyleModifier.identity = Symbol('checkboxgroupStyle');
class ArkCheckboxGroupComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  selectAll(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupSelectAllModifier.identity, CheckboxGroupSelectAllModifier, value);
    return this;
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupSelectedColorModifier.identity, CheckboxGroupSelectedColorModifier, value);
    return this;
  }
  unselectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupUnselectedColorModifier.identity, CheckboxGroupUnselectedColorModifier, value);
    return this;
  }
  mark(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupMarkModifier.identity, CheckboxGroupMarkModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupSizeModifier.identity, CheckboxGroupSizeModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupWidthModifier.identity, CheckboxGroupWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupHeightModifier.identity, CheckboxGroupHeightModifier, value);
    return this;
  }
  checkboxShape(value) {
    modifierWithKey(this._modifiersWithKeys, CheckboxGroupStyleModifier.identity, CheckboxGroupStyleModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.CheckboxGroup !== undefined) {
  globalThis.CheckboxGroup.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCheckboxGroupComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CheckboxGroupModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkPanelComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  mode(value) {
    modifierWithKey(this._modifiersWithKeys, PanelModeModifier.identity, PanelModeModifier, value);
    return this;
  }
  type(value) {
    modifierWithKey(this._modifiersWithKeys, PanelTypeModifier.identity, PanelTypeModifier, value);
    return this;
  }
  dragBar(value) {
    modifierWithKey(this._modifiersWithKeys, DragBarModifier.identity, DragBarModifier, value);
    return this;
  }
  customHeight(value) {
    modifierWithKey(this._modifiersWithKeys, PanelCustomHeightModifier.identity, PanelCustomHeightModifier, value);
    return this;
  }
  fullHeight(value) {
    modifierWithKey(this._modifiersWithKeys, PanelFullHeightModifier.identity, PanelFullHeightModifier, value);
    return this;
  }
  halfHeight(value) {
    modifierWithKey(this._modifiersWithKeys, PanelHalfHeightModifier.identity, PanelHalfHeightModifier, value);
    return this;
  }
  miniHeight(value) {
    modifierWithKey(this._modifiersWithKeys, PanelMiniHeightModifier.identity, PanelMiniHeightModifier, value);
    return this;
  }
  show(value) {
    modifierWithKey(this._modifiersWithKeys, ShowModifier.identity, ShowModifier, value);
    return this;
  }
  backgroundMask(color) {
    modifierWithKey(this._modifiersWithKeys, PanelBackgroundMaskModifier.identity, PanelBackgroundMaskModifier, color);
    return this;
  }
  showCloseIcon(value) {
    modifierWithKey(this._modifiersWithKeys, ShowCloseIconModifier.identity, ShowCloseIconModifier, value);
    return this;
  }
  onChange(event) {
    throw new Error('Method not implemented.');
  }
  onHeightChange(callback) {
    throw new Error('Method not implemented.');
  }
}
class PanelBackgroundMaskModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelBackgroundMask(node);
    }
    else {
      getUINativeModule().panel.setPanelBackgroundMask(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelBackgroundMaskModifier.identity = Symbol('panelBackgroundMask');
class PanelModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelMode(node);
    }
    else {
      getUINativeModule().panel.setPanelMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelModeModifier.identity = Symbol('panelMode');
class PanelTypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelType(node);
    }
    else {
      getUINativeModule().panel.setPanelType(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelTypeModifier.identity = Symbol('panelType');
class PanelCustomHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelCustomHeight(node);
    }
    else {
      getUINativeModule().panel.setPanelCustomHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelCustomHeightModifier.identity = Symbol('panelCustomHeight');
class PanelFullHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelFullHeight(node);
    }
    else {
      getUINativeModule().panel.setPanelFullHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelFullHeightModifier.identity = Symbol('panelFullHeight');
class PanelHalfHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelHalfHeight(node);
    }
    else {
      getUINativeModule().panel.setPanelHalfHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelHalfHeightModifier.identity = Symbol('panelHalfHeight');
class PanelMiniHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetPanelMiniHeight(node);
    }
    else {
      getUINativeModule().panel.setPanelMiniHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PanelMiniHeightModifier.identity = Symbol('panelMiniHeight');
class ShowCloseIconModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetShowCloseIcon(node);
    }
    else {
      getUINativeModule().panel.setShowCloseIcon(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ShowCloseIconModifier.identity = Symbol('showCloseIcon');
class DragBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetDragBar(node);
    }
    else {
      getUINativeModule().panel.setDragBar(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DragBarModifier.identity = Symbol('dragBar');
class ShowModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().panel.resetShow(node);
    }
    else {
      getUINativeModule().panel.setShow(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ShowModifier.identity = Symbol('show');
// @ts-ignore
if (globalThis.Panel !== undefined) {
  globalThis.Panel.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPanelComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PanelModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
const TITLE_MODE_RANGE = 2;
const NAV_BAR_POSITION_RANGE = 1;
const NAVIGATION_MODE_RANGE = 2;
const DEFAULT_NAV_BAR_WIDTH = 240;
const MIN_NAV_BAR_WIDTH_DEFAULT = '240vp';
const MAX_NAV_BAR_WIDTH_DEFAULT = '40%';
const NAVIGATION_TITLE_MODE_DEFAULT = 0;
const DEFAULT_UNIT = 'vp';
class ArkNavigationComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  navBarWidth(value) {
    modifierWithKey(this._modifiersWithKeys, NavBarWidthModifier.identity, NavBarWidthModifier, value);
    return this;
  }
  navBarPosition(value) {
    modifierWithKey(this._modifiersWithKeys, NavBarPositionModifier.identity, NavBarPositionModifier, value);
    return this;
  }
  navBarWidthRange(value) {
    modifierWithKey(this._modifiersWithKeys, NavBarWidthRangeModifier.identity, NavBarWidthRangeModifier, value);
    return this;
  }
  minContentWidth(value) {
    modifierWithKey(this._modifiersWithKeys, MinContentWidthModifier.identity, MinContentWidthModifier, value);
    return this;
  }
  mode(value) {
    modifierWithKey(this._modifiersWithKeys, ModeModifier.identity, ModeModifier, value);
    return this;
  }
  backButtonIcon(value) {
    modifierWithKey(this._modifiersWithKeys, BackButtonIconModifier.identity, BackButtonIconModifier, value);
    return this;
  }
  hideNavBar(value) {
    modifierWithKey(this._modifiersWithKeys, HideNavBarModifier.identity, HideNavBarModifier, value);
    return this;
  }
  title(value) {
    throw new Error('Method not implemented.');
  }
  subTitle(value) {
    modifierWithKey(this._modifiersWithKeys, SubTitleModifier.identity, SubTitleModifier, value);
    return this;
  }
  hideTitleBar(value) {
    modifierWithKey(this._modifiersWithKeys, NavigationHideTitleBarModifier.identity, NavigationHideTitleBarModifier, value);
    return this;
  }
  hideBackButton(value) {
    modifierWithKey(this._modifiersWithKeys, HideBackButtonModifier.identity, HideBackButtonModifier, value);
    return this;
  }
  titleMode(value) {
    modifierWithKey(this._modifiersWithKeys, TitleModeModifier.identity, TitleModeModifier, value);
    return this;
  }
  menus(value) {
    throw new Error('Method not implemented.');
  }
  toolBar(value) {
    throw new Error('Method not implemented.');
  }
  toolbarConfiguration(value) {
    throw new Error('Method not implemented.');
  }
  hideToolBar(value) {
    modifierWithKey(this._modifiersWithKeys, HideToolBarModifier.identity, HideToolBarModifier, value);
    return this;
  }
  onTitleModeChange(callback) {
    throw new Error('Method not implemented.');
  }
  onNavBarStateChange(callback) {
    throw new Error('Method not implemented.');
  }
  onNavigationModeChange(callback) {
    throw new Error('Method not implemented.');
  }
  navDestination(builder) {
    throw new Error('Method not implemented.');
  }
}
class BackButtonIconModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetBackButtonIcon(node);
    }
    else {
      getUINativeModule().navigation.setBackButtonIcon(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BackButtonIconModifier.identity = Symbol('backButtonIcon');
class NavBarWidthRangeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetNavBarWidthRange(node);
    }
    else {
      getUINativeModule().navigation.setNavBarWidthRange(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
NavBarWidthRangeModifier.identity = Symbol('navBarWidthRange');
class MinContentWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetMinContentWidth(node);
    }
    else {
      getUINativeModule().navigation.setMinContentWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MinContentWidthModifier.identity = Symbol('minContentWidth');
class NavBarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetNavBarWidth(node);
    }
    else {
      getUINativeModule().navigation.setNavBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
NavBarWidthModifier.identity = Symbol('navBarWidth');
class NavBarPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetNavBarPosition(node);
    }
    else {
      getUINativeModule().navigation.setNavBarPosition(node, this.value);
    }
  }
}
NavBarPositionModifier.identity = Symbol('navBarPosition');
class ModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetMode(node);
    }
    else {
      getUINativeModule().navigation.setMode(node, this.value);
    }
  }
}
ModeModifier.identity = Symbol('mode');
class HideToolBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetHideToolBar(node);
    }
    else {
      getUINativeModule().navigation.setHideToolBar(node, this.value);
    }
  }
}
HideToolBarModifier.identity = Symbol('hideToolBar');
class TitleModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetTitleMode(node);
    }
    else {
      getUINativeModule().navigation.setTitleMode(node, this.value);
    }
  }
}
TitleModeModifier.identity = Symbol('titleMode');
class HideBackButtonModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetHideBackButton(node);
    }
    else {
      getUINativeModule().navigation.setHideBackButton(node, this.value);
    }
  }
}
HideBackButtonModifier.identity = Symbol('hideBackButton');
class SubTitleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetSubTitle(node);
    }
    else {
      getUINativeModule().navigation.setSubTitle(node, this.value);
    }
  }
}
SubTitleModifier.identity = Symbol('subTitle');
class NavigationHideTitleBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetHideTitleBar(node);
    }
    else {
      getUINativeModule().navigation.setHideTitleBar(node, this.value);
    }
  }
}
NavigationHideTitleBarModifier.identity = Symbol('hideTitleBar');
class HideNavBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigation.resetHideNavBar(node);
    }
    else {
      getUINativeModule().navigation.setHideNavBar(node, this.value);
    }
  }
}
HideNavBarModifier.identity = Symbol('hideNavBar');
// @ts-ignore
if (globalThis.Navigation !== undefined) {
  globalThis.Navigation.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkNavigationComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.NavigationModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkNavRouterComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onStateChange(callback) {
    throw new Error('Method not implemented.');
  }
  mode(mode) {
    modifierWithKey(this._modifiersWithKeys, NavRouterModeModifier.identity, NavRouterModeModifier, mode);
    return this;
  }
}
class NavRouterModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navRouter.resetMode(node);
    }
    else {
      getUINativeModule().navRouter.setMode(node, this.value);
    }
  }
}
NavRouterModeModifier.identity = Symbol('mode');
// @ts-ignore
if (globalThis.NavRouter !== undefined) {
  globalThis.NavRouter.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkNavRouterComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.NavRouterModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkNavigatorComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  active(value) {
    modifierWithKey(this._modifiersWithKeys, ActiveModifier.identity, ActiveModifier, value);
    return this;
  }
  type(value) {
    modifierWithKey(this._modifiersWithKeys, TypeModifier.identity, TypeModifier, value);
    return this;
  }
  target(value) {
    modifierWithKey(this._modifiersWithKeys, TargetModifier.identity, TargetModifier, value);
    return this;
  }
  params(value) {
    modifierWithKey(this._modifiersWithKeys, ParamsModifier.identity, ParamsModifier, JSON.stringify(value));
    return this;
  }
}
class ParamsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigator.resetParams(node);
    }
    else {
      getUINativeModule().navigator.setParams(node, this.value);
    }
  }
}
ParamsModifier.identity = Symbol('params');
class TypeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigator.resetType(node);
    }
    else {
      getUINativeModule().navigator.setType(node, this.value);
    }
  }
}
TypeModifier.identity = Symbol('type');
class ActiveModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigator.resetActive(node);
    }
    else {
      getUINativeModule().navigator.setActive(node, this.value);
    }
  }
}
ActiveModifier.identity = Symbol('active');
class TargetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().navigator.resetTarget(node);
    }
    else {
      getUINativeModule().navigator.setTarget(node, this.value);
    }
  }
}
TargetModifier.identity = Symbol('target');
// @ts-ignore
if (globalThis.Navigator !== undefined) {
  globalThis.Navigator.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkNavigatorComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.NavigatorModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkAlphabetIndexerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onSelected(callback) {
    throw new Error('Method not implemented.');
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, ColorModifier.identity, ColorModifier, value);
    return this;
  }
  selectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedColorModifier.identity, SelectedColorModifier, value);
    return this;
  }
  popupColor(value) {
    modifierWithKey(this._modifiersWithKeys, PopupColorModifier.identity, PopupColorModifier, value);
    return this;
  }
  selectedBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedBackgroundColorModifier.identity, SelectedBackgroundColorModifier, value);
    return this;
  }
  popupBackground(value) {
    modifierWithKey(this._modifiersWithKeys, PopupBackgroundModifier.identity, PopupBackgroundModifier, value);
    return this;
  }
  popupSelectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, PopupSelectedColorModifier.identity, PopupSelectedColorModifier, value);
    return this;
  }
  popupUnselectedColor(value) {
    modifierWithKey(this._modifiersWithKeys, PopupUnselectedColorModifier.identity, PopupUnselectedColorModifier, value);
    return this;
  }
  popupItemBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, PopupItemBackgroundColorModifier.identity, PopupItemBackgroundColorModifier, value);
    return this;
  }
  usingPopup(value) {
    modifierWithKey(this._modifiersWithKeys, UsingPopupModifier.identity, UsingPopupModifier, value);
    return this;
  }
  selectedFont(value) {
    modifierWithKey(this._modifiersWithKeys, SelectedFontModifier.identity, SelectedFontModifier, value);
    return this;
  }
  popupFont(value) {
    modifierWithKey(this._modifiersWithKeys, PopupFontModifier.identity, PopupFontModifier, value);
    return this;
  }
  popupItemFont(value) {
    modifierWithKey(this._modifiersWithKeys, PopupItemFontModifier.identity, PopupItemFontModifier, value);
    return this;
  }
  itemSize(value) {
    modifierWithKey(this._modifiersWithKeys, ItemSizeModifier.identity, ItemSizeModifier, value);
    return this;
  }
  font(value) {
    modifierWithKey(this._modifiersWithKeys, AlphabetIndexerFontModifier.identity, AlphabetIndexerFontModifier, value);
    return this;
  }
  alignStyle(value, offset) {
    let alignStyle = new ArkAlignStyle;
    alignStyle.indexerAlign = value;
    alignStyle.offset = offset;
    modifierWithKey(this._modifiersWithKeys, AlignStyleModifier.identity, AlignStyleModifier, alignStyle);
    return this;
  }
  onSelect(callback) {
    throw new Error('Method not implemented.');
  }
  onRequestPopupData(callback) {
    throw new Error('Method not implemented.');
  }
  onPopupSelect(callback) {
    throw new Error('Method not implemented.');
  }
  selected(index) {
    modifierWithKey(this._modifiersWithKeys, AlphabetIndexerSelectedModifier.identity, AlphabetIndexerSelectedModifier, index);
    return this;
  }
  popupPosition(value) {
    modifierWithKey(this._modifiersWithKeys, PopupPositionModifier.identity, PopupPositionModifier, value);
    return this;
  }
  popupItemBorderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, PopupItemBorderRadiusModifier.identity, PopupItemBorderRadiusModifier, value);
    return this;
  }
  itemBorderRadius(value) {
    modifierWithKey(this._modifiersWithKeys, ItemBorderRadiusModifier.identity, ItemBorderRadiusModifier, value);
    return this;
  }
  popupBackgroundBlurStyle(value) {
    modifierWithKey(this._modifiersWithKeys, PopupBackgroundBlurStyleModifier.identity, PopupBackgroundBlurStyleModifier, value);
    return this;
  }
  popupTitleBackground(value) {
    modifierWithKey(this._modifiersWithKeys, PopupTitleBackgroundModifier.identity, PopupTitleBackgroundModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, AdaptiveWidthModifier.identity, AdaptiveWidthModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.AlphabetIndexer !== undefined) {
  globalThis.AlphabetIndexer.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkAlphabetIndexerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.AlphabetIndexerModifier(nativePtr, classType);
    });
  };
}

class PopupItemFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupItemFont(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupItemFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
PopupItemFontModifier.identity = Symbol('popupItemFont');
class SelectedFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetSelectedFont(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setSelectedFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
SelectedFontModifier.identity = Symbol('alphaBetIndexerSelectedFont');
class PopupFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupFont(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
PopupFontModifier.identity = Symbol('popupFont');
class AlphabetIndexerFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetFont(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
AlphabetIndexerFontModifier.identity = Symbol('alphaBetIndexerFont');
class PopupItemBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupItemBackgroundColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupItemBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PopupItemBackgroundColorModifier.identity = Symbol('popupItemBackgroundColor');
class ColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ColorModifier.identity = Symbol('alphabetColor');
class PopupColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PopupColorModifier.identity = Symbol('popupColor');
class SelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetSelectedColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectedColorModifier.identity = Symbol('selectedColor');
class PopupBackgroundModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupBackground(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupBackground(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PopupBackgroundModifier.identity = Symbol('popupBackground');
class SelectedBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetSelectedBackgroundColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setSelectedBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SelectedBackgroundColorModifier.identity = Symbol('selectedBackgroundColor');
class PopupUnselectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupUnselectedColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupUnselectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PopupUnselectedColorModifier.identity = Symbol('popupUnselectedColor');
class PopupSelectedColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupSelectedColor(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupSelectedColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
PopupSelectedColorModifier.identity = Symbol('popupSelectedColor');
class AlignStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetAlignStyle(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setAlignStyle(node, this.value.indexerAlign, this.value.offset);
    }
  }
  checkObjectDiff() {
    let indexerAlignEQ = isBaseOrResourceEqual(this.stageValue.indexerAlign, this.value.indexerAlign);
    let offsetEQ = isBaseOrResourceEqual(this.stageValue.offset, this.value.offset);
    return !indexerAlignEQ || !offsetEQ;
  }
}
AlignStyleModifier.identity = Symbol('alignStyle');
class UsingPopupModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetUsingPopup(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setUsingPopup(node, this.value);
    }
  }
}
UsingPopupModifier.identity = Symbol('usingPopup');
class AlphabetIndexerSelectedModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetSelected(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setSelected(node, this.value);
    }
  }
}
AlphabetIndexerSelectedModifier.identity = Symbol('alphabetIndexerSelected');
class ItemSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetItemSize(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setItemSize(node, this.value);
    }
  }
}
ItemSizeModifier.identity = Symbol('itemSize');
class PopupPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupPosition(node);
    }
    else {
      getUINativeModule().alphabetIndexer.setPopupPosition(node, this.value.x, this.value.y);
    }
  }
  checkObjectDiff() {
    let xEQ = isBaseOrResourceEqual(this.stageValue.x, this.value.x);
    let yEQ = isBaseOrResourceEqual(this.stageValue.y, this.value.y);
    return !xEQ || !yEQ;
  }
}
PopupPositionModifier.identity = Symbol('popupPosition');
class PopupItemBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupItemBorderRadius(node);
    } else {
      getUINativeModule().alphabetIndexer.setPopupItemBorderRadius(node, this.value);
    }
  }
}
PopupItemBorderRadiusModifier.identity = Symbol('popupItemBorderRadius');
class ItemBorderRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetItemBorderRadius(node);
    } else {
      getUINativeModule().alphabetIndexer.setItemBorderRadius(node, this.value);
    }
  }
}
ItemBorderRadiusModifier.identity = Symbol('itemBorderRadius');
class PopupBackgroundBlurStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupBackgroundBlurStyle(node);
    } else {
      getUINativeModule().alphabetIndexer.setPopupBackgroundBlurStyle(node, this.value);
    }
  }
}
ItemBorderRadiusModifier.identity = Symbol('popupBackgroundBlurStyle');

class PopupTitleBackgroundModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().alphabetIndexer.resetPopupTitleBackground(node);
    } else {
      getUINativeModule().alphabetIndexer.setPopupTitleBackground(node, this.value);
    }
  }
}
PopupTitleBackgroundModifier.identity = Symbol('popupTitleBackground');
class AdaptiveWidthModifier extends ModifierWithKey {
  constructor(value) {
      super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
        getUINativeModule().alphabetIndexer.resetAdaptiveWidth(node);
    } else {
        getUINativeModule().alphabetIndexer.setAdaptiveWidth(node, this.value);
    }
  }
}
AdaptiveWidthModifier.identity = Symbol('adaptiveWidth');

/// <reference path='./import.ts' />
class TextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().calendarPicker.resetTextStyle(node);
    }
    else {
      getUINativeModule().calendarPicker.setTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined, (_h =
      (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.color, (_f = this.value) === null ||
      _f === void 0 ? void 0 : _f.color) ||
        !isBaseOrResourceEqual((_h = (_g = this.stageValue) === null || _g === void 0 ? void 0 : _g.font) === null ||
         _h === void 0 ? void 0 : _h.size, (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
         _k === void 0 ? void 0 : _k.size);
    }
  }
}
TextStyleModifier.identity = Symbol('textStyle');
class EdgeAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (reset) {
      getUINativeModule().calendarPicker.resetEdgeAlign(node);
    }
    else {
      getUINativeModule().calendarPicker.setEdgeAlign(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.alignType) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.offset) === null ||
      _d === void 0 ? void 0 : _d.dx) !== null && _e !== void 0 ? _e : undefined, (_h = (_g =
      (_f = this.value) === null || _f === void 0 ? void 0 : _f.offset) === null ||
      _g === void 0 ? void 0 : _g.dy) !== null && _h !== void 0 ? _h : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    if (!(this.stageValue.alignType === this.value.alignType)) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.offset) === null || _b === void 0 ? void 0 : _b.dx, (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.offset) === null || _d === void 0 ? void 0 : _d.dx) ||
        !isBaseOrResourceEqual((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.offset) === null || _f === void 0 ? void 0 : _f.dy, (_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.offset) === null || _h === void 0 ? void 0 : _h.dy);
    }
  }
}
EdgeAlignModifier.identity = Symbol('edgeAlign');
class CalendarPickerPaddingModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().calendarPicker.resetCalendarPickerPadding(node);
    }
    else {
      getUINativeModule().calendarPicker.setCalendarPickerPadding(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.top, this.value.top) ||
      !isBaseOrResourceEqual(this.stageValue.right, this.value.right) ||
      !isBaseOrResourceEqual(this.stageValue.bottom, this.value.bottom) ||
      !isBaseOrResourceEqual(this.stageValue.left, this.value.left);
  }
}
CalendarPickerPaddingModifier.identity = Symbol('calendarPickerPadding');
class CalendarPickerBorderModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().calendarPicker.resetCalendarPickerBorder(node);
    }
    else {
      getUINativeModule().calendarPicker.setCalendarPickerBorder(node, this.value.arkWidth.left,
        this.value.arkWidth.right, this.value.arkWidth.top, this.value.arkWidth.bottom,
        this.value.arkColor.leftColor, this.value.arkColor.rightColor, this.value.arkColor.topColor,
        this.value.arkColor.bottomColor, this.value.arkRadius.topLeft, this.value.arkRadius.topRight,
        this.value.arkRadius.bottomLeft, this.value.arkRadius.bottomRight, this.value.arkStyle.top,
        this.value.arkStyle.right, this.value.arkStyle.bottom, this.value.arkStyle.left);
    }
  }
  checkObjectDiff() {
    return this.value.checkObjectDiff(this.stageValue);
  }
}
CalendarPickerBorderModifier.identity = Symbol('calendarPickerBorder');
class ArkCalendarPickerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  edgeAlign(alignType, offset) {
    let arkEdgeAlign = new ArkEdgeAlign();
    arkEdgeAlign.alignType = alignType;
    arkEdgeAlign.offset = offset;
    modifierWithKey(this._modifiersWithKeys, EdgeAlignModifier.identity, EdgeAlignModifier, arkEdgeAlign);
    return this;
  }
  textStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextStyleModifier.identity, TextStyleModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  padding(value) {
    let arkValue = new ArkPadding();
    if (value !== null && value !== undefined) {
      if (isLengthType(value) || isResource(value)) {
        arkValue.top = value;
        arkValue.right = value;
        arkValue.bottom = value;
        arkValue.left = value;
      }
      else {
        arkValue.top = value.top;
        arkValue.right = value.right;
        arkValue.bottom = value.bottom;
        arkValue.left = value.left;
      }
      modifierWithKey(this._modifiersWithKeys, CalendarPickerPaddingModifier.identity, CalendarPickerPaddingModifier, arkValue);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, CalendarPickerPaddingModifier.identity, CalendarPickerPaddingModifier, undefined);
    }
    return this;
  }
  border(value) {
    let _a, _b, _c, _d;
    let arkBorder = new ArkBorder();
    if (isUndefined(value)) {
      arkBorder = undefined;
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.width) && (value === null || value === void 0 ? void 0 : value.width) !== null) {
      if (isNumber(value.width) || isString(value.width) || isResource(value.width)) {
        arkBorder.arkWidth.left = value.width;
        arkBorder.arkWidth.right = value.width;
        arkBorder.arkWidth.top = value.width;
        arkBorder.arkWidth.bottom = value.width;
      }
      else {
        arkBorder.arkWidth.left = value.width.left;
        arkBorder.arkWidth.right = value.width.right;
        arkBorder.arkWidth.top = value.width.top;
        arkBorder.arkWidth.bottom = value.width.bottom;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.color) && (value === null || value === void 0 ? void 0 : value.color) !== null) {
      if (isNumber(value.color) || isString(value.color) || isResource(value.color)) {
        arkBorder.arkColor.leftColor = value.color;
        arkBorder.arkColor.rightColor = value.color;
        arkBorder.arkColor.topColor = value.color;
        arkBorder.arkColor.bottomColor = value.color;
      }
      else {
        arkBorder.arkColor.leftColor = value.color.left;
        arkBorder.arkColor.rightColor = value.color.right;
        arkBorder.arkColor.topColor = value.color.top;
        arkBorder.arkColor.bottomColor = value.color.bottom;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.radius) && (value === null || value === void 0 ? void 0 : value.radius) !== null) {
      if (isNumber(value.radius) || isString(value.radius) || isResource(value.radius)) {
        arkBorder.arkRadius.topLeft = value.radius;
        arkBorder.arkRadius.topRight = value.radius;
        arkBorder.arkRadius.bottomLeft = value.radius;
        arkBorder.arkRadius.bottomRight = value.radius;
      }
      else {
        arkBorder.arkRadius.topLeft = (_a = value.radius) === null || _a === void 0 ? void 0 : _a.topLeft;
        arkBorder.arkRadius.topRight = (_b = value.radius) === null || _b === void 0 ? void 0 : _b.topRight;
        arkBorder.arkRadius.bottomLeft = (_c = value.radius) === null || _c === void 0 ? void 0 : _c.bottomLeft;
        arkBorder.arkRadius.bottomRight = (_d = value.radius) === null || _d === void 0 ? void 0 : _d.bottomRight;
      }
    }
    if (!isUndefined(value === null || value === void 0 ? void 0 : value.style) && (value === null || value === void 0 ? void 0 : value.style) !== null) {
      let arkBorderStyle = new ArkBorderStyle();
      if (arkBorderStyle.parseBorderStyle(value.style)) {
        if (!isUndefined(arkBorderStyle.style)) {
          arkBorder.arkStyle.top = arkBorderStyle.style;
          arkBorder.arkStyle.left = arkBorderStyle.style;
          arkBorder.arkStyle.bottom = arkBorderStyle.style;
          arkBorder.arkStyle.right = arkBorderStyle.style;
        }
        else {
          arkBorder.arkStyle.top = arkBorderStyle.top;
          arkBorder.arkStyle.left = arkBorderStyle.left;
          arkBorder.arkStyle.bottom = arkBorderStyle.bottom;
          arkBorder.arkStyle.right = arkBorderStyle.right;
        }
      }
    }
    modifierWithKey(this._modifiersWithKeys, CalendarPickerBorderModifier.identity, CalendarPickerBorderModifier, arkBorder);
    return this;
  }
}
// @ts-ignore
if (globalThis.CalendarPicker !== undefined) {
  globalThis.CalendarPicker.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCalendarPickerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CalendarPickerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkDataPanelComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  closeEffect(value) {
    modifierWithKey(this._modifiersWithKeys, DataPanelCloseEffectModifier.identity, DataPanelCloseEffectModifier, value);
    return this;
  }
  valueColors(value) {
    modifierWithKey(this._modifiersWithKeys, DataPanelValueColorsModifier.identity, DataPanelValueColorsModifier, value);
    return this;
  }
  trackBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, DataPanelTrackBackgroundColorModifier.identity, DataPanelTrackBackgroundColorModifier, value);
    return this;
  }
  strokeWidth(value) {
    modifierWithKey(this._modifiersWithKeys, DataPanelStrokeWidthModifier.identity, DataPanelStrokeWidthModifier, value);
    return this;
  }
  trackShadow(value) {
    modifierWithKey(this._modifiersWithKeys, DataPanelTrackShadowModifier.identity, DataPanelTrackShadowModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().dataPanel.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().dataPanel.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, dataPanelConfig) {
    dataPanelConfig.contentModifier = this.modifier;
    if (isUndefined(this.dataPanelNode) || this.needRebuild) {
      let xNode = globalThis.requireNapi('arkui.node');
      this.dataPanelNode = new xNode.BuilderNode(context);
      this.dataPanelNode.build(this.builder, dataPanelConfig);
      this.needRebuild = false;
    } else {
      this.dataPanelNode.update(dataPanelConfig);
    }
    return this.dataPanelNode.getFrameNode();
  }
}
class DataPanelStrokeWidthModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().dataPanel.resetDataPanelStrokeWidth(node);
    }
    else {
      getUINativeModule().dataPanel.setDataPanelStrokeWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DataPanelStrokeWidthModifier.identity = Symbol('dataPanelStrokeWidth');
class DataPanelCloseEffectModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().dataPanel.resetCloseEffect(node);
    }
    else {
      getUINativeModule().dataPanel.setCloseEffect(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DataPanelCloseEffectModifier.identity = Symbol('dataPanelCloseEffect');
class DataPanelTrackBackgroundColorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().dataPanel.resetDataPanelTrackBackgroundColor(node);
    }
    else {
      getUINativeModule().dataPanel.setDataPanelTrackBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DataPanelTrackBackgroundColorModifier.identity = Symbol('dataPanelTrackBackgroundColorModifier');
class DataPanelTrackShadowModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      if (this.value === null) {
        getUINativeModule().dataPanel.setDataPanelTrackShadow(node, null);
      }
      getUINativeModule().dataPanel.resetDataPanelTrackShadow(node);
    }
    else {
      getUINativeModule().dataPanel.setDataPanelTrackShadow(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
DataPanelTrackShadowModifier.identity = Symbol('dataPanelTrackShadow');
class DataPanelValueColorsModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().dataPanel.resetDataPanelValueColors(node);
      return;
    }
    else {
      getUINativeModule().dataPanel.setDataPanelValueColors(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
DataPanelValueColorsModifier.identity = Symbol('dataPanelValueColors');
// @ts-ignore
if (globalThis.DataPanel !== undefined) {
  globalThis.DataPanel.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkDataPanelComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.DataPanelModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkDatePickerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  lunar(value) {
    modifierWithKey(this._modifiersWithKeys, DatePickerLunarModifier.identity, DatePickerLunarModifier, value);
    return this;
  }
  disappearTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, DatePickerDisappearTextStyleModifier.identity, DatePickerDisappearTextStyleModifier, value);
    return this;
  }
  textStyle(value) {
    modifierWithKey(this._modifiersWithKeys, DatePickerTextStyleModifier.identity, DatePickerTextStyleModifier, value);
    return this;
  }
  selectedTextStyle(value) {
    modifierWithKey(this._modifiersWithKeys, DatePickerSelectedTextStyleModifier.identity, DatePickerSelectedTextStyleModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  onDateChange(callback) {
    throw new Error('Method not implemented.');
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, DatePickerBackgroundColorModifier.identity, DatePickerBackgroundColorModifier, value);
    return this;
  }
}
class DatePickerLunarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().datePicker.resetLunar(node);
    }
    else {
      getUINativeModule().datePicker.setLunar(node, this.value);
    }
  }
}
DatePickerLunarModifier.identity = Symbol('lunar');
class DatePickerTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().datePicker.resetTextStyle(node);
    }
    else {
      getUINativeModule().datePicker.setTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined, (_e = (_d = (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined,
      (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
      ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null || _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null ||
        _t === void 0 ? void 0 : _t.family);
    }
  }
}
DatePickerTextStyleModifier.identity = Symbol('textStyle');
class DatePickerSelectedTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().datePicker.resetSelectedTextStyle(node);
    }
    else {
      getUINativeModule().datePicker.setSelectedTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined, (_h = (_g =
      (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined, (_p =
      (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null || _m ===
        void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null || _p ===
        void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null || _r ===
        void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null || _s === void 0 ? void 0 : _s.font) === null || _t ===
        void 0 ? void 0 : _t.family);
    }
  }
}
DatePickerSelectedTextStyleModifier.identity = Symbol('selectedTextStyle');
class DatePickerDisappearTextStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
    if (reset) {
      getUINativeModule().datePicker.resetDisappearTextStyle(node);
    }
    else {
      getUINativeModule().datePicker.setDisappearTextStyle(node, (_b = (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.color) !== null && _b !== void 0 ? _b : undefined,
      (_e = (_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null ||
      _d === void 0 ? void 0 : _d.size) !== null && _e !== void 0 ? _e : undefined,
      (_h = (_g = (_f = this.value) === null || _f === void 0 ? void 0 : _f.font) === null ||
      _g === void 0 ? void 0 : _g.weight) !== null && _h !== void 0 ? _h : undefined,
      (_l = (_k = (_j = this.value) === null || _j === void 0 ? void 0 : _j.font) === null ||
      _k === void 0 ? void 0 : _k.family) !== null && _l !== void 0 ? _l : undefined,
      (_p = (_o = (_m = this.value) === null || _m === void 0 ? void 0 : _m.font) === null ||
      _o === void 0 ? void 0 : _o.style) !== null && _p !== void 0 ? _p : undefined);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t;
    if (!(((_b = (_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.font) === null || _b === void 0 ? void 0 : _b.weight) ===
    ((_d = (_c = this.value) === null || _c === void 0 ? void 0 : _c.font) === null || _d === void 0 ? void 0 : _d.weight) &&
      ((_f = (_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.font) === null || _f === void 0 ? void 0 : _f.style) ===
      ((_h = (_g = this.value) === null || _g === void 0 ? void 0 : _g.font) === null || _h === void 0 ? void 0 : _h.style))) {
      return true;
    }
    else {
      return !isBaseOrResourceEqual((_j = this.stageValue) === null || _j === void 0 ? void 0 : _j.color, (_k = this.value) === null ||
      _k === void 0 ? void 0 : _k.color) ||
        !isBaseOrResourceEqual((_m = (_l = this.stageValue) === null || _l === void 0 ? void 0 : _l.font) === null ||
        _m === void 0 ? void 0 : _m.size, (_p = (_o = this.value) === null || _o === void 0 ? void 0 : _o.font) === null ||
        _p === void 0 ? void 0 : _p.size) ||
        !isBaseOrResourceEqual((_r = (_q = this.stageValue) === null || _q === void 0 ? void 0 : _q.font) === null ||
        _r === void 0 ? void 0 : _r.family, (_t = (_s = this.value) === null ||
        _s === void 0 ? void 0 : _s.font) === null || _t === void 0 ? void 0 : _t.family);
    }
  }
}
DatePickerDisappearTextStyleModifier.identity = Symbol('disappearTextStyle');
class DatePickerBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().datePicker.resetBackgroundColor(node);
    }
    else {
      getUINativeModule().datePicker.setBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
DatePickerBackgroundColorModifier.identity = Symbol('datePickerBackgroundColor');
//@ts-ignore
if (globalThis.DatePicker !== undefined) {
  globalThis.DatePicker.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkDatePickerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.DatePickerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkFormComponentComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, FormComponentSizeModifier.identity, FormComponentSizeModifier, value);
    return this;
  }
  visibility(value) {
    modifierWithKey(this._modifiersWithKeys, FormComponentVisibilityModifier.identity, FormComponentVisibilityModifier, value);
    return this;
  }
  moduleName(value) {
    modifierWithKey(this._modifiersWithKeys, FormComponentModuleNameModifier.identity, FormComponentModuleNameModifier, value);
    return this;
  }
  dimension(value) {
    modifierWithKey(this._modifiersWithKeys, FormComponentDimensionModifier.identity, FormComponentDimensionModifier, value);
    return this;
  }
  allowUpdate(value) {
    modifierWithKey(this._modifiersWithKeys, FormComponentAllowUpdateModifier.identity, FormComponentAllowUpdateModifier, value);
    return this;
  }
  onAcquired(callback) {
    throw new Error('Method not implemented.');
  }
  onError(callback) {
    throw new Error('Method not implemented.');
  }
  onRouter(callback) {
    throw new Error('Method not implemented.');
  }
  onUninstall(callback) {
    throw new Error('Method not implemented.');
  }
  onLoad(callback) {
    throw new Error('Method not implemented.');
  }
}
class FormComponentModuleNameModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().formComponent.resetModuleName(node);
    }
    else {
      getUINativeModule().formComponent.setModuleName(node, this.value);
    }
  }
}
FormComponentModuleNameModifier.identity = Symbol('formComponentModuleName');
class FormComponentDimensionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().formComponent.resetDimension(node);
    }
    else {
      getUINativeModule().formComponent.setDimension(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FormComponentDimensionModifier.identity = Symbol('formComponentDimension');
class FormComponentAllowUpdateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().formComponent.resetAllowUpdate(node);
    }
    else {
      getUINativeModule().formComponent.setAllowUpdate(node, this.value);
    }
  }
}
FormComponentAllowUpdateModifier.identity = Symbol('formComponentAllowUpdate');
class FormComponentSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().formComponent.resetSize(node);
    }
    else {
      getUINativeModule().formComponent.setSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    let widthEQ = isBaseOrResourceEqual(this.stageValue.width, this.value.width);
    let heightEQ = isBaseOrResourceEqual(this.stageValue.height, this.value.height);
    return !widthEQ || !heightEQ;
  }
}
FormComponentSizeModifier.identity = Symbol('formComponentSize');
class FormComponentVisibilityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().formComponent.resetVisibility(node);
    }
    else {
      getUINativeModule().formComponent.setVisibility(node, this.value);
    }
  }
}
FormComponentVisibilityModifier.identity = Symbol('formComponentVisibility');
// @ts-ignore
if (globalThis.FormComponent !== undefined) {
  globalThis.FormComponent.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkFormComponentComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.FormComponentModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkGaugeComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  value(value) {
    modifierWithKey(this._modifiersWithKeys, GaugeVauleModifier.identity, GaugeVauleModifier, value);
    return this;
  }
  startAngle(angle) {
    modifierWithKey(this._modifiersWithKeys, GaugeStartAngleModifier.identity, GaugeStartAngleModifier, angle);
    return this;
  }
  endAngle(angle) {
    modifierWithKey(this._modifiersWithKeys, GaugeEndAngleModifier.identity, GaugeEndAngleModifier, angle);
    return this;
  }
  colors(colors) {
    modifierWithKey(this._modifiersWithKeys, GaugeColorsModifier.identity, GaugeColorsModifier, colors);
    return this;
  }
  strokeWidth(length) {
    modifierWithKey(this._modifiersWithKeys, GaugeStrokeWidthModifier.identity, GaugeStrokeWidthModifier, length);
    return this;
  }
  description(value) {
    throw new Error('Method not implemented.');
  }
  trackShadow(value) {
    modifierWithKey(this._modifiersWithKeys, GaugeTrackShadowModifier.identity, GaugeTrackShadowModifier, value);
    return this;
  }
  indicator(value) {
    modifierWithKey(this._modifiersWithKeys, GaugeIndicatorModifier.identity, GaugeIndicatorModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().gauge.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().gauge.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, gaugeConfiguration) {
    gaugeConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.gaugeNode) || this.needRebuild) {
      let xNode = globalThis.requireNapi('arkui.node');
      this.gaugeNode = new xNode.BuilderNode(context);
      this.gaugeNode.build(this.builder, gaugeConfiguration);
      this.needRebuild = false;
    } else {
      this.gaugeNode.update(gaugeConfiguration);
    }
    return this.gaugeNode.getFrameNode();
  }
}
// @ts-ignore
globalThis.Gauge.contentModifier = function (modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return new ArkGaugeComponent(nativeNode);
  });
  component.setContentModifier(modifier);
};
class GaugeIndicatorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeIndicator(node, this.value);
    }
    else {
      getUINativeModule().gauge.setGaugeIndicator(node, this.value.icon, this.value.space);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.icon, this.value.icon) ||
      !isBaseOrResourceEqual(this.stageValue.space, this.value.space);
  }
}
GaugeIndicatorModifier.identity = Symbol('gaugeIndicator');
class GaugeColorsModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeColors(node);
    }
    else {
      getUINativeModule().gauge.setGaugeColors(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
GaugeColorsModifier.identity = Symbol('gaugeColors');
class GaugeVauleModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeVaule(node);
    }
    else {
      getUINativeModule().gauge.setGaugeVaule(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GaugeVauleModifier.identity = Symbol('gaugeVaule');
class GaugeStartAngleModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeStartAngle(node);
    }
    else {
      getUINativeModule().gauge.setGaugeStartAngle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GaugeStartAngleModifier.identity = Symbol('gaugeStartAngle');
class GaugeEndAngleModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeEndAngle(node);
    }
    else {
      getUINativeModule().gauge.setGaugeEndAngle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GaugeEndAngleModifier.identity = Symbol('gaugeEndAngle');
class GaugeStrokeWidthModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeStrokeWidth(node);
    }
    else {
      getUINativeModule().gauge.setGaugeStrokeWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GaugeStrokeWidthModifier.identity = Symbol('gaugeStrokeWidth');
class GaugeTrackShadowModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gauge.resetGaugeTrackShadow(node);
    }
    else {
      getUINativeModule().gauge.setGaugeTrackShadow(node, this.value, this.value.radius, this.value.offsetX, this.value.offsetY);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
GaugeTrackShadowModifier.identity = Symbol('gaugeTrackShadow');
// @ts-ignore
if (globalThis.Gauge !== undefined) {
  globalThis.Gauge.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGaugeComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.GaugeModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkMarqueeComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeFontSizeModifier.identity, MarqueeFontSizeModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeFontColorModifier.identity, MarqueeFontColorModifier, value);
    return this;
  }
  allowScale(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeAllowScaleModifier.identity, MarqueeAllowScaleModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeFontWeightModifier.identity, MarqueeFontWeightModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeFontFamilyModifier.identity, MarqueeFontFamilyModifier, value);
    return this;
  }
  onStart(event) {
    modifierWithKey(this._modifiersWithKeys, MarqueeOnStartModifier.identity, MarqueeOnStartModifier, event);
    return this;
  }
  onBounce(event) {
    modifierWithKey(this._modifiersWithKeys, MarqueeOnBounceModifier.identity, MarqueeOnBounceModifier, event);
    return this;
  }
  onFinish(event) {
    modifierWithKey(this._modifiersWithKeys, MarqueeOnFinishModifier.identity, MarqueeOnFinishModifier, event);
    return this;
  }
  marqueeUpdateStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, MarqueeUpdateStrategyModifier.identity, MarqueeUpdateStrategyModifier, value);
    return this;
  }
}
class MarqueeFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetFontColor(node);
    }
    else {
      getUINativeModule().marquee.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MarqueeFontColorModifier.identity = Symbol('fontColor');
class MarqueeFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetFontSize(node);
    }
    else {
      getUINativeModule().marquee.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MarqueeFontSizeModifier.identity = Symbol('fontSize');
class MarqueeAllowScaleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetAllowScale(node);
    }
    else {
      getUINativeModule().marquee.setAllowScale(node, this.value);
    }
  }
}
MarqueeAllowScaleModifier.identity = Symbol('allowScale');
class MarqueeFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetFontWeight(node);
    }
    else {
      getUINativeModule().marquee.setFontWeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
MarqueeFontWeightModifier.identity = Symbol('fontWeight');
class MarqueeFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetFontFamily(node);
    }
    else {
      getUINativeModule().marquee.setFontFamily(node, this.value);
    }
  }
}
MarqueeFontFamilyModifier.identity = Symbol('fontFamily');
class MarqueeUpdateStrategyModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().marquee.resetMarqueeUpdateStrategy(node);
        }
        else {
            getUINativeModule().marquee.setMarqueeUpdateStrategy(node, this.value);
        }
    }
}
MarqueeUpdateStrategyModifier.identity = Symbol('marqueeUpdateStrategy');
class MarqueeOnStartModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetMarqueeOnStart(node);
    } else {
      getUINativeModule().marquee.setMarqueeOnStart(node, this.value);
    }
  }
}
MarqueeOnStartModifier.identity = Symbol('marqueeOnStart');
class MarqueeOnBounceModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetMarqueeOnBounce(node);
    } else {
      getUINativeModule().marquee.setMarqueeOnBounce(node, this.value);
    }
  }
}
MarqueeOnBounceModifier.identity = Symbol('marqueeOnBounce');
class MarqueeOnFinishModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().marquee.resetMarqueeOnFinish(node);
    } else {
      getUINativeModule().marquee.setMarqueeOnFinish(node, this.value);
    }
  }
}
MarqueeOnFinishModifier.identity = Symbol('marqueeOnFinish');
// @ts-ignore
if (globalThis.Marquee !== undefined) {
  globalThis.Marquee.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkMarqueeComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.MarqueeModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class MenuFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menu.resetMenuFontColor(node);
    }
    else {
      getUINativeModule().menu.setMenuFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MenuFontColorModifier.identity = Symbol('fontColor');
class MenuWidthModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menu.resetWidth(node);
    } else {
      getUINativeModule().menu.setWidth(node, this.value);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MenuWidthModifier.identity = Symbol('menuWidth');
class MenuFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset || !this.value) {
      getUINativeModule().menu.resetFont(node);
    }
    else {
      getUINativeModule().menu.setFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
MenuFontModifier.identity = Symbol('font');
class RadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menu.resetRadius(node);
    }
    else {
      if (isNumber(this.value) || isString(this.value) || isResource(this.value)) {
        getUINativeModule().menu.setRadius(node, this.value, this.value, this.value, this.value, false);
      }
      else {
        getUINativeModule().menu.setRadius(node, this.value.topLeft, this.value.topRight, this.value.bottomLeft, this.value.bottomRight, true);
      }
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.stageValue.topLeft === this.value.topLeft &&
        this.stageValue.topRight === this.value.topRight &&
        this.stageValue.bottomLeft === this.value.bottomLeft &&
        this.stageValue.bottomRight === this.value.bottomRight);
    }
    else {
      return true;
    }
  }
}
RadiusModifier.identity = Symbol('radius');
class ArkMenuComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, MenuWidthModifier.identity, MenuWidthModifier, value);
    return this;
  }
  fontSize(value) {
    throw new Error('Method not implemented.');
  }
  font(value) {
    modifierWithKey(this._modifiersWithKeys, MenuFontModifier.identity, MenuFontModifier, value);
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, MenuFontColorModifier.identity, MenuFontColorModifier, value);
    return this;
  }
  radius(value) {
    modifierWithKey(this._modifiersWithKeys, RadiusModifier.identity, RadiusModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Menu !== undefined) {
  globalThis.Menu.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkMenuComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.MenuModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class MenuItemSelectedModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menuitem.resetMenuItemSelected(node);
    }
    else {
      getUINativeModule().menuitem.setMenuItemSelected(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MenuItemSelectedModifier.identity = Symbol('menuItemSelected');
class LabelFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menuitem.resetLabelFontColor(node);
    }
    else {
      getUINativeModule().menuitem.setLabelFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
LabelFontColorModifier.identity = Symbol('labelfontColor');
class ContentFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().menuitem.resetContentFontColor(node);
    }
    else {
      getUINativeModule().menuitem.setContentFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ContentFontColorModifier.identity = Symbol('contentfontColor');
class LabelFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset || !this.value) {
      getUINativeModule().menuitem.resetLabelFont(node);
    }
    else {
      getUINativeModule().menuitem.setLabelFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
LabelFontModifier.identity = Symbol('labelFont');
class ContentFontModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset || !this.value) {
      getUINativeModule().menuitem.resetContentFont(node);
    }
    else {
      getUINativeModule().menuitem.setContentFont(node, this.value.size, this.value.weight, this.value.family, this.value.style);
    }
  }
  checkObjectDiff() {
    let sizeEQ = isBaseOrResourceEqual(this.stageValue.size, this.value.size);
    let weightEQ = this.stageValue.weight === this.value.weight;
    let familyEQ = isBaseOrResourceEqual(this.stageValue.family, this.value.family);
    let styleEQ = this.stageValue.style === this.value.style;
    return !sizeEQ || !weightEQ || !familyEQ || !styleEQ;
  }
}
ContentFontModifier.identity = Symbol('contentFont');
class MenuItemSelectIconModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset || !this.value) {
      getUINativeModule().menuitem.resetSelectIcon(node);
    } else {
      getUINativeModule().menuitem.setSelectIcon(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
MenuItemSelectIconModifier.identity = Symbol('selectIcon');
class ArkMenuItemComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  selected(value) {
    modifierWithKey(this._modifiersWithKeys, MenuItemSelectedModifier.identity, MenuItemSelectedModifier, value);
    return this;
  }
  selectIcon(value) {
    modifierWithKey(this._modifiersWithKeys, MenuItemSelectIconModifier.identity, MenuItemSelectIconModifier, value);
    return this;
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  contentFont(value) {
    modifierWithKey(this._modifiersWithKeys, ContentFontModifier.identity, ContentFontModifier, value);
    return this;
  }
  contentFontColor(value) {
    modifierWithKey(this._modifiersWithKeys, ContentFontColorModifier.identity, ContentFontColorModifier, value);
    return this;
  }
  labelFont(value) {
    modifierWithKey(this._modifiersWithKeys, LabelFontModifier.identity, LabelFontModifier, value);
    return this;
  }
  labelFontColor(value) {
    modifierWithKey(this._modifiersWithKeys, LabelFontColorModifier.identity, LabelFontColorModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.MenuItem !== undefined) {
  globalThis.MenuItem.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkMenuItemComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.MenuItemModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkMenuItemGroupComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.MenuItemGroup !== undefined) {
  globalThis.MenuItemGroup.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkMenuItemGroupComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkPluginComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onComplete(callback) {
    throw new Error('Method not implemented.');
  }
  onError(callback) {
    throw new Error('Method not implemented.');
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, PluginSizeModifier.identity, PluginSizeModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, PluginWidthModifier.identity, PluginWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, PluginHeightModifier.identity, PluginHeightModifier, value);
    return this;
  }
}
class PluginWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().plugin.resetWidth(node);
    }
    else {
      getUINativeModule().plugin.setWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else {
      return true;
    }
  }
}
PluginWidthModifier.identity = Symbol('pluginWidth');
class PluginHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().plugin.resetHeight(node);
    }
    else {
      getUINativeModule().plugin.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else {
      return true;
    }
  }
}
PluginHeightModifier.identity = Symbol('pluginHeight');
class PluginSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().plugin.resetSize(node);
    }
    else {
      getUINativeModule().plugin.setSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
PluginSizeModifier.identity = Symbol('size');
// @ts-ignore
if (globalThis.PluginComponent !== undefined) {
  globalThis.PluginComponent.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPluginComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PluginComponentModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkProgressComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys,
        ProgressInitializeModifier.identity, ProgressInitializeModifier, value[0]);
    }
    return this;
  }
  value(value) {
    modifierWithKey(this._modifiersWithKeys, ProgressValueModifier.identity, ProgressValueModifier, value);
    return this;
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, ProgressColorModifier.identity, ProgressColorModifier, value);
    return this;
  }
  style(value) {
    modifierWithKey(this._modifiersWithKeys, ProgressStyleModifier.identity, ProgressStyleModifier, value);
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, ProgressBackgroundColorModifier.identity, ProgressBackgroundColorModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().progress.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().progress.setContentModifierBuilder(this.nativePtr, this);
    return this;
  }
  makeContentModifierNode(context, progressConfig) {
    progressConfig.contentModifier = this.modifier;
    if (isUndefined(this.progressNode) || this.needRebuild) {
      let xNode = globalThis.requireNapi('arkui.node');
      this.progressNode = new xNode.BuilderNode(context);
      this.progressNode.build(this.builder, progressConfig);
      this.needRebuild = false;
    } else {
      this.progressNode.update(progressConfig);
    }
    return this.progressNode.getFrameNode();
  }
}
class ProgressInitializeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().progress.resetProgressInitialize(node);
    }
    else {
      getUINativeModule().progress.setProgressInitialize(node, this.value.value,
        this.value.total, this.value.style, this.value.type);
    }
  }
}
ProgressInitializeModifier.identity = Symbol('progressInitialize');
class ProgressValueModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().progress.ResetProgressValue(node);
    }
    else {
      getUINativeModule().progress.SetProgressValue(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ProgressValueModifier.identity = Symbol('value');
class ProgressColorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().progress.resetProgressColor(node);
    }
    else {
      getUINativeModule().progress.setProgressColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
ProgressColorModifier.identity = Symbol('color');
class ProgressStyleModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().progress.ResetProgressStyle(node);
    }
    else {
      let strokeWidth = this.value.strokeWidth;
      let scaleCount = this.value.scaleCount;
      let scaleWidth = this.value.scaleWidth;
      let enableSmoothEffect = this.value.enableSmoothEffect;
      let borderColor = this.value.borderColor;
      let borderWidth = this.value.borderWidth;
      let content = this.value.content;
      let fontSize;
      let fontWeight;
      let fontFamily;
      let fontStyle;
      if (this.value.font) {
        fontSize = this.value.font.size;
        fontWeight = this.value.font.weight;
        fontFamily = this.value.font.family;
        fontStyle = this.value.font.style;
      }
      let fontColor = this.value.fontColor;
      let enableScanEffect = this.value.enableScanEffect;
      let showDefaultPercentage = this.value.showDefaultPercentage;
      let shadow = this.value.shadow;
      let status = this.value.status;
      let strokeRadius = this.value.strokeRadius;
      getUINativeModule().progress.SetProgressStyle(node, strokeWidth, scaleCount,
        scaleWidth, enableSmoothEffect, borderColor, borderWidth, content, fontSize,
        fontWeight, fontFamily, fontStyle, fontColor, enableScanEffect, showDefaultPercentage,
        shadow, status, strokeRadius);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ProgressStyleModifier.identity = Symbol('style');
class ProgressBackgroundColorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().progress.resetProgressBackgroundColor(node);
    }
    else {
      getUINativeModule().progress.setProgressBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ProgressBackgroundColorModifier.identity = Symbol('progressBackgroundColor');
// @ts-ignore
if (globalThis.Progress !== undefined) {
  globalThis.Progress.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkProgressComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ProgressModifier(nativePtr, classType);
    });
  };
}

// @ts-ignore
if (globalThis.Progress !== undefined) {
  globalThis.Progress.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkProgressComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkQRCodeComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, QRColorModifier.identity, QRColorModifier, value);
    return this;
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, QRBackgroundColorModifier.identity, QRBackgroundColorModifier, value);
    return this;
  }
  contentOpacity(value) {
    modifierWithKey(this._modifiersWithKeys, QRContentOpacityModifier.identity, QRContentOpacityModifier, value);
    return this;
  }
}
class QRColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().qrcode.resetQRColor(node);
    }
    else {
      getUINativeModule().qrcode.setQRColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
QRColorModifier.identity = Symbol('color');
class QRBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().qrcode.resetQRBackgroundColor(node);
    }
    else {
      getUINativeModule().qrcode.setQRBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
QRBackgroundColorModifier.identity = Symbol('qrBackgroundColor');
class QRContentOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().qrcode.resetContentOpacity(node);
    }
    else {
      getUINativeModule().qrcode.setContentOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
QRContentOpacityModifier.identity = Symbol('qrContentOpacity');
// @ts-ignore
if (globalThis.QRCode !== undefined) {
  globalThis.QRCode.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkQRCodeComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.QRCodeModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkRichTextComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onStart(callback) {
    throw new Error('Method not implemented.');
  }
  onComplete(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.RichText !== undefined) {
  globalThis.RichText.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRichTextComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkScrollBarComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.ScrollBar !== undefined) {
  globalThis.ScrollBar.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkScrollBarComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkStepperComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onFinish(callback) {
    throw new Error('Method not implemented.');
  }
  onSkip(callback) {
    throw new Error('Method not implemented.');
  }
  onChange(callback) {
    throw new Error('Method not implemented.');
  }
  onNext(callback) {
    throw new Error('Method not implemented.');
  }
  onPrevious(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Stepper !== undefined) {
  globalThis.Stepper.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkStepperComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkStepperItemComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  prevLabel(value) {
    throw new Error('Method not implemented.');
  }
  nextLabel(value) {
    modifierWithKey(this._modifiersWithKeys, NextLabelModifier.identity, NextLabelModifier, value);
    return this;
  }
  status(value) {
    throw new Error('Method not implemented.');
  }
}
class NextLabelModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().stepperItem.resetNextLabel(node);
    }
    else {
      getUINativeModule().stepperItem.setNextLabel(node, this.value);
    }
  }
}
NextLabelModifier.identity = Symbol('NextLabel');
// @ts-ignore
if (globalThis.StepperItem !== undefined) {
  globalThis.StepperItem.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkStepperItemComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.StepperItemModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkTextClockComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  format(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFormatModifier.identity, TextClockFormatModifier, value);
    return this;
  }
  onDateChange(event) {
    throw new Error('Method not implemented.');
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFontColorModifier.identity, TextClockFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFontSizeModifier.identity, TextClockFontSizeModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFontStyleModifier.identity, TextClockFontStyleModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFontWeightModifier.identity, TextClockFontWeightModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, TextClockFontFamilyModifier.identity, TextClockFontFamilyModifier, value);
    return this;
  }
  textShadow(value) {
    throw new Error('Method not implemented.');
  }
  fontFeature(value) {
    throw new Error('Method not implemented.');
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().textClock.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.needRebuild = false;
    if (this.builder !== modifier.applyContent()) {
      this.needRebuild = true;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().textClock.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, textClockConfiguration) {
    textClockConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.textClockNode) || this.needRebuild) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.textClockNode = new xNode.BuilderNode(context);
      this.textClockNode.build(this.builder, textClockConfiguration);
      this.needRebuild = false;
    } else {
      this.textClockNode.update(textClockConfiguration);
    }
    return this.textClockNode.getFrameNode();
  }
}
class TextClockFormatModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFormat(node);
    }
    else {
      getUINativeModule().textClock.setFormat(node, this.value);
    }
  }
}
TextClockFormatModifier.identity = Symbol('textClockFormat');
class TextClockFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFontColor(node);
    }
    else {
      getUINativeModule().textClock.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextClockFontColorModifier.identity = Symbol('textClockFontColor');
class TextClockFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFontSize(node);
    }
    else {
      getUINativeModule().textClock.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextClockFontSizeModifier.identity = Symbol('textClockFontSize');
class TextClockFontStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFontStyle(node);
    }
    else {
      getUINativeModule().textClock.setFontStyle(node, this.value);
    }
  }
}
TextClockFontStyleModifier.identity = Symbol('textClockFontStyle');
class TextClockFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFontWeight(node);
    }
    else {
      getUINativeModule().textClock.setFontWeight(node, this.value);
    }
  }
}
TextClockFontWeightModifier.identity = Symbol('textClockFontWeight');
class TextClockFontFamilyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textClock.resetFontFamily(node);
    }
    else {
      getUINativeModule().textClock.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextClockFontFamilyModifier.identity = Symbol('textClockFontFamily');
// @ts-ignore
if (globalThis.TextClock !== undefined) {
  globalThis.TextClock.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextClockComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextClockModifier(nativePtr, classType);
    });
  };
}
// @ts-ignore
globalThis.TextClock.contentModifier = function (modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return new ArkTextClockComponent(nativeNode);
  });
  component.setContentModifier(modifier);
};

/// <reference path='./import.ts' />
class ArkTextTimerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontColorModifier.identity, TextTimerFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontSizeModifier.identity, TextTimerFontSizeModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontWeightModifier.identity, TextTimerFontWeightModifier, value);
    return this;
  }
  fontStyle(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontStyleModifier.identity, TextTimerFontStyleModifier, value);
    return this;
  }
  fontFamily(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontFamilyModifier.identity, TextTimerFontFamilyModifier, value);
    return this;
  }
  format(value) {
    modifierWithKey(this._modifiersWithKeys, TextTimerFormatModifier.identity, TextTimerFormatModifier, value);
    return this;
  }
  contentModifier(value) {
    this.setContentModifier(value);
    return this;
  }
  setContentModifier(modifier) {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().textTimer.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().textTimer.setContentModifierBuilder(this.nativePtr, this);
  }
  makeContentModifierNode(context, textTimerConfiguration) {
    textTimerConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.textTimerNode)) {
      let xNode = globalThis.requireNapi('arkui.node');
      this.textTimerNode = new xNode.BuilderNode(context);
      this.textTimerNode.build(this.builder, textTimerConfiguration);
    } else {
      this.textTimerNode.update(textTimerConfiguration);
    }
    return this.textTimerNode.getFrameNode();
  }
  onTimer(event) {
    throw new Error('Method not implemented.');
  }
}
class TextTimerFontColorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFontColor(node);
    }
    else {
      getUINativeModule().textTimer.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTimerFontColorModifier.identity = Symbol('fontColor');
class TextTimerFontSizeModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFontSize(node);
    }
    else {
      getUINativeModule().textTimer.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTimerFontSizeModifier.identity = Symbol('fontSize');
class TextTimerFontWeightModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFontWeight(node);
    }
    else {
      getUINativeModule().textTimer.setFontWeight(node, this.value);
    }
  }
}
TextTimerFontWeightModifier.identity = Symbol('fontWeight');
class TextTimerFontStyleModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFontStyle(node);
    }
    else {
      getUINativeModule().textTimer.setFontStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTimerFontStyleModifier.identity = Symbol('fontStyle');
class TextTimerFontFamilyModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFontFamily(node);
    }
    else {
      getUINativeModule().textTimer.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TextTimerFontFamilyModifier.identity = Symbol('fontFamily');
class TextTimerFormatModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().textTimer.resetFormat(node);
    }
    else {
      getUINativeModule().textTimer.setFormat(node, this.value);
    }
  }
}
TextTimerFormatModifier.identity = Symbol('textTimerFormat');
// @ts-ignore
if (globalThis.TextTimer !== undefined) {
  globalThis.TextTimer.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTextTimerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TextTimerModifier(nativePtr, classType);
    });
  };
  globalThis.TextTimer.contentModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkTextTimerComponent(nativeNode);
    });
    component.setContentModifier(modifier);
  };
}

/// <reference path='./import.ts' />
class ArkWebComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  javaScriptAccess(javaScriptAccess) {
    throw new Error('Method not implemented.');
  }
  fileAccess(fileAccess) {
    throw new Error('Method not implemented.');
  }
  onlineImageAccess(onlineImageAccess) {
    throw new Error('Method not implemented.');
  }
  domStorageAccess(domStorageAccess) {
    throw new Error('Method not implemented.');
  }
  imageAccess(imageAccess) {
    throw new Error('Method not implemented.');
  }
  mixedMode(mixedMode) {
    throw new Error('Method not implemented.');
  }
  zoomAccess(zoomAccess) {
    throw new Error('Method not implemented.');
  }
  geolocationAccess(geolocationAccess) {
    throw new Error('Method not implemented.');
  }
  javaScriptProxy(javaScriptProxy) {
    throw new Error('Method not implemented.');
  }
  password(password) {
    throw new Error('Method not implemented.');
  }
  cacheMode(cacheMode) {
    throw new Error('Method not implemented.');
  }
  darkMode(mode) {
    throw new Error('Method not implemented.');
  }
  forceDarkAccess(access) {
    throw new Error('Method not implemented.');
  }
  mediaOptions(options) {
    throw new Error('Method not implemented.');
  }
  tableData(tableData) {
    throw new Error('Method not implemented.');
  }
  wideViewModeAccess(wideViewModeAccess) {
    throw new Error('Method not implemented.');
  }
  overviewModeAccess(overviewModeAccess) {
    throw new Error('Method not implemented.');
  }
  overScrollMode(mode) {
    throw new Error('Method not implemented.');
  }
  textZoomAtio(textZoomAtio) {
    throw new Error('Method not implemented.');
  }
  textZoomRatio(textZoomRatio) {
    throw new Error('Method not implemented.');
  }
  databaseAccess(databaseAccess) {
    throw new Error('Method not implemented.');
  }
  initialScale(percent) {
    throw new Error('Method not implemented.');
  }
  userAgent(userAgent) {
    throw new Error('Method not implemented.');
  }
  onPageEnd(callback) {
    throw new Error('Method not implemented.');
  }
  onPageBegin(callback) {
    throw new Error('Method not implemented.');
  }
  onProgressChange(callback) {
    throw new Error('Method not implemented.');
  }
  onTitleReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onGeolocationHide(callback) {
    throw new Error('Method not implemented.');
  }
  onGeolocationShow(callback) {
    throw new Error('Method not implemented.');
  }
  onRequestSelected(callback) {
    throw new Error('Method not implemented.');
  }
  onAlert(callback) {
    throw new Error('Method not implemented.');
  }
  onBeforeUnload(callback) {
    throw new Error('Method not implemented.');
  }
  onConfirm(callback) {
    throw new Error('Method not implemented.');
  }
  onPrompt(callback) {
    throw new Error('Method not implemented.');
  }
  onConsole(callback) {
    throw new Error('Method not implemented.');
  }
  onErrorReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onHttpErrorReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onDownloadStart(callback) {
    throw new Error('Method not implemented.');
  }
  onRefreshAccessedHistory(callback) {
    throw new Error('Method not implemented.');
  }
  onUrlLoadIntercept(callback) {
    throw new Error('Method not implemented.');
  }
  onSslErrorReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onRenderExited(callback) {
    throw new Error('Method not implemented.');
  }
  onShowFileSelector(callback) {
    throw new Error('Method not implemented.');
  }
  onFileSelectorShow(callback) {
    throw new Error('Method not implemented.');
  }
  onResourceLoad(callback) {
    throw new Error('Method not implemented.');
  }
  onFullScreenExit(callback) {
    throw new Error('Method not implemented.');
  }
  onFullScreenEnter(callback) {
    throw new Error('Method not implemented.');
  }
  onScaleChange(callback) {
    throw new Error('Method not implemented.');
  }
  onHttpAuthRequest(callback) {
    throw new Error('Method not implemented.');
  }
  onInterceptRequest(callback) {
    throw new Error('Method not implemented.');
  }
  onPermissionRequest(callback) {
    throw new Error('Method not implemented.');
  }
  onScreenCaptureRequest(callback) {
    throw new Error('Method not implemented.');
  }
  onContextMenuShow(callback) {
    throw new Error('Method not implemented.');
  }
  mediaPlayGestureAccess(access) {
    throw new Error('Method not implemented.');
  }
  onSearchResultReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onScroll(callback) {
    throw new Error('Method not implemented.');
  }
  onSslErrorEventReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onSslErrorEvent(callback) {
    throw new Error('Method not implemented.');
  }
  onClientAuthenticationRequest(callback) {
    throw new Error('Method not implemented.');
  }
  onWindowNew(callback) {
    throw new Error('Method not implemented.');
  }
  onWindowExit(callback) {
    throw new Error('Method not implemented.');
  }
  multiWindowAccess(multiWindow) {
    throw new Error('Method not implemented.');
  }
  onInterceptKeyEvent(callback) {
    throw new Error('Method not implemented.');
  }
  webStandardFont(family) {
    throw new Error('Method not implemented.');
  }
  webSerifFont(family) {
    throw new Error('Method not implemented.');
  }
  webSansSerifFont(family) {
    throw new Error('Method not implemented.');
  }
  webFixedFont(family) {
    throw new Error('Method not implemented.');
  }
  webFantasyFont(family) {
    throw new Error('Method not implemented.');
  }
  webCursiveFont(family) {
    throw new Error('Method not implemented.');
  }
  defaultFixedFontSize(size) {
    throw new Error('Method not implemented.');
  }
  defaultFontSize(size) {
    throw new Error('Method not implemented.');
  }
  minFontSize(size) {
    throw new Error('Method not implemented.');
  }
  minLogicalFontSize(size) {
    throw new Error('Method not implemented.');
  }
  blockNetwork(block) {
    throw new Error('Method not implemented.');
  }
  horizontalScrollBarAccess(horizontalScrollBar) {
    throw new Error('Method not implemented.');
  }
  verticalScrollBarAccess(verticalScrollBar) {
    throw new Error('Method not implemented.');
  }
  onTouchIconUrlReceived(callback) {
    throw new Error('Method not implemented.');
  }
  onFaviconReceived(callback) {
    throw new Error('Method not implemented.');
  }
  onPageVisible(callback) {
    throw new Error('Method not implemented.');
  }
  onDataResubmitted(callback) {
    throw new Error('Method not implemented.');
  }
  pinchSmooth(isEnabled) {
    throw new Error('Method not implemented.');
  }
  allowWindowOpenMethod(flag) {
    throw new Error('Method not implemented.');
  }
  onAudioStateChanged(callback) {
    throw new Error('Method not implemented.');
  }
  onFirstContentfulPaint(callback) {
    throw new Error('Method not implemented.');
  }
  onLoadIntercept(callback) {
    throw new Error('Method not implemented.');
  }
  onControllerAttached(callback) {
    throw new Error('Method not implemented.');
  }
  onOverScroll(callback) {
    throw new Error('Method not implemented.');
  }
  javaScriptOnDocumentStart(scripts) {
    throw new Error('Method not implemented.');
  }
  layoutMode(mode) {
    throw new Error('Method not implemented.');
  }
  nestedScroll(value) {
    throw new Error('Method not implemented.');
  }
  onOverrideUrlLoading(callback) {
    throw new Error('Method not implemented.');
  }
  enableNativeMediaPlayer(config) {
    throw new Error('Method not implemented.');
  }
  onRenderProcessNotResponding(callback) {
    throw new Error('Method not implemented.');
  }
  onRenderProcessResponding(callback) {
    throw new Error('Method not implemented.');
  }
  onViewportFitChanged(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Web !== undefined) {
  globalThis.Web.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkWebComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkXComponentComponent {
  constructor(nativePtr) {
    this._modifiersWithKeys = new Map();
    this.nativePtr = nativePtr;
  }
  applyModifierPatch() {
    let expiringItemsWithKeys = [];
    this._modifiersWithKeys.forEach((value, key) => {
      if (value.applyStage(this.nativePtr)) {
        expiringItemsWithKeys.push(key);
      }
    });
    expiringItemsWithKeys.forEach(key => {
      this._modifiersWithKeys.delete(key);
    });
  }
  outline(value) {
    throw new Error('Method not implemented.');
  }
  outlineColor(value) {
    throw new Error('Method not implemented.');
  }
  outlineRadius(value) {
    throw new Error('Method not implemented.');
  }
  outlineStyle(value) {
    throw new Error('Method not implemented.');
  }
  outlineWidth(value) {
    throw new Error('Method not implemented.');
  }
  width(value) {
    throw new Error('Method not implemented.');
  }
  height(value) {
    throw new Error('Method not implemented.');
  }
  expandSafeArea(types, edges) {
    throw new Error('Method not implemented.');
  }
  responseRegion(value) {
    throw new Error('Method not implemented.');
  }
  mouseResponseRegion(value) {
    throw new Error('Method not implemented.');
  }
  size(value) {
    throw new Error('Method not implemented.');
  }
  constraintSize(value) {
    throw new Error('Method not implemented.');
  }
  touchable(value) {
    throw new Error('Method not implemented.');
  }
  hitTestBehavior(value) {
    throw new Error('Method not implemented.');
  }
  layoutWeight(value) {
    throw new Error('Method not implemented.');
  }
  padding(value) {
    throw new Error('Method not implemented.');
  }
  margin(value) {
    throw new Error('Method not implemented.');
  }
  background(builder, options) {
    throw new Error('Method not implemented.');
  }
  backgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBackgroundColorModifier.identity, XComponentBackgroundColorModifier, value);
    return this;
  }
  backgroundImage(src, repeat) {
    let arkBackgroundImage = new ArkBackgroundImage();
    arkBackgroundImage.src = src;
    arkBackgroundImage.repeat = repeat;
    modifierWithKey(this._modifiersWithKeys, XComponentBackgroundImageModifier.identity, XComponentBackgroundImageModifier, arkBackgroundImage);
    return this;
  }
  backgroundImageSize(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBackgroundImageSizeModifier.identity, XComponentBackgroundImageSizeModifier, value);
    return this;
  }
  backgroundImagePosition(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBackgroundImagePositionModifier.identity, XComponentBackgroundImagePositionModifier, value);
    return this;
  }
  backgroundBlurStyle(value, options) {
    throw new Error('Method not implemented.');
  }
  foregroundBlurStyle(value, options) {
    throw new Error('Method not implemented.');
  }
  opacity(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentOpacityModifier.identity, XComponentOpacityModifier, value);
    return this;
  }
  border(value) {
    throw new Error('Method not implemented.');
  }
  borderStyle(value) {
    throw new Error('Method not implemented.');
  }
  borderWidth(value) {
    throw new Error('Method not implemented.');
  }
  borderColor(value) {
    throw new Error('Method not implemented.');
  }
  borderRadius(value) {
    throw new Error('Method not implemented.');
  }
  borderImage(value) {
    throw new Error('Method not implemented.');
  }
  foregroundColor(value) {
    throw new Error('Method not implemented.');
  }
  onClick(event) {
    throw new Error('Method not implemented.');
  }
  onHover(event) {
    throw new Error('Method not implemented.');
  }
  hoverEffect(value) {
    throw new Error('Method not implemented.');
  }
  onMouse(event) {
    throw new Error('Method not implemented.');
  }
  onTouch(event) {
    throw new Error('Method not implemented.');
  }
  onKeyEvent(event) {
    throw new Error('Method not implemented.');
  }
  focusable(value) {
    throw new Error('Method not implemented.');
  }
  onFocus(event) {
    throw new Error('Method not implemented.');
  }
  onBlur(event) {
    throw new Error('Method not implemented.');
  }
  tabIndex(index) {
    throw new Error('Method not implemented.');
  }
  defaultFocus(value) {
    throw new Error('Method not implemented.');
  }
  groupDefaultFocus(value) {
    throw new Error('Method not implemented.');
  }
  focusOnTouch(value) {
    throw new Error('Method not implemented.');
  }
  animation(value) {
    throw new Error('Method not implemented.');
  }
  transition(value) {
    throw new Error('Method not implemented.');
  }
  gesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  priorityGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  parallelGesture(gesture, mask) {
    throw new Error('Method not implemented.');
  }
  blur(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBlurModifier.identity, XComponentBlurModifier, value);
    return this;
  }
  linearGradientBlur(value, options) {
    if (isUndefined(value) || isNull(value) || isUndefined(options) || isNull(options)) {
      modifierWithKey(this._modifiersWithKeys, XComponentLinearGradientBlurModifier.identity, XComponentLinearGradientBlurModifier, undefined);
      return this;
    }
    let arkLinearGradientBlur = new ArkLinearGradientBlur();
    arkLinearGradientBlur.blurRadius = value;
    arkLinearGradientBlur.fractionStops = options.fractionStops;
    arkLinearGradientBlur.direction = options.direction;
    modifierWithKey(this._modifiersWithKeys, XComponentLinearGradientBlurModifier.identity, XComponentLinearGradientBlurModifier, arkLinearGradientBlur);
    return this;
  }
  brightness(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBrightnessModifier.identity, XComponentBrightnessModifier, value);
    return this;
  }
  contrast(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentContrastModifier.identity, XComponentContrastModifier, value);
    return this;
  }
  grayscale(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentGrayscaleModifier.identity, XComponentGrayscaleModifier, value);
    return this;
  }
  colorBlend(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentColorBlendModifier.identity, XComponentColorBlendModifier, value);
    return this;
  }
  saturate(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentSaturateModifier.identity, XComponentSaturateModifier, value);
    return this;
  }
  sepia(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentSepiaModifier.identity, XComponentSepiaModifier, value);
    return this;
  }
  invert(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentInvertModifier.identity, XComponentInvertModifier, value);
    return this;
  }
  hueRotate(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentHueRotateModifier.identity, XComponentHueRotateModifier, value);
    return this;
  }
  useEffect(value) {
    throw new Error('Method not implemented.');
  }
  backdropBlur(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentBackdropBlurModifier.identity, XComponentBackdropBlurModifier, value);
    return this;
  }
  renderGroup(value) {
    throw new Error('Method not implemented.');
  }
  translate(value) {
    throw new Error('Method not implemented.');
  }
  scale(value) {
    throw new Error('Method not implemented.');
  }
  gridSpan(value) {
    throw new Error('Method not implemented.');
  }
  gridOffset(value) {
    throw new Error('Method not implemented.');
  }
  rotate(value) {
    throw new Error('Method not implemented.');
  }
  transform(value) {
    throw new Error('Method not implemented.');
  }
  onAppear(event) {
    throw new Error('Method not implemented.');
  }
  onDisAppear(event) {
    throw new Error('Method not implemented.');
  }
  onAttach(event) {
    throw new Error('Method not implemented.');
  }
  onDetach(event) {
    throw new Error('Method not implemented.');
  }
  onAreaChange(event) {
    throw new Error('Method not implemented.');
  }
  visibility(value) {
    throw new Error('Method not implemented.');
  }
  flexGrow(value) {
    throw new Error('Method not implemented.');
  }
  flexShrink(value) {
    throw new Error('Method not implemented.');
  }
  flexBasis(value) {
    throw new Error('Method not implemented.');
  }
  alignSelf(value) {
    throw new Error('Method not implemented.');
  }
  displayPriority(value) {
    throw new Error('Method not implemented.');
  }
  zIndex(value) {
    throw new Error('Method not implemented.');
  }
  sharedTransition(id, options) {
    throw new Error('Method not implemented.');
  }
  direction(value) {
    throw new Error('Method not implemented.');
  }
  align(value) {
    throw new Error('Method not implemented.');
  }
  position(value) {
    throw new Error('Method not implemented.');
  }
  markAnchor(value) {
    throw new Error('Method not implemented.');
  }
  offset(value) {
    throw new Error('Method not implemented.');
  }
  enabled(value) {
    throw new Error('Method not implemented.');
  }
  useSizeType(value) {
    throw new Error('Method not implemented.');
  }
  alignRules(value) {
    throw new Error('Method not implemented.');
  }
  aspectRatio(value) {
    throw new Error('Method not implemented.');
  }
  clickEffect(value) {
    throw new Error('Method not implemented.');
  }
  onDragStart(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnter(event) {
    throw new Error('Method not implemented.');
  }
  onDragMove(event) {
    throw new Error('Method not implemented.');
  }
  onDragLeave(event) {
    throw new Error('Method not implemented.');
  }
  onDrop(event) {
    throw new Error('Method not implemented.');
  }
  onDragEnd(event) {
    throw new Error('Method not implemented.');
  }
  allowDrop(value) {
    throw new Error('Method not implemented.');
  }
  draggable(value) {
    throw new Error('Method not implemented.');
  }
  overlay(value, options) {
    throw new Error('Method not implemented.');
  }
  linearGradient(value) {
    throw new Error('Method not implemented.');
  }
  sweepGradient(value) {
    throw new Error('Method not implemented.');
  }
  radialGradient(value) {
    throw new Error('Method not implemented.');
  }
  motionPath(value) {
    throw new Error('Method not implemented.');
  }
  motionBlur(value) {
    throw new Error('Method not implemented.');
  }
  shadow(value) {
    modifierWithKey(this._modifiersWithKeys, ShadowModifier.identity, ShadowModifier, value);
    return this;
  }
  blendMode(value) {
    throw new Error('Method not implemented.');
  }
  clip(value) {
    throw new Error('Method not implemented.');
  }
  mask(value) {
    throw new Error('Method not implemented.');
  }
  key(value) {
    throw new Error('Method not implemented.');
  }
  id(value) {
    throw new Error('Method not implemented.');
  }
  geometryTransition(id) {
    throw new Error('Method not implemented.');
  }
  bindPopup(show, popup) {
    throw new Error('Method not implemented.');
  }
  bindMenu(content, options) {
    throw new Error('Method not implemented.');
  }
  bindContextMenu(content, responseType, options) {
    throw new Error('Method not implemented.');
  }
  bindContentCover(isShow, builder, options) {
    throw new Error('Method not implemented.');
  }
  bindSheet(isShow, builder, options) {
    throw new Error('Method not implemented.');
  }
  stateStyles(value) {
    throw new Error('Method not implemented.');
  }
  restoreId(value) {
    throw new Error('Method not implemented.');
  }
  onVisibleAreaChange(ratios, event) {
    throw new Error('Method not implemented.');
  }
  sphericalEffect(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentSphericalEffectModifier.identity, XComponentSphericalEffectModifier, value);
    return this;
  }
  lightUpEffect(value) {
    modifierWithKey(this._modifiersWithKeys, XComponentLightUpEffectModifier.identity, XComponentLightUpEffectModifier, value);
    return this;
  }
  pixelStretchEffect(options) {
    modifierWithKey(this._modifiersWithKeys, XComponentPixelStretchEffectModifier.identity, XComponentPixelStretchEffectModifier, options);
    return this;
  }
  keyboardShortcut(value, keys, action) {
    throw new Error('Method not implemented.');
  }
  accessibilityGroup(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityText(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityDescription(value) {
    throw new Error('Method not implemented.');
  }
  accessibilityLevel(value) {
    throw new Error('Method not implemented.');
  }
  obscured(reasons) {
    throw new Error('Method not implemented.');
  }
  reuseId(id) {
    throw new Error('Method not implemented.');
  }
  renderFit(fitMode) {
    throw new Error('Method not implemented.');
  }
  attributeModifier(modifier) {
    return this;
  }
  onGestureJudgeBegin(callback) {
    throw new Error('Method not implemented.');
  }
  onLoad(callback) {
    throw new Error('Method not implemented.');
  }
  onDestroy(event) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.XComponent !== undefined) {
  globalThis.XComponent.attributeModifier = function (modifier) {
    const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
    let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
    let component = this.createOrGetNode(elmtId, () => {
      return new ArkXComponentComponent(nativeNode);
    });
    applyUIAttributes(modifier, nativeNode, component);
    component.applyModifierPatch();
  };
  globalThis.DataPanel.contentModifier = function (style) {
      const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
      let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
      let component = this.createOrGetNode(elmtId, () => {
        return new ArkDataPanelComponent(nativeNode);
      });
    component.setContentModifier(style);
  };
}

class XComponentOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetOpacity(node);
    }
    else {
      getUINativeModule().xComponent.setOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
XComponentOpacityModifier.identity = Symbol('xComponentOpacity');
class XComponentBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetBackgroundColor(node);
    }
    else {
      getUINativeModule().xComponent.setBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
XComponentBackgroundColorModifier.identity = Symbol('xComponentBackgroundColor');
class XComponentBackgroundImageModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetBackgroundImage(node);
    }
    else {
      getUINativeModule().xComponent.setBackgroundImage(node, this.value.src, this.value.repeat);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.src === this.value.src &&
      this.stageValue.repeat === this.value.repeat);
  }
}
XComponentBackgroundImageModifier.identity = Symbol('xComponentBackgroundImage');
class XComponentBackgroundImageSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().xComponent.resetBackgroundImageSize(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().xComponent.setBackgroundImageSize(node, this.value, undefined, undefined);
      }
      else {
        getUINativeModule().xComponent.setBackgroundImageSize(node, undefined, (_a = this.value) === null ||
          _a === void 0 ? void 0 : _a.width, (_b = this.value) === null || _b === void 0 ? void 0 : _b.height);
      }
    }
  }
  checkObjectDiff() {
    return !(this.value.width === this.stageValue.width &&
      this.value.height === this.stageValue.height);
  }
}
XComponentBackgroundImageSizeModifier.identity = Symbol('xComponentBackgroundImageSize');
class XComponentBackgroundImagePositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().xComponent.resetBackgroundImagePosition(node);
    }
    else {
      if (isNumber(this.value)) {
        getUINativeModule().xComponent.setBackgroundImagePosition(node, this.value, undefined, undefined);
      }
      else {
        getUINativeModule().xComponent.setBackgroundImagePosition(node, undefined, (_a = this.value) === null ||
          _a === void 0 ? void 0 : _a.x, (_b = this.value) === null || _b === void 0 ? void 0 : _b.y);
      }
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d;
    return !(((_a = this.value) === null || _a === void 0 ? void 0 : _a.x) === ((_b = this.stageValue) === null || _b === void 0 ? void 0 : _b.x) &&
      ((_c = this.value) === null || _c === void 0 ? void 0 : _c.y) === ((_d = this.stageValue) === null || _d === void 0 ? void 0 : _d.y));
  }
}
XComponentBackgroundImagePositionModifier.identity = Symbol('xComponentBackgroundImagePosition');
class XComponentBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetBlur(node);
    }
    else {
      getUINativeModule().xComponent.setBlur(node, this.value);
    }
  }
}
XComponentBlurModifier.identity = Symbol('xComponentBlur');
class XComponentBackdropBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetBackdropBlur(node);
    }
    else {
      getUINativeModule().xComponent.setBackdropBlur(node, this.value);
    }
  }
}
XComponentBackdropBlurModifier.identity = Symbol('xComponentBackdropBlur');
class XComponentGrayscaleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetGrayscale(node);
    }
    else {
      getUINativeModule().xComponent.setGrayscale(node, this.value);
    }
  }
}
XComponentGrayscaleModifier.identity = Symbol('xComponentGrayscale');
class XComponentBrightnessModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetBrightness(node);
    }
    else {
      getUINativeModule().xComponent.setBrightness(node, this.value);
    }
  }
}
XComponentBrightnessModifier.identity = Symbol('xComponentBrightness');
class XComponentSaturateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetSaturate(node);
    }
    else {
      getUINativeModule().xComponent.setSaturate(node, this.value);
    }
  }
}
XComponentSaturateModifier.identity = Symbol('xComponentSaturate');
class XComponentContrastModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetContrast(node);
    }
    else {
      getUINativeModule().xComponent.setContrast(node, this.value);
    }
  }
}
XComponentContrastModifier.identity = Symbol('xComponentContrast');
class XComponentInvertModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetInvert(node);
    }
    else {
      getUINativeModule().xComponent.setInvert(node, this.value);
    }
  }
}
XComponentInvertModifier.identity = Symbol('xComponentInvert');
class XComponentSepiaModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetSepia(node);
    }
    else {
      getUINativeModule().xComponent.setSepia(node, this.value);
    }
  }
}
XComponentSepiaModifier.identity = Symbol('xComponentSepia');
class XComponentHueRotateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetHueRotate(node);
    }
    else {
      getUINativeModule().xComponent.setHueRotate(node, this.value);
    }
  }
}
XComponentHueRotateModifier.identity = Symbol('xComponentHueRotate');
class XComponentColorBlendModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetColorBlend(node);
    }
    else {
      getUINativeModule().xComponent.setColorBlend(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
XComponentColorBlendModifier.identity = Symbol('xComponentColorBlend');
class XComponentSphericalEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetSphericalEffect(node);
    }
    else {
      getUINativeModule().xComponent.setSphericalEffect(node, this.value);
    }
  }
}
XComponentSphericalEffectModifier.identity = Symbol('xComponentSphericalEffect');
class XComponentLightUpEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetLightUpEffect(node);
    }
    else {
      getUINativeModule().xComponent.setLightUpEffect(node, this.value);
    }
  }
}
XComponentLightUpEffectModifier.identity = Symbol('xComponentLightUpEffect');
class XComponentPixelStretchEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetPixelStretchEffect(node);
    }
    else {
      getUINativeModule().xComponent.setPixelStretchEffect(node, this.value.top, this.value.right, this.value.bottom, this.value.left);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.left === this.value.left &&
      this.stageValue.right === this.value.right &&
      this.stageValue.top === this.value.top &&
      this.stageValue.bottom === this.value.bottom);
  }
}
XComponentPixelStretchEffectModifier.identity = Symbol('xComponentPixelStretchEffect');
class XComponentLinearGradientBlurModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().xComponent.resetLinearGradientBlur(node);
    }
    else {
      getUINativeModule().xComponent.setLinearGradientBlur(node, this.value.blurRadius, this.value.fractionStops, this.value.direction);
    }
  }
  checkObjectDiff() {
    return !this.value.isEqual(this.stageValue);
  }
}
XComponentLinearGradientBlurModifier.identity = Symbol('xComponentlinearGradientBlur');
/// <reference path='./import.ts' />
class ArkBadgeComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.Badge !== undefined) {
  globalThis.Badge.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkBadgeComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkFlowItemComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.FlowItem !== undefined) {
  globalThis.FlowItem.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkFlowItemComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkFormLinkComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.FormLink !== undefined) {
  globalThis.FormLink.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkFormLinkComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class GridItemSelectableModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemSelectable(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemSelectable(node, this.value);
    }
  }
}
GridItemSelectableModifier.identity = Symbol('gridItemSelectable');
class GridItemSelectedModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemSelected(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemSelected(node, this.value);
    }
  }
}
GridItemSelectedModifier.identity = Symbol('gridItemSelected');
class GridItemRowStartModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemRowStart(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemRowStart(node, this.value);
    }
  }
}
GridItemRowStartModifier.identity = Symbol('gridItemRowStart');
class GridItemRowEndModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemRowEnd(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemRowEnd(node, this.value);
    }
  }
}
GridItemRowEndModifier.identity = Symbol('gridItemRowEnd');
class GridItemColumnStartModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemColumnStart(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemColumnStart(node, this.value);
    }
  }
}
GridItemColumnStartModifier.identity = Symbol('gridItemColumnStart');
class GridItemColumnEndModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().gridItem.resetGridItemColumnEnd(node);
    }
    else {
      getUINativeModule().gridItem.setGridItemColumnEnd(node, this.value);
    }
  }
}
GridItemColumnEndModifier.identity = Symbol('gridItemColumnEnd');
class ArkGridItemComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  rowStart(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemRowStartModifier.identity, GridItemRowStartModifier, value);
    return this;
  }
  rowEnd(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemRowEndModifier.identity, GridItemRowEndModifier, value);
    return this;
  }
  columnStart(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemColumnStartModifier.identity, GridItemColumnStartModifier, value);
    return this;
  }
  columnEnd(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemColumnEndModifier.identity, GridItemColumnEndModifier, value);
    return this;
  }
  forceRebuild(value) {
    throw new Error('Method not implemented.');
  }
  selectable(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemSelectableModifier.identity, GridItemSelectableModifier, value);
    return this;
  }
  selected(value) {
    modifierWithKey(this._modifiersWithKeys, GridItemSelectedModifier.identity, GridItemSelectedModifier, value);
    return this;
  }
  onSelect(event) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.GridItem !== undefined) {
  globalThis.GridItem.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGridItemComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.GridItemModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkHyperlinkComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  color(value) {
    modifierWithKey(this._modifiersWithKeys, HyperlinkColorModifier.identity, HyperlinkColorModifier, value);
    return this;
  }
  draggable(value) {
    modifierWithKey(this._modifiersWithKeys, HyperlinkDraggableModifier.identity, HyperlinkDraggableModifier, value);
    return this;
  }
}
class HyperlinkColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().hyperlink.resetColor(node);
    }
    else {
      getUINativeModule().hyperlink.setColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
HyperlinkColorModifier.identity = Symbol('hyperlinkColor');
class HyperlinkDraggableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().hyperlink.resetDraggable(node);
    }
    else {
      getUINativeModule().hyperlink.setDraggable(node, this.value);
    }
  }
}
HyperlinkDraggableModifier.identity = Symbol('hyperlinkDraggable');
// @ts-ignore
if (globalThis.Hyperlink !== undefined) {
  globalThis.Hyperlink.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkHyperlinkComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.HyperlinkModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ListEditModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetEditMode(node);
    }
    else {
      getUINativeModule().list.setEditMode(node, this.value);
    }
  }
}
ListEditModeModifier.identity = Symbol('editMode');
class ListMultiSelectableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetMultiSelectable(node);
    }
    else {
      getUINativeModule().list.setMultiSelectable(node, this.value);
    }
  }
}
ListMultiSelectableModifier.identity = Symbol('listMultiSelectable');
class ListAlignListItemModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetAlignListItem(node);
    }
    else {
      getUINativeModule().list.setAlignListItem(node, this.value);
    }
  }
}
ListAlignListItemModifier.identity = Symbol('listAlignListItem');
class ListScrollSnapAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetScrollSnapAlign(node);
    }
    else {
      getUINativeModule().list.setScrollSnapAlign(node, this.value);
    }
  }
}
ListScrollSnapAlignModifier.identity = Symbol('listScrollSnapAlign');
class ContentStartOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetContentStartOffset(node);
    }
    else {
      getUINativeModule().list.setContentStartOffset(node, this.value);
    }
  }
}
ContentStartOffsetModifier.identity = Symbol('contentStartOffset');
class ContentEndOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetContentEndOffset(node);
    }
    else {
      getUINativeModule().list.setContentEndOffset(node, this.value);
    }
  }
}
ContentEndOffsetModifier.identity = Symbol('contentEndOffset');
class ListDividerModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d;
    if (reset) {
      getUINativeModule().list.resetDivider(node);
    }
    else {
      getUINativeModule().list.setDivider(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.strokeWidth, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.color, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.startMargin, (_d = this.value) === null ||
      _d === void 0 ? void 0 : _d.endMargin);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    return !(((_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.strokeWidth) === ((_b = this.value) === null || _b === void 0 ? void 0 : _b.strokeWidth) &&
      ((_c = this.stageValue) === null || _c === void 0 ? void 0 : _c.color) === ((_d = this.value) === null || _d === void 0 ? void 0 : _d.color) &&
      ((_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.startMargin) === ((_f = this.value) === null || _f === void 0 ? void 0 : _f.startMargin) &&
      ((_g = this.stageValue) === null || _g === void 0 ? void 0 : _g.endMargin) === ((_h = this.value) === null || _h === void 0 ? void 0 : _h.endMargin));
  }
}
ListDividerModifier.identity = Symbol('listDivider');
class ChainAnimationOptionsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e, _f, _g;
    if (reset) {
      getUINativeModule().list.resetChainAnimationOptions(node);
    }
    else {
      getUINativeModule().list.setChainAnimationOptions(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.minSpace, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.maxSpace, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.conductivity, (_d = this.value) === null ||
      _d === void 0 ? void 0 : _d.intensity, (_e = this.value) === null ||
      _e === void 0 ? void 0 : _e.edgeEffect, (_f = this.value) === null ||
      _f === void 0 ? void 0 : _f.stiffness, (_g = this.value) === null ||
      _g === void 0 ? void 0 : _g.damping);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.minSpace === this.value.minSpace && this.stageValue.maxSpace === this.value.maxSpace &&
      this.stageValue.conductivity === this.value.conductivity && this.stageValue.intensity === this.value.intensity &&
      this.stageValue.edgeEffect === this.value.edgeEffect && this.stageValue.stiffness === this.value.stiffness &&
      this.stageValue.damping === this.value.damping);
  }
}
ChainAnimationOptionsModifier.identity = Symbol('chainAnimationOptions');
class ListChainAnimationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetChainAnimation(node);
    }
    else {
      getUINativeModule().list.setChainAnimation(node, this.value);
    }
  }
}
ListChainAnimationModifier.identity = Symbol('listChainAnimation');
class ListCachedCountModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetCachedCount(node);
    }
    else {
      getUINativeModule().list.setCachedCount(node, this.value);
    }
  }
}
ListCachedCountModifier.identity = Symbol('listCachedCount');
class ListEnableScrollInteractionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetEnableScrollInteraction(node);
    }
    else {
      getUINativeModule().list.setEnableScrollInteraction(node, this.value);
    }
  }
}
ListEnableScrollInteractionModifier.identity = Symbol('listEnableScrollInteraction');
class ListStickyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetSticky(node);
    }
    else {
      getUINativeModule().list.setSticky(node, this.value);
    }
  }
}
ListStickyModifier.identity = Symbol('listSticky');
class ListEdgeEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a;
    if (reset) {
      getUINativeModule().list.resetListEdgeEffect(node);
    }
    else {
      getUINativeModule().list.setListEdgeEffect(node, this.value.value, (_a = this.value.options) === null ||
      _a === void 0 ? void 0 : _a.alwaysEnabled);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
ListEdgeEffectModifier.identity = Symbol('listEdgeEffect');
class ListListDirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetListDirection(node);
    }
    else {
      getUINativeModule().list.setListDirection(node, this.value);
    }
  }
}
ListListDirectionModifier.identity = Symbol('listListDirection');
class ListFrictionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetListFriction(node);
    }
    else {
      if (!isNumber(this.value) && !isResource(this.value)) {
        getUINativeModule().list.resetListFriction(node);
      }
      else {
        getUINativeModule().list.setListFriction(node, this.value);
      }
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ListFrictionModifier.identity = Symbol('listFriction');
class ListNestedScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().list.resetListNestedScroll(node);
    }
    else {
      getUINativeModule().list.setListNestedScroll(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.scrollForward, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.scrollBackward);
    }
  }
}
ListNestedScrollModifier.identity = Symbol('listNestedScroll');
class ListScrollBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetListScrollBar(node);
    }
    else {
      getUINativeModule().list.setListScrollBar(node, this.value);
    }
  }
}
ListScrollBarModifier.identity = Symbol('listScrollBar');
class ListLanesModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetListLanes(node);
    }
    else {
      getUINativeModule().list.setListLanes(node, this.value.lanesNum, this.value.minLength, this.value.maxLength, this.value.gutter);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ListLanesModifier.identity = Symbol('listLanes');
class ListClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
ListClipModifier.identity = Symbol('listClip');
class ListFadingEdgeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetFadingEdge(node);
    }
    else {
      getUINativeModule().list.setFadingEdge(node, this.value);
    }
  }
}
ListFadingEdgeModifier.identity = Symbol('fadingEdge');

class ListSpaceModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetSpace(node);
    }
    else {
      getUINativeModule().list.setSpace(node, this.value);
    }
  }
}
ListSpaceModifier.identity = Symbol('listSpace');

class ListInitialIndexModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().list.resetInitialIndex(node);
    }
    else {
      getUINativeModule().list.setInitialIndex(node, this.value);
    }
  }
}
ListInitialIndexModifier.identity = Symbol('listInitialIndex');

class ArkListComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }

  initialize(value) {
    if (value[0] !== undefined) {
      if (value[0].initialIndex !== undefined) {
        modifierWithKey(this._modifiersWithKeys, ListInitialIndexModifier.identity, ListInitialIndexModifier, value[0].initialIndex);
      }
      if (value[0].space !== undefined) {
        modifierWithKey(this._modifiersWithKeys, ListSpaceModifier.identity, ListSpaceModifier, value[0].space);
      }
    }
    return this;
  }

  lanes(value, gutter) {
    let opt = new ArkLanesOpt();
    opt.gutter = gutter;
    if (isUndefined(value)) {
      opt.lanesNum = undefined;
    }
    else if (isNumber(value)) {
      opt.lanesNum = value;
    }
    else {
      const lc = value;
      opt.minLength = lc.minLength;
      opt.maxLength = lc.maxLength;
    }
    modifierWithKey(this._modifiersWithKeys, ListLanesModifier.identity, ListLanesModifier, opt);
    return this;
  }
  alignListItem(value) {
    modifierWithKey(this._modifiersWithKeys, ListAlignListItemModifier.identity, ListAlignListItemModifier, value);
    return this;
  }
  listDirection(value) {
    modifierWithKey(this._modifiersWithKeys, ListListDirectionModifier.identity, ListListDirectionModifier, value);
    return this;
  }
  scrollBar(value) {
    modifierWithKey(this._modifiersWithKeys, ListScrollBarModifier.identity, ListScrollBarModifier, value);
    return this;
  }
  edgeEffect(value, options) {
    let effect = new ArkListEdgeEffect();
    effect.value = value;
    effect.options = options;
    modifierWithKey(this._modifiersWithKeys, ListEdgeEffectModifier.identity, ListEdgeEffectModifier, effect);
    return this;
  }
  contentStartOffset(value) {
    modifierWithKey(this._modifiersWithKeys, ContentStartOffsetModifier.identity, ContentStartOffsetModifier, value);
    return this;
  }
  contentEndOffset(value) {
    modifierWithKey(this._modifiersWithKeys, ContentEndOffsetModifier.identity, ContentEndOffsetModifier, value);
    return this;
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, ListDividerModifier.identity, ListDividerModifier, value);
    return this;
  }
  editMode(value) {
    modifierWithKey(this._modifiersWithKeys, ListEditModeModifier.identity, ListEditModeModifier, value);
    return this;
  }
  multiSelectable(value) {
    modifierWithKey(this._modifiersWithKeys, ListMultiSelectableModifier.identity, ListMultiSelectableModifier, value);
    return this;
  }
  cachedCount(value) {
    modifierWithKey(this._modifiersWithKeys, ListCachedCountModifier.identity, ListCachedCountModifier, value);
    return this;
  }
  chainAnimation(value) {
    modifierWithKey(this._modifiersWithKeys, ListChainAnimationModifier.identity, ListChainAnimationModifier, value);
    return this;
  }
  chainAnimationOptions(value) {
    modifierWithKey(this._modifiersWithKeys, ChainAnimationOptionsModifier.identity, ChainAnimationOptionsModifier, value);
    return this;
  }
  sticky(value) {
    modifierWithKey(this._modifiersWithKeys, ListStickyModifier.identity, ListStickyModifier, value);
    return this;
  }
  scrollSnapAlign(value) {
    modifierWithKey(this._modifiersWithKeys, ListScrollSnapAlignModifier.identity, ListScrollSnapAlignModifier, value);
    return this;
  }
  nestedScroll(value) {
    modifierWithKey(this._modifiersWithKeys, ListNestedScrollModifier.identity, ListNestedScrollModifier, value);
    return this;
  }
  enableScrollInteraction(value) {
    modifierWithKey(this._modifiersWithKeys, ListEnableScrollInteractionModifier.identity, ListEnableScrollInteractionModifier, value);
    return this;
  }
  friction(value) {
    modifierWithKey(this._modifiersWithKeys, ListFrictionModifier.identity, ListFrictionModifier, value);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, ListClipModifier.identity, ListClipModifier, value);
    return this;
  }
  onScroll(event) {
    throw new Error('Method not implemented.');
  }
  onScrollIndex(event) {
    throw new Error('Method not implemented.');
  }
  onReachStart(event) {
    throw new Error('Method not implemented.');
  }
  onReachEnd(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStart(event) {
    throw new Error('Method not implemented.');
  }
  onScrollStop(event) {
    throw new Error('Method not implemented.');
  }
  onItemDelete(event) {
    throw new Error('Method not implemented.');
  }
  onItemMove(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragStart(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragEnter(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragMove(event) {
    throw new Error('Method not implemented.');
  }
  onItemDragLeave(event) {
    throw new Error('Method not implemented.');
  }
  onItemDrop(event) {
    throw new Error('Method not implemented.');
  }
  onScrollFrameBegin(event) {
    throw new Error('Method not implemented.');
  }
  fadingEdge(value) {
    modifierWithKey(this._modifiersWithKeys, ListFadingEdgeModifier.identity, ListFadingEdgeModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.List !== undefined) {
  globalThis.List.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkListComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ListModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ListItemSelectedModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().listItem.resetListItemSelected(node);
    }
    else {
      getUINativeModule().listItem.setListItemSelected(node, this.value);
    }
  }
}
ListItemSelectedModifier.identity = Symbol('listItemSelected');
class ListItemSelectableModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().listItem.resetSelectable(node);
    }
    else {
      getUINativeModule().listItem.setSelectable(node, this.value);
    }
  }
}
ListItemSelectableModifier.identity = Symbol('listItemSelectable');
class ArkListItemComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    return this;
  }
  sticky(value) {
    throw new Error('Method not implemented.');
  }
  editable(value) {
    throw new Error('Method not implemented.');
  }
  selectable(value) {
    modifierWithKey(this._modifiersWithKeys, ListItemSelectableModifier.identity, ListItemSelectableModifier, value);
    return this;
  }
  selected(value) {
    modifierWithKey(this._modifiersWithKeys, ListItemSelectedModifier.identity, ListItemSelectedModifier, value);
    return this;
  }
  swipeAction(value) {
    throw new Error('Method not implemented.');
  }
  onSelect(event) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.ListItem !== undefined) {
  globalThis.ListItem.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkListItemComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ListItemModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ListItemGroupDividerModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b, _c, _d;
    if (reset) {
      getUINativeModule().listItemGroup.resetDivider(node);
    }
    else {
      getUINativeModule().listItemGroup.setDivider(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.strokeWidth, (_b = this.value) === null ||
      _b === void 0 ? void 0 : _b.color, (_c = this.value) === null ||
      _c === void 0 ? void 0 : _c.startMargin, (_d = this.value) === null ||
      _d === void 0 ? void 0 : _d.endMargin);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d, _e, _f, _g, _h;
    return !(((_a = this.stageValue) === null || _a === void 0 ? void 0 : _a.strokeWidth) === ((_b = this.value) === null || _b === void 0 ? void 0 : _b.strokeWidth) &&
      ((_c = this.stageValue) === null || _c === void 0 ? void 0 : _c.color) === ((_d = this.value) === null || _d === void 0 ? void 0 : _d.color) &&
      ((_e = this.stageValue) === null || _e === void 0 ? void 0 : _e.startMargin) === ((_f = this.value) === null || _f === void 0 ? void 0 : _f.startMargin) &&
      ((_g = this.stageValue) === null || _g === void 0 ? void 0 : _g.endMargin) === ((_h = this.value) === null || _h === void 0 ? void 0 : _h.endMargin));
  }
}
ListItemGroupDividerModifier.identity = Symbol('listItemGroupDivider');
class ArkListItemGroupComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, ListItemGroupDividerModifier.identity, ListItemGroupDividerModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.ListItemGroup !== undefined) {
  globalThis.ListItemGroup.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkListItemGroupComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ListItemGroupModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkRelativeContainerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.RelativeContainer !== undefined) {
  globalThis.RelativeContainer.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRelativeContainerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RelativeContainerModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkSwiperComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, SwiperInitializeModifier.identity, SwiperInitializeModifier, value[0]);
    }
    return this;
  }
  index(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperIndexModifier.identity, SwiperIndexModifier, value);
    return this;
  }
  autoPlay(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperAutoPlayModifier.identity, SwiperAutoPlayModifier, value);
    return this;
  }
  interval(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperIntervalModifier.identity, SwiperIntervalModifier, value);
    return this;
  }
  indicator(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperIndicatorModifier.identity, SwiperIndicatorModifier, value);
    return this;
  }
  displayArrow(value, isHoverShow) {
    let arkDisplayArrow = new ArkDisplayArrow();
    arkDisplayArrow.value = value;
    arkDisplayArrow.isHoverShow = isHoverShow;
    modifierWithKey(this._modifiersWithKeys, SwiperDisplayArrowModifier.identity, SwiperDisplayArrowModifier, arkDisplayArrow);
    return this;
  }
  loop(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperLoopModifier.identity, SwiperLoopModifier, value);
    return this;
  }
  duration(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperDurationModifier.identity, SwiperDurationModifier, value);
    return this;
  }
  vertical(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperVerticalModifier.identity, SwiperVerticalModifier, value);
    return this;
  }
  itemSpace(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperItemSpaceModifier.identity, SwiperItemSpaceModifier, value);
    return this;
  }
  displayMode(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperDisplayModeModifier.identity, SwiperDisplayModeModifier, value);
    return this;
  }
  cachedCount(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperCachedCountModifier.identity, SwiperCachedCountModifier, value);
    return this;
  }
  displayCount(value, swipeByGroup) {
    let arkDisplayCount = new ArkDisplayCount();
    arkDisplayCount.value = value;
    arkDisplayCount.swipeByGroup = swipeByGroup;
    modifierWithKey(this._modifiersWithKeys, SwiperDisplayCountModifier.identity, SwiperDisplayCountModifier, arkDisplayCount);
    return this;
  }
  effectMode(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperEffectModeModifier.identity, SwiperEffectModeModifier, value);
    return this;
  }
  disableSwipe(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperDisableSwipeModifier.identity, SwiperDisableSwipeModifier, value);
    return this;
  }
  curve(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperCurveModifier.identity, SwiperCurveModifier, value);
    return this;
  }
  onChange(event) {
    throw new Error('Method not implemented.');
  }
  indicatorStyle(value) {
    throw new Error('Method not implemented.');
  }
  prevMargin(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperPrevMarginModifier.identity, SwiperPrevMarginModifier, value);
    return this;
  }
  nextMargin(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperNextMarginModifier.identity, SwiperNextMarginModifier, value);
    return this;
  }
  enabled(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperEnabledModifier.identity, SwiperEnabledModifier, value);
    return this;
  }
  onAnimationStart(event) {
    throw new Error('Method not implemented.');
  }
  onAnimationEnd(event) {
    throw new Error('Method not implemented.');
  }
  onGestureSwipe(event) {
    throw new Error('Method not implemented.');
  }
  nestedScroll(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperNestedScrollModifier.identity, SwiperNestedScrollModifier, value);
    return this;
  }
  indicatorInteractive(value) {
    modifierWithKey(this._modifiersWithKeys, SwiperIndicatorInteractiveModifier.identity, SwiperIndicatorInteractiveModifier, value);
    return this;
  }
}
class SwiperInitializeModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperInitialize(node);
    }
    else {
      getUINativeModule().swiper.setSwiperInitialize(node, this.value);
    }
  }
}
SwiperInitializeModifier.identity = Symbol('swiperInitialize');
class SwiperNextMarginModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperNextMargin(node);
    }
    else {
      getUINativeModule().swiper.setSwiperNextMargin(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperNextMarginModifier.identity = Symbol('swiperNextMargin');
class SwiperPrevMarginModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperPrevMargin(node);
    }
    else {
      getUINativeModule().swiper.setSwiperPrevMargin(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperPrevMarginModifier.identity = Symbol('swiperPrevMargin');
class SwiperDisplayCountModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperSwipeByGroup(node);
      getUINativeModule().swiper.resetSwiperDisplayCount(node);
    }
    else {
      if (!isNull(this.value) && !isUndefined(this.value)) {
        let swipeByGroup;
        if (typeof this.value.swipeByGroup === 'boolean') {
          swipeByGroup = this.value.swipeByGroup;
        }

        getUINativeModule().swiper.setSwiperSwipeByGroup(node, swipeByGroup);

        if (typeof this.value.value === 'object') {
          let minSize = this.value.value.minSize.toString();
          getUINativeModule().swiper.setSwiperDisplayCount(node, minSize, typeof this.value.value);
        } else {
          getUINativeModule().swiper.setSwiperDisplayCount(node, this.value.value, typeof this.value.value, swipeByGroup);
        }
      } else {
        getUINativeModule().swiper.resetSwiperSwipeByGroup(node);
        getUINativeModule().swiper.resetSwiperDisplayCount(node);
      }
    }
  }
  checkObjectDiff() {
    if (this.stageValue.swipeByGroup !== this.value.swipeByGroup ||
      typeof this.stageValue.value !== typeof this.value.value) {
      return true;
    }
    else if (typeof this.stageValue.value === 'object' &&
      typeof this.value.value === 'object') {
      return this.stageValue.value.minSize !== this.value.value.minSize;
    }
    else {
      return !isBaseOrResourceEqual(this.stageValue.value, this.value.value);
    }
  }
}
SwiperDisplayCountModifier.identity = Symbol('swiperDisplayCount');
class SwiperDisplayArrowModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperDisplayArrow(node);
    }
    else {
      if (!isNull(this.value.value) && !isUndefined(this.value.value) && typeof this.value === 'object') {
        let displayArrowValue = 3;
        let showBackground;
        let isSidebarMiddle;
        let backgroundSize;
        let backgroundColor;
        let arrowSize;
        let arrowColor;
        if (typeof this.value.value === 'boolean') {
          if (this.value.value) {
            displayArrowValue = 1;
          }
          else {
            displayArrowValue = 0;
          }
        }
        else if (typeof this.value.value === 'object') {
          displayArrowValue = 2;
          showBackground = this.value.value.showBackground;
          isSidebarMiddle = this.value.value.isSidebarMiddle;
          backgroundSize = this.value.value.backgroundSize;
          backgroundColor = this.value.value.backgroundColor;
          arrowSize = this.value.value.arrowSize;
          arrowColor = this.value.value.arrowColor;
        }
        let isHoverShow;
        if (typeof this.value.isHoverShow === 'boolean') {
          isHoverShow = this.value.isHoverShow;
        }
        getUINativeModule().swiper.setSwiperDisplayArrow(node, displayArrowValue, showBackground,
          isSidebarMiddle, backgroundSize, backgroundColor, arrowSize, arrowColor, isHoverShow);
      }
      else {
        getUINativeModule().swiper.resetSwiperDisplayArrow(node);
      }
    }
  }
  checkObjectDiff() {
    if (this.stageValue.isHoverShow !== this.value.isHoverShow ||
      typeof this.stageValue.value !== typeof this.value.value) {
      return true;
    }
    if (typeof this.stageValue.value === 'boolean' &&
      typeof this.value.value === 'boolean' &&
      this.stageValue.value !== this.value.value) {
      return true;
    }
    else if (typeof this.stageValue.value === 'object' && typeof this.value.value === 'object') {
      return (!isBaseOrResourceEqual(this.stageValue.value.showBackground, this.value.value.showBackground) ||
        !isBaseOrResourceEqual(this.stageValue.value.isSidebarMiddle, this.value.value.isSidebarMiddle) ||
        !isBaseOrResourceEqual(this.stageValue.value.backgroundSize, this.value.value.backgroundSize) ||
        !isBaseOrResourceEqual(this.stageValue.value.backgroundColor, this.value.value.backgroundColor) ||
        !isBaseOrResourceEqual(this.stageValue.value.arrowSize, this.value.value.arrowSize) ||
        !isBaseOrResourceEqual(this.stageValue.value.arrowColor, this.value.value.arrowColor));
    }
    else {
      return true;
    }
  }
}
SwiperDisplayArrowModifier.identity = Symbol('swiperDisplayArrow');
class SwiperIndicatorModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperIndicator(node);
    }
    else {
      let left;
      let top;
      let right;
      let bottom;
      let itemWidth;
      let itemHeight;
      let selectedItemWidth;
      let selectedItemHeight;
      let mask;
      let color;
      let selectedColor;
      let fontColor;
      let selectedFontColor;
      let digitFontSize;
      let digitFontWeight;
      let selectedDigitFontSize;
      let selectedDigitFontWeight;
      if (typeof this.value === 'boolean') {
        getUINativeModule().swiper.setSwiperIndicator(node, 'boolean', this.value);
      }
      else if (typeof this.value === 'object' && this.value.type === 'DotIndicator') {
        left = this.value.leftValue;
        top = this.value.topValue;
        right = this.value.rightValue;
        bottom = this.value.bottomValue;
        itemWidth = this.value.itemWidthValue;
        itemHeight = this.value.itemHeightValue;
        selectedItemWidth = this.value.selectedItemWidthValue;
        selectedItemHeight = this.value.selectedItemHeightValue;
        mask = this.value.maskValue;
        color = this.value.colorValue;
        selectedColor = this.value.selectedColorValue;
        getUINativeModule().swiper.setSwiperIndicator(node, 'ArkDotIndicator', itemWidth, itemHeight, selectedItemWidth,
          selectedItemHeight, mask, color, selectedColor, left, top, right, bottom);
      }
      else if (typeof this.value === 'object' && this.value.type === 'DigitIndicator') {
        left = this.value.leftValue;
        top = this.value.topValue;
        right = this.value.rightValue;
        bottom = this.value.bottomValue;
        fontColor = this.value.fontColorValue;
        selectedFontColor = this.value.selectedFontColorValue;
        let arkDigitFont = new ArkDigitFont();
        if (typeof this.value.digitFontValue === 'object') {
          digitFontSize = this.value.digitFontValue.size;
          digitFontWeight = arkDigitFont.parseFontWeight(this.value.digitFontValue.weight);
        }
        if (typeof this.value.selectedDigitFontValue === 'object') {
          selectedDigitFontSize = this.value.selectedDigitFontValue.size;
          selectedDigitFontWeight = arkDigitFont.parseFontWeight(this.value.selectedDigitFontValue.weight);
        }
        getUINativeModule().swiper.setSwiperIndicator(node, 'ArkDigitIndicator', fontColor, selectedFontColor, digitFontSize,
          digitFontWeight, selectedDigitFontSize, selectedDigitFontWeight, left, top, right, bottom);
      }
      else {
        getUINativeModule().swiper.setSwiperIndicator(node, 'boolean', true);
      }
    }
  }
  checkObjectDiff() {
    if (typeof this.stageValue !== typeof this.value) {
      return true;
    }
    if (typeof this.stageValue === 'boolean' && typeof this.value === 'boolean') {
      return this.stageValue !== this.value;
    }
    if (this.stageValue instanceof ArkDotIndicator && this.value instanceof ArkDotIndicator) {
      return (!isBaseOrResourceEqual(this.stageValue.itemWidthValue, this.value.itemWidthValue) ||
        !isBaseOrResourceEqual(this.stageValue.itemHeightValue, this.value.itemHeightValue) ||
        !isBaseOrResourceEqual(this.stageValue.selectedItemWidthValue, this.value.selectedItemWidthValue) ||
        !isBaseOrResourceEqual(this.stageValue.selectedItemHeightValue, this.value.selectedItemHeightValue) ||
        !isBaseOrResourceEqual(this.stageValue.maskValue, this.value.maskValue) ||
        !isBaseOrResourceEqual(this.stageValue.colorValue, this.value.colorValue) ||
        !isBaseOrResourceEqual(this.stageValue.selectedColorValue, this.value.selectedColorValue));
    }
    else if (this.stageValue instanceof ArkDigitIndicator && this.value instanceof ArkDigitIndicator) {
      return (!isBaseOrResourceEqual(this.stageValue.fontColorValue, this.value.fontColorValue) ||
        !isBaseOrResourceEqual(this.stageValue.selectedFontColorValue, this.value.selectedFontColorValue) ||
        !isBaseOrResourceEqual(this.stageValue.digitFontValue.size, this.value.digitFontValue.size) ||
        !isBaseOrResourceEqual(this.stageValue.digitFontValue.weight, this.value.digitFontValue.weight) ||
        !isBaseOrResourceEqual(this.stageValue.selectedDigitFontValue.size, this.value.selectedDigitFontValue.size) ||
        !isBaseOrResourceEqual(this.stageValue.selectedDigitFontValue.weight, this.value.selectedDigitFontValue.weight));
    }
    else {
      return true;
    }
  }
}
SwiperIndicatorModifier.identity = Symbol('swiperIndicator');
class SwiperCurveModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperCurve(node);
    }
    else {
      const curveMap = {
        [0]: 'linear',
        [1]: 'ease',
        [2]: 'ease-in',
        [3]: 'ease-out',
        [4]: 'ease-in-out',
        [5]: 'fast-out-slow-in',
        [6]: 'linear-out-slow-in',
        [7]: 'fast-out-linear-in',
        [8]: 'extreme-deceleration',
        [9]: 'sharp',
        [10]: 'rhythm',
        [11]: 'smooth',
        [12]: 'friction'
      };
      if (typeof this.value === 'number') {
        if (this.value in curveMap) {
          this.value = curveMap[this.value];
        }
        else {
          this.value = this.value.toString();
        }
      }
      getUINativeModule().swiper.setSwiperCurve(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperCurveModifier.identity = Symbol('swiperCurve');
class SwiperDisableSwipeModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperDisableSwipe(node);
    }
    else {
      getUINativeModule().swiper.setSwiperDisableSwipe(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperDisableSwipeModifier.identity = Symbol('swiperDisableSwipe');
class SwiperEffectModeModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperEffectMode(node);
    }
    else {
      getUINativeModule().swiper.setSwiperEffectMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperEffectModeModifier.identity = Symbol('swiperEffectMode');
class SwiperCachedCountModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperCachedCount(node);
    }
    else {
      getUINativeModule().swiper.setSwiperCachedCount(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperCachedCountModifier.identity = Symbol('swiperCachedCount');
class SwiperDisplayModeModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperDisplayMode(node);
    }
    else {
      getUINativeModule().swiper.setSwiperDisplayMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperDisplayModeModifier.identity = Symbol('swiperDisplayMode');
class SwiperItemSpaceModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperItemSpace(node);
    }
    else {
      getUINativeModule().swiper.setSwiperItemSpace(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperItemSpaceModifier.identity = Symbol('swiperItemSpace');
class SwiperVerticalModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperVertical(node);
    }
    else {
      getUINativeModule().swiper.setSwiperVertical(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperVerticalModifier.identity = Symbol('swiperVertical');
class SwiperLoopModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperLoop(node);
    }
    else {
      getUINativeModule().swiper.setSwiperLoop(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperLoopModifier.identity = Symbol('swiperLoop');
class SwiperIntervalModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperInterval(node);
    }
    else {
      getUINativeModule().swiper.setSwiperInterval(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperIntervalModifier.identity = Symbol('swiperInterval');
class SwiperAutoPlayModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperAutoPlay(node);
    }
    else {
      getUINativeModule().swiper.setSwiperAutoPlay(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperAutoPlayModifier.identity = Symbol('swiperAutoPlay');
class SwiperIndexModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperIndex(node);
    }
    else {
      getUINativeModule().swiper.setSwiperIndex(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperIndexModifier.identity = Symbol('swiperIndex');
class SwiperDurationModifier extends ModifierWithKey {
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperDuration(node);
    }
    else {
      getUINativeModule().swiper.setSwiperDuration(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperDurationModifier.identity = Symbol('swiperDuration');
class SwiperEnabledModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetSwiperEnabled(node);
    }
    else {
      getUINativeModule().swiper.setSwiperEnabled(node, this.value);
    }
  }
}
SwiperEnabledModifier.identity = Symbol('swiperenabled');
class SwiperNestedScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetNestedScroll(node);
    } else {
      getUINativeModule().swiper.setNestedScroll(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SwiperNestedScrollModifier.identity = Symbol('nestedScroll');
class SwiperIndicatorInteractiveModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().swiper.resetIndicatorInteractive(node);
    } else {
      getUINativeModule().swiper.setIndicatorInteractive(node, this.value);
    }
  }
}
SwiperIndicatorInteractiveModifier.identity = Symbol('indicatorInteractive');
// @ts-ignore
if (globalThis.Swiper !== undefined) {
  globalThis.Swiper.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSwiperComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SwiperModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkTabsComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onAnimationStart(handler) {
    throw new Error('Method not implemented.');
  }
  onAnimationEnd(handler) {
    throw new Error('Method not implemented.');
  }
  onGestureSwipe(handler) {
    throw new Error('Method not implemented.');
  }
  vertical(value) {
    modifierWithKey(this._modifiersWithKeys, TabsVerticalModifier.identity, TabsVerticalModifier, value);
    return this;
  }
  barPosition(value) {
    modifierWithKey(this._modifiersWithKeys, BarPositionModifier.identity, BarPositionModifier, value);
    return this;
  }
  scrollable(value) {
    modifierWithKey(this._modifiersWithKeys, ScrollableModifier.identity, ScrollableModifier, value);
    return this;
  }
  barMode(value, options) {
    let arkBarMode = new ArkBarMode();
    arkBarMode.barMode = value;
    arkBarMode.options = options;
    modifierWithKey(this._modifiersWithKeys, TabBarModeModifier.identity, TabBarModeModifier, arkBarMode);
    return this;
  }
  barWidth(value) {
    modifierWithKey(this._modifiersWithKeys, BarWidthModifier.identity, BarWidthModifier, value);
    return this;
  }
  barHeight(value) {
    if (isUndefined(value) || isNull(value)) {
      modifierWithKey(this._modifiersWithKeys, BarHeightModifier.identity, BarHeightModifier, undefined);
    }
    else {
      modifierWithKey(this._modifiersWithKeys, BarHeightModifier.identity, BarHeightModifier, value);
    }
    return this;
  }
  animationDuration(value) {
    modifierWithKey(this._modifiersWithKeys, AnimationDurationModifier.identity, AnimationDurationModifier, value);
    return this;
  }
  animationMode(value) {
    modifierWithKey(this._modifiersWithKeys, AnimationModeModifier.identity, AnimationModeModifier, value);
    return this;
  }
  onChange(event) {
    throw new Error('Method not implemented.');
  }
  onTabBarClick(event) {
    throw new Error('Method not implemented.');
  }
  fadingEdge(value) {
    modifierWithKey(this._modifiersWithKeys, FadingEdgeModifier.identity, FadingEdgeModifier, value);
    return this;
  }
  divider(value) {
    modifierWithKey(this._modifiersWithKeys, TabsDividerModifier.identity, TabsDividerModifier, value);
    return this;
  }
  barOverlap(value) {
    modifierWithKey(this._modifiersWithKeys, BarOverlapModifier.identity, BarOverlapModifier, value);
    return this;
  }
  barBackgroundColor(value) {
    modifierWithKey(this._modifiersWithKeys, BarBackgroundColorModifier.identity, BarBackgroundColorModifier, value);
    return this;
  }
  barBackgroundBlurStyle(value) {
    modifierWithKey(this._modifiersWithKeys, BarBackgroundBlurStyleModifier.identity, BarBackgroundBlurStyleModifier, value);
    return this;
  }
  barGridAlign(value) {
    modifierWithKey(this._modifiersWithKeys, BarGridAlignModifier.identity, BarGridAlignModifier, value);
    return this;
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, TabClipModifier.identity, TabClipModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, TabWidthModifier.identity, TabWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, TabHeightModifier.identity, TabHeightModifier, value);
    return this;
  }
}
class BarGridAlignModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetBarGridAlign(node);
    }
    else {
      getUINativeModule().tabs.setBarGridAlign(node, this.value.sm, this.value.md, this.value.lg, this.value.gutter, this.value.margin);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.sm === this.value.sm &&
      this.stageValue.md === this.value.md &&
      this.stageValue.lg === this.value.lg &&
      this.stageValue.gutter === this.value.gutter &&
      this.stageValue.margin === this.value.margin);
  }
}
BarGridAlignModifier.identity = Symbol('barGridAlign');
class TabsDividerModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetDivider(node);
    }
    else {
      getUINativeModule().tabs.setDivider(node, this.value.strokeWidth, this.value.color, this.value.startMargin, this.value.endMargin);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.strokeWidth === this.value.strokeWidth &&
      this.stageValue.color === this.value.color &&
      this.stageValue.startMargin === this.value.startMargin &&
      this.stageValue.endMargin === this.value.endMargin);
  }
}
TabsDividerModifier.identity = Symbol('tabsDivider');
class BarWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetTabBarWidth(node);
    }
    else {
      getUINativeModule().tabs.setTabBarWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BarWidthModifier.identity = Symbol('barWidth');
class BarAdaptiveHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetBarAdaptiveHeight(node);
    }
    else {
      getUINativeModule().tabs.setBarAdaptiveHeight(node, this.value);
    }
  }
}
BarAdaptiveHeightModifier.identity = Symbol('barAdaptiveHeight');
class BarHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetTabBarHeight(node);
    }
    else {
      getUINativeModule().tabs.setTabBarHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BarHeightModifier.identity = Symbol('barHeight');
class BarOverlapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetBarOverlap(node);
    }
    else {
      getUINativeModule().tabs.setBarOverlap(node, this.value);
    }
  }
}
BarOverlapModifier.identity = Symbol('barOverlap');
class TabsVerticalModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetIsVertical(node);
    }
    else {
      getUINativeModule().tabs.setIsVertical(node, this.value);
    }
  }
}
TabsVerticalModifier.identity = Symbol('vertical');
class AnimationDurationModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetAnimationDuration(node);
    }
    else {
      getUINativeModule().tabs.setAnimationDuration(node, this.value);
    }
  }
}
AnimationDurationModifier.identity = Symbol('animationduration');
class AnimationModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetAnimateMode(node);
    }
    else {
      getUINativeModule().tabs.setAnimateMode(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
AnimationModeModifier.identity = Symbol('animationMode');
class ScrollableModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetScrollable(node);
    }
    else {
      getUINativeModule().tabs.setScrollable(node, this.value);
    }
  }
}
ScrollableModifier.identity = Symbol('scrollable');
class TabBarModeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().tabs.resetTabBarMode(node);
    }
    else {
      getUINativeModule().tabs.setTabBarMode(node, this.value.barMode,
        (_a = this.value.options) === null || _a === void 0 ? void 0 : _a.margin,
        (_b = this.value.options) === null || _b === void 0 ? void 0 : _b.nonScrollableLayoutStyle);
    }
  }
  checkObjectDiff() {
    let _a, _b, _c, _d;
    if (isResource(this.stageValue) && isResource(this.value)) {
      return !isResourceEqual(this.stageValue, this.value);
    }
    else if (!isResource(this.stageValue) && !isResource(this.value)) {
      return !(this.value.barMode === this.stageValue.barMode &&
        ((_a = this.value.options) === null || _a === void 0 ? void 0 : _a.margin) === ((_b = this.stageValue.options) === null ||
        _b === void 0 ? void 0 : _b.margin) &&
        ((_c = this.value.options) === null || _c === void 0 ? void 0 : _c.nonScrollableLayoutStyle) === ((_d = this.stageValue.options) === null ||
        _d === void 0 ? void 0 : _d.nonScrollableLayoutStyle));
    }
    else {
      return true;
    }
  }
}
TabBarModeModifier.identity = Symbol('tabsbarMode');
class BarPositionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetTabBarPosition(node);
    }
    else {
      getUINativeModule().tabs.setTabBarPosition(node, this.value);
    }
  }
}
BarPositionModifier.identity = Symbol('barPosition');
class TabsHideTitleBarModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetHideTitleBar(node);
    }
    else {
      getUINativeModule().tabs.setHideTitleBar(node, this.value);
    }
  }
}
TabsHideTitleBarModifier.identity = Symbol('hideTitleBar');
class BarBackgroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetBarBackgroundColor(node);
    }
    else {
      getUINativeModule().tabs.setBarBackgroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BarBackgroundColorModifier.identity = Symbol('barbackgroundcolor');
class BarBackgroundBlurStyleModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetBarBackgroundBlurStyle(node);
    }
    else {
      getUINativeModule().tabs.setBarBackgroundBlurStyle(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
BarBackgroundBlurStyleModifier.identity = Symbol('barbackgroundblurstyle');
class FadingEdgeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetFadingEdge(node);
    }
    else {
      getUINativeModule().tabs.setFadingEdge(node, this.value);
    }
  }
}
FadingEdgeModifier.identity = Symbol('fadingedge');
class TabClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabs.resetTabClip(node);
    }
    else {
      getUINativeModule().tabs.setTabClip(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
TabClipModifier.identity = Symbol('tabclip');
class TabWidthModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().tabs.resetTabWidth(node);
        }
        else {
            getUINativeModule().tabs.setTabWidth(node, this.value);
        }
    }
}
TabWidthModifier.identity = Symbol('tabWidth');
class TabHeightModifier extends ModifierWithKey {
    constructor(value) {
        super(value);
    }
    applyPeer(node, reset) {
        if (reset) {
            getUINativeModule().tabs.resetTabHeight(node);
        }
        else {
            getUINativeModule().tabs.setTabHeight(node, this.value);
        }
    }
}
TabHeightModifier.identity = Symbol('tabHeight');
// @ts-ignore
if (globalThis.Tabs !== undefined) {
  globalThis.Tabs.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTabsComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TabsModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkTabContentComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  tabBar(value) {
    throw new Error('Method not implemented.');
  }
  size(value) {
    modifierWithKey(this._modifiersWithKeys, TabContentSizeModifier.identity, TabContentSizeModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, TabContentWidthModifier.identity, TabContentWidthModifier, value);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, TabContentHeightModifier.identity, TabContentHeightModifier, value);
    return this;
  }
}
class TabContentWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabContent.resetTabContentWidth(node);
    }
    else {
      getUINativeModule().tabContent.setTabContentWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TabContentWidthModifier.identity = Symbol('tabcontentwidth');
class TabContentHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabContent.resetTabContentHeight(node);
    }
    else {
      getUINativeModule().tabContent.setTabContentHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
TabContentHeightModifier.identity = Symbol('tabcontentheight');
class TabContentSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().tabContent.resetTabContentSize(node);
    }
    else {
      getUINativeModule().tabContent.setTabContentSize(node, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.width, this.value.width) ||
      !isBaseOrResourceEqual(this.stageValue.height, this.value.height);
  }
}
TabContentSizeModifier.identity = Symbol('tabcontentsize');
// @ts-ignore
if (globalThis.TabContent !== undefined) {
  globalThis.TabContent.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkTabContentComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.TabContentModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkUIExtensionComponentComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onRemoteReady(callback) {
    throw new Error('Method not implemented.');
  }
  onReceive(callback) {
    throw new Error('Method not implemented.');
  }
  onResult(callback) {
    throw new Error('Method not implemented.');
  }
  onRelease(callback) {
    throw new Error('Method not implemented.');
  }
  onError(callback) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.UIExtensionComponent !== undefined) {
  globalThis.UIExtensionComponent.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkUIExtensionComponentComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ItemConstraintSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetItemConstraintSize(node);
    }
    else {
      getUINativeModule().waterFlow.setItemConstraintSize(node, this.value.minWidth, this.value.maxWidth, this.value.minHeight, this.value.maxHeight);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue.minWidth, this.value.minWidth) ||
      !isBaseOrResourceEqual(this.stageValue.maxWidth, this.value.maxWidth) ||
      !isBaseOrResourceEqual(this.stageValue.minHeight, this.value.minHeight) ||
      !isBaseOrResourceEqual(this.stageValue.maxHeight, this.value.maxHeight);
  }
}
ItemConstraintSizeModifier.identity = Symbol('itemConstraintSize');
class ColumnsTemplateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetColumnsTemplate(node);
    }
    else {
      getUINativeModule().waterFlow.setColumnsTemplate(node, this.value);
    }
  }
}
ColumnsTemplateModifier.identity = Symbol('columnsTemplate');
class RowsTemplateModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetRowsTemplate(node);
    }
    else {
      getUINativeModule().waterFlow.setRowsTemplate(node, this.value);
    }
  }
}
RowsTemplateModifier.identity = Symbol('rowsTemplate');
class EnableScrollInteractionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetEnableScrollInteraction(node);
    }
    else {
      getUINativeModule().waterFlow.setEnableScrollInteraction(node, this.value);
    }
  }
}
EnableScrollInteractionModifier.identity = Symbol('enableScrollInteraction');
class RowsGapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetRowsGap(node);
    }
    else {
      getUINativeModule().waterFlow.setRowsGap(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
RowsGapModifier.identity = Symbol('rowsGap');
class WaterFlowClipModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetClipWithEdge(node);
    }
    else {
      getUINativeModule().common.setClipWithEdge(node, this.value);
    }
  }
  checkObjectDiff() {
    return true;
  }
}
WaterFlowClipModifier.identity = Symbol('waterFlowclip');
class ColumnsGapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetColumnsGap(node);
    }
    else {
      getUINativeModule().waterFlow.setColumnsGap(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ColumnsGapModifier.identity = Symbol('columnsGap');
class LayoutDirectionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetLayoutDirection(node);
    }
    else {
      getUINativeModule().waterFlow.setLayoutDirection(node, this.value);
    }
  }
}
LayoutDirectionModifier.identity = Symbol('layoutDirection');
class NestedScrollModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetNestedScroll(node);
    }
    else {
      getUINativeModule().waterFlow.setNestedScroll(node, this.value.scrollForward, this.value.scrollBackward);
    }
  }
}
NestedScrollModifier.identity = Symbol('nestedScroll');
class FrictionModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().waterFlow.resetFriction(node);
    }
    else {
      getUINativeModule().waterFlow.setFriction(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FrictionModifier.identity = Symbol('friction');

class WaterFlowEdgeEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let _a, _b;
    if (reset) {
      getUINativeModule().waterFlow.resetEdgeEffect(node);
    }
    else {
      getUINativeModule().waterFlow.setEdgeEffect(node, (_a = this.value) === null ||
      _a === void 0 ? void 0 : _a.value, (_b = this.value.options) === null ||
      _b === void 0 ? void 0 : _b.alwaysEnabled);
    }
  }
  checkObjectDiff() {
    return !((this.stageValue.value === this.value.value) &&
      (this.stageValue.options === this.value.options));
  }
}
WaterFlowEdgeEffectModifier.identity = Symbol('waterFlowEdgeEffect');
class ArkWaterFlowComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  columnsTemplate(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnsTemplateModifier.identity, ColumnsTemplateModifier, value);
    return this;
  }
  rowsTemplate(value) {
    modifierWithKey(this._modifiersWithKeys, RowsTemplateModifier.identity, RowsTemplateModifier, value);
    return this;
  }
  itemConstraintSize(value) {
    if (!value) {
      modifierWithKey(this._modifiersWithKeys, ItemConstraintSizeModifier.identity, ItemConstraintSizeModifier, undefined);
      return this;
    }
    let arkValue = new ArkConstraintSizeOptions();
    arkValue.minWidth = value.minWidth;
    arkValue.maxWidth = value.maxWidth;
    arkValue.minHeight = value.minHeight;
    arkValue.maxHeight = value.maxHeight;
    modifierWithKey(this._modifiersWithKeys, ItemConstraintSizeModifier.identity, ItemConstraintSizeModifier, arkValue);
    return this;
  }
  columnsGap(value) {
    modifierWithKey(this._modifiersWithKeys, ColumnsGapModifier.identity, ColumnsGapModifier, value);
    return this;
  }
  rowsGap(value) {
    modifierWithKey(this._modifiersWithKeys, RowsGapModifier.identity, RowsGapModifier, value);
    return this;
  }
  layoutDirection(value) {
    modifierWithKey(this._modifiersWithKeys, LayoutDirectionModifier.identity, LayoutDirectionModifier, value);
    return this;
  }
  nestedScroll(value) {
    let options = new ArkNestedScrollOptions();
    if (value) {
      if (value.scrollForward) {
        options.scrollForward = value.scrollForward;
      }
      if (value.scrollBackward) {
        options.scrollBackward = value.scrollBackward;
      }
      modifierWithKey(this._modifiersWithKeys, NestedScrollModifier.identity, NestedScrollModifier, options);
    }
    return this;
  }
  enableScrollInteraction(value) {
    modifierWithKey(this._modifiersWithKeys, EnableScrollInteractionModifier.identity, EnableScrollInteractionModifier, value);
    return this;
  }
  friction(value) {
    modifierWithKey(this._modifiersWithKeys, FrictionModifier.identity, FrictionModifier, value);
    return this;
  }
  cachedCount(value) {
    throw new Error('Method not implemented.');
  }
  onReachStart(event) {
    throw new Error('Method not implemented.');
  }
  onReachEnd(event) {
    throw new Error('Method not implemented.');
  }
  onScrollFrameBegin(event) {
    throw new Error('Method not implemented.');
  }
  clip(value) {
    modifierWithKey(this._modifiersWithKeys, WaterFlowClipModifier.identity, WaterFlowClipModifier, value);
    return this;
  }
  edgeEffect(value, options) {
    let effect = new ArkWaterFlowEdgeEffect();
    effect.value = value;
    effect.options = options;
    modifierWithKey(this._modifiersWithKeys, WaterFlowEdgeEffectModifier.identity, WaterFlowEdgeEffectModifier, effect);
    return this;
  }
}

// @ts-ignore
if (globalThis.WaterFlow !== undefined) {
  globalThis.WaterFlow.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkWaterFlowComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.WaterFlowModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkCommonShapeComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  viewPort(value) {
    throw new Error('Method not implemented.');
  }
  stroke(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeModifier.identity, StrokeModifier, value);
    return this;
  }
  fill(value) {
    modifierWithKey(this._modifiersWithKeys, FillModifier.identity, FillModifier, value);
    return this;
  }
  strokeDashOffset(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeDashOffsetModifier.identity, StrokeDashOffsetModifier, value);
    return this;
  }
  strokeLineCap(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeLineCapModifier.identity, StrokeLineCapModifier, value);
    return this;
  }
  strokeLineJoin(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeLineJoinModifier.identity, StrokeLineJoinModifier, value);
    return this;
  }
  strokeMiterLimit(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeMiterLimitModifier.identity, StrokeMiterLimitModifier, value);
    return this;
  }
  strokeOpacity(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeOpacityModifier.identity, StrokeOpacityModifier, value);
    return this;
  }
  fillOpacity(value) {
    modifierWithKey(this._modifiersWithKeys, FillOpacityModifier.identity, FillOpacityModifier, value);
    return this;
  }
  strokeWidth(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeWidthModifier.identity, StrokeWidthModifier, value);
    return this;
  }
  antiAlias(value) {
    modifierWithKey(this._modifiersWithKeys, AntiAliasModifier.identity, AntiAliasModifier, value);
    return this;
  }
  strokeDashArray(value) {
    modifierWithKey(this._modifiersWithKeys, StrokeDashArrayModifier.identity, StrokeDashArrayModifier, value);
    return this;
  }
  mesh(value, column, row) {
    throw new Error('Method not implemented.');
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, CommonShapeHeightModifier.identity, CommonShapeHeightModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, CommonShapeWidthModifier.identity, CommonShapeWidthModifier, value);
    return this;
  }
  foregroundColor(value) {
    modifierWithKey(
      this._modifiersWithKeys, CommonShapeForegroundColorModifier.identity, CommonShapeForegroundColorModifier, value);
    return this;
  }
}
class StrokeDashArrayModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeDashArray(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeDashArray(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StrokeDashArrayModifier.identity = Symbol('strokeDashArray');
class StrokeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStroke(node);
    }
    else {
      getUINativeModule().commonShape.setStroke(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StrokeModifier.identity = Symbol('stroke');
class FillModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetFill(node);
    }
    else {
      getUINativeModule().commonShape.setFill(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FillModifier.identity = Symbol('fill');
class StrokeDashOffsetModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeDashOffset(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeDashOffset(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StrokeDashOffsetModifier.identity = Symbol('strokeDashOffset');
class StrokeLineCapModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeLineCap(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeLineCap(node, this.value);
    }
  }
}
StrokeLineCapModifier.identity = Symbol('strokeLineCap');
class StrokeLineJoinModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeLineJoin(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeLineJoin(node, this.value);
    }
  }
}
StrokeLineJoinModifier.identity = Symbol('strokeLineJoin');
class StrokeMiterLimitModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeMiterLimit(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeMiterLimit(node, this.value);
    }
  }
}
StrokeMiterLimitModifier.identity = Symbol('strokeMiterLimit');
class FillOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetFillOpacity(node);
    }
    else {
      getUINativeModule().commonShape.setFillOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
FillOpacityModifier.identity = Symbol('FillOpacity');
class StrokeOpacityModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeOpacity(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeOpacity(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
StrokeOpacityModifier.identity = Symbol('StrokeOpacity');
class StrokeWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetStrokeWidth(node);
    }
    else {
      getUINativeModule().commonShape.setStrokeWidth(node, this.value);
    }
  }
}
StrokeWidthModifier.identity = Symbol('strokeWidth');
class AntiAliasModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetAntiAlias(node);
    }
    else {
      getUINativeModule().commonShape.setAntiAlias(node, this.value);
    }
  }
}
AntiAliasModifier.identity = Symbol('antiAlias');
class CommonShapeHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetHeight(node);
    }
    else {
      getUINativeModule().commonShape.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CommonShapeHeightModifier.identity = Symbol('commonShapeHeight');
class CommonShapeWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetWidth(node);
    }
    else {
      getUINativeModule().commonShape.setWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CommonShapeWidthModifier.identity = Symbol('commonShapeWidth');
class CommonShapeForegroundColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().commonShape.resetForegroundColor(node);
    }
    else {
      getUINativeModule().commonShape.setForegroundColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
CommonShapeForegroundColorModifier.identity = Symbol('commonShapeForegroundColor');

/// <reference path='./import.ts' />
class ArkCircleComponent extends ArkCommonShapeComponent {
}
// @ts-ignore
if (globalThis.Circle !== undefined) {
  globalThis.Circle.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCircleComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CircleModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkEllipseComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
}
// @ts-ignore
if (globalThis.Ellipse !== undefined) {
  globalThis.Ellipse.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkEllipseComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
/// <reference path='./ArkCommonShape.ts' />
class ArkLineComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  startPoint(value) {
    modifierWithKey(this._modifiersWithKeys, LineStartPointModifier.identity, LineStartPointModifier, value);
    return this;
  }
  endPoint(value) {
    modifierWithKey(this._modifiersWithKeys, LineEndPointModifier.identity, LineEndPointModifier, value);
    return this;
  }
}
class LineStartPointModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().line.resetStartPoint(node);
    }
    else {
      getUINativeModule().line.setStartPoint(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
LineStartPointModifier.identity = Symbol('startPoint');
class LineEndPointModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().line.resetEndPoint(node);
    }
    else {
      getUINativeModule().line.setEndPoint(node, this.value);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
LineEndPointModifier.identity = Symbol('endPoint');
// @ts-ignore
if (globalThis.Line !== undefined) {
  globalThis.Line.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkLineComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.LineModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
/// <reference path='./ArkCommonShape.ts' />
const ARRAY_LENGTH = 2;
class ArkPolylineComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  points(value) {
    modifierWithKey(this._modifiersWithKeys, PolylinePointsModifier.identity, PolylinePointsModifier, value);
    return this;
  }
}
class PolylinePointsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let xPoint = [];
    let yPoint = [];
    if (Array.isArray(this.value)) {
      for (let i = 0; i <= this.value.length; i++) {
        let item = this.value[i];
        if (!Array.isArray(item)) {
          continue;
        }
        if (item.length < ARRAY_LENGTH || isUndefined(item[0]) || isUndefined(item[1])) {
          reset = true;
          break;
        }
        xPoint.push(item[0]);
        yPoint.push(item[1]);
      }
    }
    else {
      reset = true;
    }
    if (reset) {
      getUINativeModule().polyline.resetPoints(node);
    }
    else {
      getUINativeModule().polyline.setPoints(node, xPoint, yPoint);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
PolylinePointsModifier.identity = Symbol('points');
// @ts-ignore
if (globalThis.Polyline !== undefined) {
  globalThis.Polyline.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPolylineComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PolylineModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkPolygonComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  points(value) {
    modifierWithKey(this._modifiersWithKeys, PolygonPointsModifier.identity, PolygonPointsModifier, value);
    return this;
  }
}
class PolygonPointsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    let xPoint = [];
    let yPoint = [];
    if (Array.isArray(this.value)) {
      for (let i = 0; i <= this.value.length; i++) {
        let item = this.value[i];
        if (!Array.isArray(item)) {
          continue;
        }
        if (item.length < ARRAY_LENGTH || isUndefined(item[0]) || isUndefined(item[1])) {
          reset = true;
          break;
        }
        xPoint.push(item[0]);
        yPoint.push(item[1]);
      }
    }
    else {
      reset = true;
    }
    if (reset) {
      getUINativeModule().polygon.resetPolygonPoints(node);
    }
    else {
      getUINativeModule().polygon.setPolygonPoints(node, xPoint, yPoint);
    }
  }
  checkObjectDiff() {
    return this.stageValue !== this.value;
  }
}
PolygonPointsModifier.identity = Symbol('polygonPoints');
// @ts-ignore
if (globalThis.Polygon !== undefined) {
  globalThis.Polygon.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPolygonComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PolygonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkPathComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  commands(value) {
    modifierWithKey(this._modifiersWithKeys, CommandsModifier.identity, CommandsModifier, value);
    return this;
  }
}
class CommandsModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().path.resetPathCommands(node);
    }
    else {
      getUINativeModule().path.setPathCommands(node, this.value);
    }
  }
  checkObjectDiff() {
    if (isString(this.stageValue) && isString(this.value)) {
      return this.stageValue !== this.value;
    }
    else {
      return true;
    }
  }
}
CommandsModifier.identity = Symbol('commands');
// @ts-ignore
if (globalThis.Path !== undefined) {
  globalThis.Path.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkPathComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.PathModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
/// <reference path='./ArkCommonShape.ts' />
class RectRadiusWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rect.resetRectRadiusWidth(node);
    }
    else {
      getUINativeModule().rect.setRectRadiusWidth(node, this.value);
    }
  }
}
RectRadiusWidthModifier.identity = Symbol('rectRadiusWidth');
class RectRadiusHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rect.resetRectRadiusHeight(node);
    }
    else {
      getUINativeModule().rect.setRectRadiusHeight(node, this.value);
    }
  }
}
RectRadiusHeightModifier.identity = Symbol('rectRadiusHeight');
class RectRadiusModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().rect.resetRectRadius(node);
    }
    else {
      getUINativeModule().rect.setRectRadius(node, this.value);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue === this.value);
  }
}
RectRadiusModifier.identity = Symbol('rectRadius');
class ArkRectComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  radiusWidth(value) {
    modifierWithKey(this._modifiersWithKeys, RectRadiusWidthModifier.identity, RectRadiusWidthModifier, value);
    return this;
  }
  radiusHeight(value) {
    modifierWithKey(this._modifiersWithKeys, RectRadiusHeightModifier.identity, RectRadiusHeightModifier, value);
    return this;
  }
  radius(value) {
    modifierWithKey(this._modifiersWithKeys, RectRadiusModifier.identity, RectRadiusModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Rect !== undefined) {
  globalThis.Rect.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRectComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.RectModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
/// <reference path='./ArkCommonShape.ts' />
class ShapeViewPortModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().shape.resetShapeViewPort(node);
    }
    else {
      getUINativeModule().shape.setShapeViewPort(node, this.value.x, this.value.y, this.value.width, this.value.height);
    }
  }
  checkObjectDiff() {
    return !(this.stageValue.x === this.value.x && this.stageValue.y === this.value.y &&
      this.stageValue.width === this.value.width && this.stageValue.height === this.value.height);
  }
}
ShapeViewPortModifier.identity = Symbol('shapeViewPort');
class ShapeMeshModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().shape.resetShapeMesh(node);
    }
    else {
      getUINativeModule().shape.setShapeMesh(node, this.value.value, this.value.column, this.value.row);
    }
  }
  checkObjectDiff() {
    return !this.stageValue.isEqual(this.value);
  }
}
ShapeMeshModifier.identity = Symbol('shapeMesh');
class ShapeHeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetHeight(node);
    }
    else {
      getUINativeModule().common.setHeight(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ShapeHeightModifier.identity = Symbol('shapeHeight');
class ShapeWidthModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().common.resetWidth(node);
    }
    else {
      getUINativeModule().common.setWidth(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
ShapeWidthModifier.identity = Symbol('shapeWidth');
class ArkShapeComponent extends ArkCommonShapeComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  viewPort(value) {
    if (value === null) {
      value = undefined;
    }
    modifierWithKey(this._modifiersWithKeys, ShapeViewPortModifier.identity, ShapeViewPortModifier, value);
    return this;
  }
  mesh(value, column, row) {
    let arkMesh = new ArkMesh();
    if (value !== null && column !== null && row !== null) {
      arkMesh.value = value;
      arkMesh.column = column;
      arkMesh.row = row;
    }
    modifierWithKey(this._modifiersWithKeys, ShapeMeshModifier.identity, ShapeMeshModifier, arkMesh);
    return this;
  }
  height(value) {
    modifierWithKey(this._modifiersWithKeys, ShapeHeightModifier.identity, ShapeHeightModifier, value);
    return this;
  }
  width(value) {
    modifierWithKey(this._modifiersWithKeys, ShapeWidthModifier.identity, ShapeWidthModifier, value);
    return this;
  }
}
// @ts-ignore
if (globalThis.Shape !== undefined) {
  globalThis.Shape.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkShapeComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ShapeModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkCanvasComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  onReady(event) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.Canvas !== undefined) {
  globalThis.Canvas.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkCanvasComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkGridContainerComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  alignItems(value) {
    throw new Error('Method not implemented.');
  }
  justifyContent(value) {
    throw new Error('Method not implemented.');
  }
  pointLight(value) {
    throw new Error('Method not implemented.');
  }
}
// @ts-ignore
if (globalThis.GridContainer !== undefined) {
  globalThis.GridContainer.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkGridContainerComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkEffectComponentComponent extends ArkComponent {
}
// @ts-ignore
if (globalThis.EffectComponent !== undefined) {
  // @ts-ignore
  globalThis.EffectComponent.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkEffectComponentComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

/// <reference path='./import.ts' />
class ArkRemoteWindowComponent extends ArkComponent {
}
// @ts-ignore
if (globalThis.RemoteWindow !== undefined) {
  // @ts-ignore
  globalThis.RemoteWindow.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkRemoteWindowComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.CommonModifier(nativePtr, classType);
    });
  };
}

class ParticleDisturbanceFieldModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }

  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().particle.resetDisturbanceField(node);
    }
    else {
      let dataArray = [];
      if (!Array.isArray(this.value)) {
        return;
      }
      for (let i = 0; i < this.value.length; i++) {
        let data = this.value[i];
        dataArray.push(parseWithDefaultNumber(data.strength, 0));
        dataArray.push(parseWithDefaultNumber(data.shape, 0));
        if (isObject(data.size)) {
          dataArray.push(parseWithDefaultNumber(data.size.width, 0));
          dataArray.push(parseWithDefaultNumber(data.size.height, 0));
        }
        else {
          dataArray.push(0);
          dataArray.push(0);
        }
        if (isObject(data.position)) {
          dataArray.push(parseWithDefaultNumber(data.position.x, 0));
          dataArray.push(parseWithDefaultNumber(data.position.y, 0));
        }
        else {
          dataArray.push(0);
          dataArray.push(0);
        }
        dataArray.push(parseWithDefaultNumber(data.feather, 0));
        dataArray.push(parseWithDefaultNumber(data.noiseScale, 1));
        dataArray.push(parseWithDefaultNumber(data.noiseFrequency, 1));
        dataArray.push(parseWithDefaultNumber(data.noiseAmplitude, 1));
      }
      getUINativeModule().particle.setDisturbanceField(node, dataArray);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

ParticleDisturbanceFieldModifier.identity = Symbol('disturbanceFields');

class ParticleEmitterModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }

  applyPeer(node, reset) {
    let _a, _b, _c, _d, _e;
    if (reset) {
      getUINativeModule().particle.resetEmitter(node);
    }
    else {
      let dataArray = [];
      if (!Array.isArray(this.value)) {
        return;
      }
      for (let i = 0; i < this.value.length; i++) {
        let data = this.value[i];
        let indexValue = 0;
        if (data.index > 0) {
          indexValue = data.index;
        }
        dataArray.push(indexValue);

        let emitRateValue = 5;
        if (isNumber(data.emitRate)) {
          dataArray.push(1);
          if (data.emitRate > 0) {
            emitRateValue = data.emitRate;
          }
          dataArray.push(emitRateValue);
        } else {
          dataArray.push(0);
          dataArray.push(_a);
        }

        if (isObject(data.position)) {
          if (isNumber(data.position.x) && isNumber(data.position.y)) {
            dataArray.push(1);
            dataArray.push(data.position.x);
            dataArray.push(data.position.y);
          } else {
            dataArray.push(0);
            dataArray.push(_b);
            dataArray.push(_c);
          }
        } else {
          dataArray.push(0);
          dataArray.push(_b);
          dataArray.push(_c);
        }

        if (isObject(data.size)) {
          if (data.size.width > 0 && data.size.height > 0) {
            dataArray.push(1);
            dataArray.push(data.size.width);
            dataArray.push(data.size.height);
          } else {
            dataArray.push(0);
            dataArray.push(_d);
            dataArray.push(_e);
          }
        }
        else {
          dataArray.push(0);
          dataArray.push(_d);
          dataArray.push(_e);
        }
      }
      getUINativeModule().particle.setEmitter(node, dataArray);
    }
  }

  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

ParticleEmitterModifier.identity = Symbol('emitter');

/// <reference path='./import.ts' />
class ArkParticleComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  disturbanceFields(value) {
     modifierWithKey(this._modifiersWithKeys, ParticleDisturbanceFieldModifier.identity, ParticleDisturbanceFieldModifier, value);
    return this;
  }

  emitter(value) {
    modifierWithKey(this._modifiersWithKeys, ParticleEmitterModifier.identity, ParticleEmitterModifier, value);
   return this;
 }
}
// @ts-ignore
if (globalThis.Particle !== undefined) {

  // @ts-ignore
  globalThis.Particle.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkParticleComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.ParticleModifier(nativePtr, classType);
    });
  };
}

class SymbolFontColorModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetFontColor(node);
    }
    else {
      getUINativeModule().symbolGlyph.setFontColor(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SymbolFontColorModifier.identity = Symbol('symbolGlyphFontColor');

class SymbolFontSizeModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetFontSize(node);
    }
    else {
      getUINativeModule().symbolGlyph.setFontSize(node, this.value);
    }
  }
  checkObjectDiff() {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}
SymbolFontSizeModifier.identity = Symbol('symbolGlyphFontSize');

class SymbolFontWeightModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetFontWeight(node);
    }
    else {
      getUINativeModule().symbolGlyph.setFontWeight(node, this.value);
    }
  }
}
SymbolFontWeightModifier.identity = Symbol('symbolGlyphFontWeight');

class RenderingStrategyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetRenderingStrategy(node);
    }
    else {
      getUINativeModule().symbolGlyph.setRenderingStrategy(node, this.value);
    }
  }
}
RenderingStrategyModifier.identity = Symbol('symbolGlyphRenderingStrategy');

class EffectStrategyModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetEffectStrategy(node);
    }
    else {
      getUINativeModule().symbolGlyph.setEffectStrategy(node, this.value);
    }
  }
}
EffectStrategyModifier.identity = Symbol('symbolGlyphEffectStrategy');

class SymbolContentModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.setSymbolId(node, "");
    }
    else {
      getUINativeModule().symbolGlyph.setSymbolId(node, this.value);
    }
  }
}
SymbolContentModifier.identity = Symbol('symbolContent');

class SymbolEffectModifier extends ModifierWithKey {
  constructor(value) {
    super(value);
  }
  applyPeer(node, reset) {
    if (reset) {
      getUINativeModule().symbolGlyph.resetSymbolEffectOptions(node);
    } else {
      getUINativeModule().symbolGlyph.setSymbolEffectOptions(node, this.value.symbolEffect, this.value.action);
    }
  }
}
SymbolEffectModifier.identity = Symbol('symbolEffect');

/// <reference path='./import.ts' />
class ArkSymbolGlyphComponent extends ArkComponent {
  constructor(nativePtr, classType) {
    super(nativePtr, classType);
  }
  initialize(value) {
    if (value[0] !== undefined) {
      modifierWithKey(this._modifiersWithKeys, SymbolContentModifier.identity, SymbolContentModifier, value[0]);
    }
    return this;
  }
  fontColor(value) {
    modifierWithKey(this._modifiersWithKeys, SymbolFontColorModifier.identity, SymbolFontColorModifier, value);
    return this;
  }
  fontSize(value) {
    modifierWithKey(this._modifiersWithKeys, SymbolFontSizeModifier.identity, SymbolFontSizeModifier, value);
    return this;
  }
  fontWeight(value) {
    modifierWithKey(this._modifiersWithKeys, SymbolFontWeightModifier.identity, SymbolFontWeightModifier, value);
    return this;
  }
  renderingStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, RenderingStrategyModifier.identity, RenderingStrategyModifier, value);
    return this;
  }
  effectStrategy(value) {
    modifierWithKey(this._modifiersWithKeys, EffectStrategyModifier.identity, EffectStrategyModifier, value);
    return this;
  }
  symbolEffect(effect, action) {
    let symbolEffect = new ArkSymbolEffect();
    symbolEffect.symbolEffect = effect;
    symbolEffect.action = action;
    modifierWithKey(this._modifiersWithKeys, SymbolEffectModifier.identity, SymbolEffectModifier, symbolEffect);
    return this;
  }
}

// @ts-ignore
if (globalThis.SymbolGlyph !== undefined) {
  globalThis.SymbolGlyph.attributeModifier = function (modifier) {
    attributeModifierFunc.call(this, modifier, (nativePtr) => {
      return new ArkSymbolGlyphComponent(nativePtr);
    }, (nativePtr, classType, modifierJS) => {
      return new modifierJS.SymbolGlyphModifier(undefined, nativePtr, classType);
    });
  };
}
