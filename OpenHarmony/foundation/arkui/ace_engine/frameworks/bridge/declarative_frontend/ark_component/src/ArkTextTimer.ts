/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
class ArkTextTimerComponent extends ArkComponent implements TextTimerAttribute {
  builder: WrappedBuilder<Object[]> | null = null;
  textTimerNode: BuilderNode<[TextTimerConfiguration]> | null = null;
  modifier: ContentModifier<TextTimerConfiguration>;
  constructor(nativePtr: KNode, classType?: ModifierType) {
    super(nativePtr, classType);
  }
  fontColor(value: any): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontColorModifier.identity, TextTimerFontColorModifier, value);
    return this;
  }

  fontSize(value: any): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontSizeModifier.identity, TextTimerFontSizeModifier, value);
    return this;
  }

  fontWeight(value: number | FontWeight | string): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontWeightModifier.identity, TextTimerFontWeightModifier, value);
    return this;
  }

  fontStyle(value: FontStyle): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontStyleModifier.identity, TextTimerFontStyleModifier, value);
    return this;
  }

  fontFamily(value: string | Resource): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFontFamilyModifier.identity, TextTimerFontFamilyModifier, value);
    return this;
  }

  format(value: string): this {
    modifierWithKey(this._modifiersWithKeys, TextTimerFormatModifier.identity, TextTimerFormatModifier, value);
    return this;
  }

  contentModifier(value: ContentModifier<TextTimerConfiguration>): this {
    this.setContentModifier(value);
    return this;
  }

  setContentModifier(modifier: ContentModifier<TextTimerConfiguration>): this {
    if (modifier === undefined || modifier === null) {
      getUINativeModule().textTimer.setContentModifierBuilder(this.nativePtr, false);
      return;
    }
    this.builder = modifier.applyContent();
    this.modifier = modifier;
    getUINativeModule().textTimer.setContentModifierBuilder(this.nativePtr, this);
  }

  makeContentModifierNode(context: UIContext, textTimerConfiguration: TextTimerConfiguration): FrameNode | null {
    textTimerConfiguration.contentModifier = this.modifier;
    if (isUndefined(this.textTimerNode)) {
      const xNode = globalThis.requireNapi('arkui.node');
      this.textTimerNode = new xNode.BuilderNode(context);
      this.textTimerNode.build(this.builder, textTimerConfiguration);
    } else {
      this.textTimerNode.update(textTimerConfiguration);
    }
    return this.textTimerNode.getFrameNode();
  }


  onTimer(event: (utc: number, elapsedTime: number) => void): this {
    throw new Error('Method not implemented.');
  }
}

class TextTimerFontColorModifier extends ModifierWithKey<ResourceColor> {
  static identity: Symbol = Symbol('fontColor');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFontColor(node);
    } else {
      getUINativeModule().textTimer.setFontColor(node, this.value);
    }
  }
  checkObjectDiff(): boolean {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

class TextTimerFontSizeModifier extends ModifierWithKey<Length> {
  static identity: Symbol = Symbol('fontSize');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFontSize(node);
    } else {
      getUINativeModule().textTimer.setFontSize(node, this.value);
    }
  }
  checkObjectDiff(): boolean {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

class TextTimerFontWeightModifier extends ModifierWithKey<number | FontWeight | string> {
  static identity: Symbol = Symbol('fontWeight');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFontWeight(node);
    } else {
      getUINativeModule().textTimer.setFontWeight(node, this.value);
    }
  }
}

class TextTimerFontStyleModifier extends ModifierWithKey<FontStyle> {
  static identity: Symbol = Symbol('fontStyle');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFontStyle(node);
    } else {
      getUINativeModule().textTimer.setFontStyle(node, this.value);
    }
  }
  checkObjectDiff(): boolean {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

class TextTimerFontFamilyModifier extends ModifierWithKey<string | Resource> {
  static identity: Symbol = Symbol('fontFamily');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFontFamily(node);
    } else {
      getUINativeModule().textTimer.setFontFamily(node, this.value);
    }
  }
  checkObjectDiff(): boolean {
    return !isBaseOrResourceEqual(this.stageValue, this.value);
  }
}

class TextTimerFormatModifier extends ModifierWithKey<string> {
  static identity: Symbol = Symbol('textTimerFormat');
  applyPeer(node: KNode, reset: boolean): void {
    if (reset) {
      getUINativeModule().textTimer.resetFormat(node);
    } else {
      getUINativeModule().textTimer.setFormat(node, this.value);
    }
  }
}

// @ts-ignore
globalThis.TextTimer.attributeModifier = function (modifier: ArkComponent): void {
  attributeModifierFunc.call(this, modifier, (nativePtr: KNode) => {
    return new ArkTextTimerComponent(nativePtr);
  }, (nativePtr: KNode, classType: ModifierType, modifierJS: ModifierJS) => {
    return new modifierJS.TextTimerModifier(nativePtr, classType);
  });
};

// @ts-ignore
globalThis.TextTimer.contentModifier = function (modifier) {
  const elmtId = ViewStackProcessor.GetElmtIdToAccountFor();
  let nativeNode = getUINativeModule().getFrameNodeById(elmtId);
  let component = this.createOrGetNode(elmtId, () => {
    return new ArkTextTimerComponent(nativeNode);
  });
  component.setContentModifier(modifier);
};