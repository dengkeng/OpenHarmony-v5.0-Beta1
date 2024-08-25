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

/**
 * Provides a button component.
 * @since 7
 */
/**
 * Provides a button component.
 * @form
 * @since 9
 */
/**
 * Provides a button component.
 * @form
 * @crossplatform
 * @since 10
 */
declare enum ButtonType {
  /**
   * Capsule button (rounded corners default to half the height).
   * @since 7
   */
  /**
   * Capsule button (rounded corners default to half the height).
   * @form
   * @since 9
   */
  /**
   * Capsule button (rounded corners default to half the height).
   * @form
   * @crossplatform
   * @since 10
   */
  Capsule,

  /**
   * Round buttons.
   * @since 7
   */
  /**
   * Round buttons.
   * @form
   * @since 9
   */
  /**
   * Round buttons.
   * @form
   * @crossplatform
   * @since 10
   */
  Circle,

  /**
   * Common button (no rounded corners by default).
   * @since 7
   */
  /**
   * Common button (no rounded corners by default).
   * @form
   * @since 9
   */
  /**
   * Common button (no rounded corners by default).
   * @form
   * @crossplatform
   * @since 10
   */
  Normal,
}

/**
 * Defines the button options.
 * @since 7
 */
/**
 * Defines the button options.
 * @form
 * @since 9
 */
/**
 * Defines the button options.
 * @form
 * @crossplatform
 * @since 10
 */
declare interface ButtonOptions {
  /**
   * Describes the button style.
   * @since 7
   */
  /**
   * Describes the button style.
   * @form
   * @since 9
   */
  /**
   * Describes the button style.
   * @form
   * @crossplatform
   * @since 10
   */
  type?: ButtonType;

  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @since 7
   */
  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @form
   * @since 9
   */
  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @form
   * @crossplatform
   * @since 10
   */
  stateEffect?: boolean;
}

/**
 * Defines the Button Component.
 * @since 7
 */
/**
 * Defines the Button Component.
 * @form
 * @since 9
 */
/**
 * Defines the Button Component.
 * @form
 * @crossplatform
 * @since 10
 */
interface ButtonInterface {
  /**
   * Button object
   * @since 7
   */
  /**
   * Button object
   * @form
   * @since 9
   */
  /**
   * Button object
   * @form
   * @crossplatform
   * @since 10
   */
  (): ButtonAttribute;

  /**
   * Create Button with Text child.
   * @since 7
   */
  /**
   * Create Button with Text child.
   * @form
   * @since 9
   */
  /**
   * Create Button with Text child.
   * @form
   * @crossplatform
   * @since 10
   */
  (options: ButtonOptions): ButtonAttribute;

  /**
   * Create Button with inner text label.
   * @since 7
   */
  /**
   * Create Button with inner text label.
   * @form
   * @since 9
   */
  /**
   * Create Button with inner text label.
   * @form
   * @crossplatform
   * @since 10
   */
  (label: ResourceStr, options?: ButtonOptions): ButtonAttribute;
}

/**
 * LabelStyle object.
 * @syscap SystemCapability.ArkUI.ArkUI.Full
 * @since 10
 */
/**
 * LabelStyle object.
 * @syscap SystemCapability.ArkUI.ArkUI.Full
 * @crossplatform
 * @since 10
 */
declare interface LabelStyle {
  /**
   * overflow mode.
   * @type { TextOverflow }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * overflow mode.
   * @type { TextOverflow }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  overflow?: TextOverflow;

  /**
   * Label max lines.
   * @type { number }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Label max lines.
   * @type { number }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  maxLines?: number;

  /**
   * Min font size for adapted height.
   * @type { number | ResourceStr }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Min font size for adapted height.
   * @type { number | ResourceStr }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  minFontSize?: number | ResourceStr;

  /**
   * Max font size for adapted height.
   * @type { number | ResourceStr }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Max font size for adapted height.
   * @type { number | ResourceStr }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  maxFontSize?: number | ResourceStr;

  /**
   * Adapt text height option.
   * @type { TextHeightAdaptivePolicy }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Adapt text height option.
   * @type { TextHeightAdaptivePolicy }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  heightAdaptivePolicy?: TextHeightAdaptivePolicy;

  /**
   * Font style.
   * @type { Font }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Font style.
   * @type { Font }
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  font?: Font;
}

/**
 * Defines the button attribute functions.
 * @since 7
 */
/**
 * Defines the button attribute functions.
 * @form
 * @since 9
 */
/**
 * Defines the button attribute functions.
 * @form
 * @crossplatform
 * @since 10
 */
declare class ButtonAttribute extends CommonMethod<ButtonAttribute> {
  /**
   * Describes the button style.
   * @since 7
   */
  /**
   * Describes the button style.
   * @form
   * @since 9
   */
  /**
   * Describes the button style.
   * @form
   * @crossplatform
   * @since 10
   */
  type(value: ButtonType): ButtonAttribute;

  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @since 7
   */
  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @form
   * @since 9
   */
  /**
   * Indicates whether to enable the switchover effect when the button is pressed. When the status is set to false, the switchover effect is disabled.
   * @form
   * @crossplatform
   * @since 10
   */
  stateEffect(value: boolean): ButtonAttribute;

  /**
   * Text color.
   * @since 7
   */
  /**
   * Text color.
   * @form
   * @since 9
   */
  /**
   * Text color.
   * @form
   * @crossplatform
   * @since 10
   */
  fontColor(value: ResourceColor): ButtonAttribute;

  /**
   * Text size.
   * @since 7
   */
  /**
   * Text size.
   * @form
   * @since 9
   */
  /**
   * Text size.
   * @form
   * @crossplatform
   * @since 10
   */
  fontSize(value: Length): ButtonAttribute;

  /**
   * Font weight.
   * @since 7
   */
  /**
   * Font weight.
   * @form
   * @since 9
   */
  /**
   * Font weight.
   * @form
   * @crossplatform
   * @since 10
   */
  fontWeight(value: number | FontWeight | string): ButtonAttribute;

  /**
   * Font style.
   * @since 8
   */
  /**
   * Font style.
   * @form
   * @since 9
   */
  /**
   * Font style.
   * @form
   * @crossplatform
   * @since 10
   */
  fontStyle(value: FontStyle): ButtonAttribute;

  /**
   * Font family.
   * @since 8
   */
  /**
   * Font family.
   * @form
   * @since 9
   */
  /**
   * Font family.
   * @form
   * @crossplatform
   * @since 10
   */
  fontFamily(value: string | Resource): ButtonAttribute;

  /**
   * Set button label style.
   * @param { LabelStyle } value - The label style configuration on button.
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @since 10
   */
  /**
   * Set button label style.
   * @param { LabelStyle } value - The label style configuration on button.
   * @syscap SystemCapability.ArkUI.ArkUI.Full
   * @crossplatform
   * @since 10
   */
  labelStyle(value: LabelStyle): ButtonAttribute;
}

/**
 * Defines Button Component.
 * @since 7
 */
/**
 * Defines Button Component.
 * @form
 * @since 9
 */
/**
 * Defines Button Component.
 * @form
 * @crossplatform
 * @since 10
 */
declare const Button: ButtonInterface;

/**
 * Defines Button Component instance.
 * @since 7
 */
/**
 * Defines Button Component instance.
 * @form
 * @since 9
 */
/**
 * Defines Button Component instance.
 * @form
 * @crossplatform
 * @since 10
 */
declare const ButtonInstance: ButtonAttribute;
