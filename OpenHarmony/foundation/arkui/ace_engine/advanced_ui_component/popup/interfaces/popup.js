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

const display = requireNapi('display');
const mediaquery = requireNapi('mediaquery');

export const defaultTheme = {
    icon: {
        size: { width: 32, height: 32 },
        margin: { top: 12, bottom: 12, left: 12, right: 12 },
        fillColor: '',
        borderRadius: {
            "id": -1,
            "type": 10002,
            params: ['sys.float.ohos_id_corner_radius_default_s'],
            "bundleName": "",
            "moduleName": ""
        }
    },
    title: {
        margin: { bottom: 2 },
        minFontSize: 12,
        fontWeight: FontWeight.Medium,
        fontSize: {
            "id": -1,
            "type": 10002,
            params: ['sys.float.ohos_id_text_size_sub_title2'],
            "bundleName": "",
            "moduleName": ""
        },
        fontColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.font_primary'],
            "bundleName": "",
            "moduleName": ""
        }
    },
    button: {
        margin: { top: 16, bottom: 16, left: 16, right: 16 },
        padding: { top: 4, bottom: 4, left: 4, right: 4 },
        fontSize: {
            "id": -1,
            "type": 10002,
            params: ['sys.float.ohos_id_text_size_button2'],
            "bundleName": "",
            "moduleName": ""
        },
        fontColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.font_emphasize'],
            "bundleName": "",
            "moduleName": ""
        },
        textMargin: { top: 8, bottom: 8, left: 8, right: 8 },
        minFontSize: 9,
        fontWeight: FontWeight.Medium,
        hoverColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_hover'],
            "bundleName": "",
            "moduleName": ""
        },
        backgroundColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_background_transparent'],
            "bundleName": "",
            "moduleName": ""
        }
    },
    message: {
        fontSize: {
            "id": -1,
            "type": 10002,
            params: ['sys.float.ohos_id_text_size_body2'],
            "bundleName": "",
            "moduleName": ""
        },
        fontColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.font_secondary'],
            "bundleName": "",
            "moduleName": ""
        },
        fontWeight: FontWeight.Regular,
        plainFontColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.font_primary'],
            "bundleName": "",
            "moduleName": ""
        }
    },
    windows: {
        padding: { top: 12, bottom: 12, left: 12, right: 12 },
    },
    closeButton: {
        size: { width: 22, height: 22 },
        imageSize: { width: 18, height: 18 },
        padding: { top: 2, bottom: 2, left: 2, right: 2 },
        margin: { top: 12, bottom: 12, left: 12, right: 12 },
        image: {
            "id": -1,
            "type": 20000,
            params: ['sys.media.ohos_ic_public_cancel'],
            "bundleName": "",
            "moduleName": ""
        },
        fillColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.icon_secondary'],
            "bundleName": "",
            "moduleName": ""
        },
        hoverColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_hover'],
            "bundleName": "",
            "moduleName": ""
        },
        backgroundColor: {
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_background_transparent'],
            "bundleName": "",
            "moduleName": ""
        }
    },
};
const noop = () => {
};

export function Popup(f1, b1 = null) {
    {
        (b1 ? b1 : this).observeComponentCreation2((b, c) => {
            if (c) {
                let d1 = () => {
                    return {
                        icon: f1.icon,
                        title: f1.title,
                        message: f1.message,
                        showClose: f1.showClose,
                        onClose: f1.onClose,
                        buttons: f1.buttons
                    };
                };
                ViewPU.create(new PopupComponent(b1 ? b1 : this, {
                    icon: f1.icon,
                    title: f1.title,
                    message: f1.message,
                    showClose: f1.showClose,
                    onClose: f1.onClose,
                    buttons: f1.buttons
                }, undefined, b, d1, { page: "library/src/main/ets/components/mainpage/Popup.ets", line: 160 }));
            }
            else {
                (b1 ? b1 : this).updateStateVarsOfChildByElmtId(b, {
                    icon: f1.icon,
                    title: f1.title,
                    message: f1.message,
                    showClose: f1.showClose,
                    buttons: f1.buttons
                });
            }
        }, null);
    }
}

export class PopupComponent extends ViewPU {
    constructor(b1, a1, c1, b = -1, d1 = undefined, e1) {
        super(b1, c1, b, e1);
        if (typeof d1 === "function") {
            this.paramsGenerator_ = d1;
        }
        this.onClose = noop;
        this.theme = defaultTheme;
        this.__icon = new SynchedPropertyObjectOneWayPU(a1.icon, this, "icon");
        this.__title = new SynchedPropertyObjectOneWayPU(a1.title, this, "title");
        this.__message = new SynchedPropertyObjectOneWayPU(a1.message, this, "message");
        this.__showClose = new SynchedPropertyObjectOneWayPU(a1.showClose, this, "showClose");
        this.__buttons = new SynchedPropertyObjectOneWayPU(a1.buttons, this, "buttons");
        this.textHeight = 0;
        this.__titleHeight = new ObservedPropertySimplePU(0, this, "titleHeight");
        this.__applyHeight = new ObservedPropertySimplePU(0, this, "applyHeight");
        this.__buttonHeight = new ObservedPropertySimplePU(0, this, "buttonHeight");
        this.__messageMaxWeight = new ObservedPropertyObjectPU(0, this, 'messageMaxWeight');
        this.__beforeScreenStatus = new ObservedPropertySimplePU(undefined, this, "beforeScreenStatus");
        this.__currentScreenStatus = new ObservedPropertySimplePU(true, this, "currentScreenStatus");
        this.__applySizeOptions = new ObservedPropertyObjectPU(undefined, this, "applySizeOptions");
        this.__closeButtonBackgroundColor = new ObservedPropertyObjectPU({
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_background_transparent'],
            "bundleName": "",
            "moduleName": ""
        }, this, "closeButtonBackgroundColor");
        this.__firstButtonBackgroundColor = new ObservedPropertyObjectPU({
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_background_transparent'],
            "bundleName": "",
            "moduleName": ""
        }, this, "firstButtonBackgroundColor");
        this.__secondButtonBackgroundColor = new ObservedPropertyObjectPU({
            "id": -1,
            "type": 10001,
            params: ['sys.color.ohos_id_color_background_transparent'],
            "bundleName": "",
            "moduleName": ""
        }, this, "secondButtonBackgroundColor");
        this.listener = mediaquery.matchMediaSync('(orientation: landscape)');
        this.setInitiallyProvidedValue(a1);
    }

    setInitiallyProvidedValue(a1) {
        if (a1.onClose !== undefined) {
            this.onClose = a1.onClose;
        }
        if (a1.theme !== undefined) {
            this.theme = a1.theme;
        }
        if (a1.icon === undefined) {
            this.__icon.set({ image: '' });
        }
        if (a1.title === undefined) {
            this.__title.set({ text: '' });
        }
        if (a1.message === undefined) {
            this.__message.set({ text: '' });
        }
        if (a1.showClose === undefined) {
            this.__showClose.set(true);
        }
        if (a1.buttons === undefined) {
            this.__buttons.set([{ text: '' }, { text: '' }]);
        }
        if (a1.textHeight !== undefined) {
            this.textHeight = a1.textHeight;
        }
        if (a1.titleHeight !== undefined) {
            this.titleHeight = a1.titleHeight;
        }
        if (a1.applyHeight !== undefined) {
            this.applyHeight = a1.applyHeight;
        }
        if (a1.buttonHeight !== undefined) {
            this.buttonHeight = a1.buttonHeight;
        }
        if (a1.messageMaxWeight !== undefined) {
            this.messageMaxWeight = a1.messageMaxWeight;
        }
        if (a1.beforeScreenStatus !== undefined) {
            this.beforeScreenStatus = a1.beforeScreenStatus;
        }
        if (a1.currentScreenStatus !== undefined) {
            this.currentScreenStatus = a1.currentScreenStatus;
        }
        if (a1.applySizeOptions !== undefined) {
            this.applySizeOptions = a1.applySizeOptions;
        }
        if (a1.closeButtonBackgroundColor !== undefined) {
            this.closeButtonBackgroundColor = a1.closeButtonBackgroundColor;
        }
        if (a1.firstButtonBackgroundColor !== undefined) {
            this.firstButtonBackgroundColor = a1.firstButtonBackgroundColor;
        }
        if (a1.secondButtonBackgroundColor !== undefined) {
            this.secondButtonBackgroundColor = a1.secondButtonBackgroundColor;
        }
        if (a1.listener !== undefined) {
            this.listener = a1.listener;
        }
    }

    updateStateVars(a1) {
        this.__icon.reset(a1.icon);
        this.__title.reset(a1.title);
        this.__message.reset(a1.message);
        this.__showClose.reset(a1.showClose);
        this.__buttons.reset(a1.buttons);
    }

    purgeVariableDependenciesOnElmtId(z) {
        this.__icon.purgeDependencyOnElmtId(z);
        this.__title.purgeDependencyOnElmtId(z);
        this.__message.purgeDependencyOnElmtId(z);
        this.__showClose.purgeDependencyOnElmtId(z);
        this.__buttons.purgeDependencyOnElmtId(z);
        this.__titleHeight.purgeDependencyOnElmtId(z);
        this.__applyHeight.purgeDependencyOnElmtId(z);
        this.__buttonHeight.purgeDependencyOnElmtId(z);
        this.__messageMaxWeight.purgeDependencyOnElmtId(z);
        this.__beforeScreenStatus.purgeDependencyOnElmtId(z);
        this.__currentScreenStatus.purgeDependencyOnElmtId(z);
        this.__applySizeOptions.purgeDependencyOnElmtId(z);
        this.__closeButtonBackgroundColor.purgeDependencyOnElmtId(z);
        this.__firstButtonBackgroundColor.purgeDependencyOnElmtId(z);
        this.__secondButtonBackgroundColor.purgeDependencyOnElmtId(z);
    }

    aboutToBeDeleted() {
        this.__icon.aboutToBeDeleted();
        this.__title.aboutToBeDeleted();
        this.__message.aboutToBeDeleted();
        this.__showClose.aboutToBeDeleted();
        this.__buttons.aboutToBeDeleted();
        this.__titleHeight.aboutToBeDeleted();
        this.__applyHeight.aboutToBeDeleted();
        this.__buttonHeight.aboutToBeDeleted();
        this.__messageMaxWeight.aboutToBeDeleted();
        this.__beforeScreenStatus.aboutToBeDeleted();
        this.__currentScreenStatus.aboutToBeDeleted();
        this.__applySizeOptions.aboutToBeDeleted();
        this.__closeButtonBackgroundColor.aboutToBeDeleted();
        this.__firstButtonBackgroundColor.aboutToBeDeleted();
        this.__secondButtonBackgroundColor.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    get icon() {
        return this.__icon.get();
    }

    set icon(y) {
        this.__icon.set(y);
    }

    get title() {
        return this.__title.get();
    }

    set title(y) {
        this.__title.set(y);
    }

    get message() {
        return this.__message.get();
    }

    set message(y) {
        this.__message.set(y);
    }

    get showClose() {
        return this.__showClose.get();
    }

    set showClose(y) {
        this.__showClose.set(y);
    }

    get buttons() {
        return this.__buttons.get();
    }

    set buttons(y) {
        this.__buttons.set(y);
    }

    get titleHeight() {
        return this.__titleHeight.get();
    }

    set titleHeight(y) {
        this.__titleHeight.set(y);
    }

    get applyHeight() {
        return this.__applyHeight.get();
    }

    set applyHeight(y) {
        this.__applyHeight.set(y);
    }

    get buttonHeight() {
        return this.__buttonHeight.get();
    }

    set buttonHeight(y) {
        this.__buttonHeight.set(y);
    }

    get messageMaxWeight() {
        return this.__messageMaxWeight.get();
    }

    set messageMaxWeight(y) {
        this.__messageMaxWeight.set(y);
    }

    get beforeScreenStatus() {
        return this.__beforeScreenStatus.get();
    }

    set beforeScreenStatus(y) {
        this.__beforeScreenStatus.set(y);
    }

    get currentScreenStatus() {
        return this.__currentScreenStatus.get();
    }

    set currentScreenStatus(y) {
        this.__currentScreenStatus.set(y);
    }

    get applySizeOptions() {
        return this.__applySizeOptions.get();
    }

    set applySizeOptions(y) {
        this.__applySizeOptions.set(y);
    }

    get closeButtonBackgroundColor() {
        return this.__closeButtonBackgroundColor.get();
    }

    set closeButtonBackgroundColor(y) {
        this.__closeButtonBackgroundColor.set(y);
    }

    get firstButtonBackgroundColor() {
        return this.__firstButtonBackgroundColor.get();
    }

    set firstButtonBackgroundColor(y) {
        this.__firstButtonBackgroundColor.set(y);
    }

    get secondButtonBackgroundColor() {
        return this.__secondButtonBackgroundColor.get();
    }

    set secondButtonBackgroundColor(y) {
        this.__secondButtonBackgroundColor.set(y);
    }

    getIconWidth() {
        var d, e;
        return (e = (d = this.icon) === null || d === void 0 ? void 0 : d.width) !== null && e !== void 0 ? e : this.theme.icon.size.width;
    }

    getIconHeight() {
        var d, e;
        return (e = (d = this.icon) === null || d === void 0 ? void 0 : d.height) !== null && e !== void 0 ? e : this.theme.icon.size.height;
    }

    getIconFillColor() {
        var d, e;
        return (e = (d = this.icon) === null || d === void 0 ? void 0 : d.fillColor) !== null && e !== void 0 ? e : this.theme.icon.fillColor;
    }

    getIconBorderRadius() {
        var d, e;
        return (e = (d = this.icon) === null || d === void 0 ? void 0 : d.borderRadius) !== null && e !== void 0 ? e : this.theme.icon.borderRadius;
    }

    getIconMargin() {
        return { left: this.theme.button.margin.left / 2,
            right: this.theme.icon.margin.right - (this.theme.button.margin.right / 2) };
    }

    getIconImage() {
        var d;
        return (d = this.icon) === null || d === void 0 ? void 0 : d.image;
    }

    getTitleText() {
        var d;
        return (d = this.title) === null || d === void 0 ? void 0 : d.text;
    }

    getTitlePadding() {
        return { left: this.theme.button.margin.left / 2, right: this.theme.closeButton.margin.right };
    }

    getTitleMargin() {
        return this.theme.title.margin;
    }

    getTitleMinFontSize() {
        return this.theme.title.minFontSize;
    }

    getTitleFontWeight() {
        var d, e;
        return (e = (d = this.title) === null || d === void 0 ? void 0 : d.fontWeight) !== null && e !== void 0 ? e : this.theme.title.fontWeight;
    }

    getTitleFontSize() {
        var d, e;
        return (e = (d = this.title) === null || d === void 0 ? void 0 : d.fontSize) !== null && e !== void 0 ? e : this.theme.title.fontSize;
    }

    getTitleFontColor() {
        var d, e;
        return (e = (d = this.title) === null || d === void 0 ? void 0 : d.fontColor) !== null && e !== void 0 ? e : this.theme.title.fontColor;
    }

    getCloseButtonWidth() {
        return this.theme.closeButton.size.width;
    }

    getCloseButtonHeight() {
        return this.theme.closeButton.size.height;
    }

    getCloseButtonImage() {
        return this.theme.closeButton.image;
    }

    getCloseButtonFillColor() {
        return this.theme.closeButton.fillColor;
    }

    getCloseButtonHoverColor() {
        return this.theme.closeButton.hoverColor;
    }

    getCloseButtonBackgroundColor() {
        return this.theme.closeButton.backgroundColor;
    }

    getCloseButtonPadding() {
        return this.theme.closeButton.padding;
    }

    getCloseButtonImageWidth() {
        return this.theme.closeButton.imageSize.width;
    }

    getCloseButtonImageHeight() {
        return this.theme.closeButton.imageSize.height;
    }

    getMessageText() {
        return this.message.text;
    }

    getMessageFontSize() {
        var d;
        return (d = this.message.fontSize) !== null && d !== void 0 ? d : this.theme.message.fontSize;
    }

    getMessageFontColor() {
        let x;
        if (this.message.fontColor) {
            x = this.message.fontColor;
        }
        else {
            if (this.title.text !== '' && this.title.text !== void (0)) {
                x = this.theme.message.fontColor;
            }
            else {
                x = this.theme.message.plainFontColor;
            }
        }
        return x;
    }

    getMessagePadding() {
        let w;
        if (this.title.text !== '' && this.title.text !== void (0)) {
            w = { left: this.theme.button.margin.left / 2 };
        }
        else {
            w = { left: this.theme.button.margin.left / 2, right: this.theme.closeButton.margin.right };
        }
        return w;
    }

    getMessageMaxWeight() {
        let v = undefined;
        let n = display.getDefaultDisplaySync();
        if (this.showClose || this.showClose === void (0)) {
            if (px2vp(n.width) > 400) {
                v = 400;
            }
            else {
                v = px2vp(n.width) - 40 - 40;
            }
            v -= (this.theme.windows.padding.left - (this.theme.button.margin.right / 2));
            v -= this.theme.windows.padding.right;
            v -= this.theme.button.margin.left / 2;
            v -= this.getCloseButtonWidth();
        }
        return v;
    }

    getMessageFontWeight() {
        return this.theme.message.fontWeight;
    }

    getButtonMargin() {
        return { top: this.theme.button.textMargin.top / 2 - 4,
            bottom: this.theme.button.textMargin.bottom / 2 - 4,
            left: this.theme.button.margin.left / 2 - 4,
            right: this.theme.button.margin.right / 2 - 4
        };
    }

    getButtonTextMargin() {
        return { top: this.theme.button.textMargin.bottom / 2 };
    }

    getButtonTextPadding() {
        return this.theme.button.padding;
    }

    getButtonHoverColor() {
        return this.theme.button.hoverColor;
    }

    getButtonBackgroundColor() {
        return this.theme.button.backgroundColor;
    }

    getFirstButtonText() {
        var d, e;
        return (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.text;
    }

    getSecondButtonText() {
        var d, e;
        return (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.text;
    }

    getFirstButtonFontSize() {
        var d, e, f;
        return (f = (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.fontSize) !== null && f !== void 0 ? f : this.theme.button.fontSize;
    }

    getSecondButtonFontSize() {
        var d, e, f;
        return (f = (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.fontSize) !== null && f !== void 0 ? f : this.theme.button.fontSize;
    }

    getFirstButtonFontColor() {
        var d, e, f;
        return (f = (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.fontColor) !== null && f !== void 0 ? f : this.theme.button.fontColor;
    }

    getSecondButtonFontColor() {
        var d, e, f;
        return (f = (e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.fontColor) !== null && f !== void 0 ? f : this.theme.button.fontColor;
    }

    getButtonMinFontSize() {
        return this.theme.button.minFontSize;
    }

    getButtonFontWeight() {
        return this.theme.button.fontWeight;
    }

    getWindowsPadding() {
        return {
            top: this.theme.windows.padding.top,
            bottom: this.theme.windows.padding.bottom - (this.theme.button.textMargin.bottom / 2),
            left: this.theme.windows.padding.left - (this.theme.button.margin.right / 2),
            right: this.theme.windows.padding.right
        };
    }

    onWillApplyTheme(o10) {
        this.theme.title.fontColor = o10.colors.fontPrimary;
        this.theme.button.fontColor = o10.colors.fontEmphasize;
        this.theme.message.fontColor = o10.colors.fontSecondary;
        this.theme.message.plainFontColor = o10.colors.fontPrimary;
        this.theme.closeButton.fillColor = o10.colors.iconSecondary;
    }

    aboutToAppear() {
        this.listener.on("change", (u) => {
            this.currentScreenStatus = u.matches;
        });
    }

    aboutToDisappear() {
        this.listener.off("change");
    }

    getScrollMaxHeight() {
        let t = undefined;
        if (this.currentScreenStatus !== this.beforeScreenStatus) {
            this.applySizeOptions = this.getApplyMaxSize();
            this.beforeScreenStatus = this.currentScreenStatus;
            return t;
        }
        t = this.applyHeight;
        t -= this.titleHeight;
        t -= this.buttonHeight;
        t -= this.theme.windows.padding.top;
        t -= (this.theme.button.textMargin.bottom / 2);
        t -= this.theme.title.margin.bottom;
        t -= (this.theme.windows.padding.bottom - (this.theme.button.textMargin.bottom / 2));
        if (Math.floor(this.textHeight) > Math.floor(t + 1)) {
            return t;
        }
        else {
            t = undefined;
            return t;
        }
    }

    getLayoutWeight() {
        var d, e, f, g, o, p, q, r;
        let s;
        if ((this.icon.image !== '' && this.icon.image !== void (0)) ||
            (this.title.text !== '' && this.title.text !== void (0)) ||
            (((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.text) !== '' && ((g = (f = this.buttons) === null || f === void 0 ? void 0 : f[0]) === null || g === void 0 ? void 0 : g.text) !== void (0)) ||
            (((p = (o = this.buttons) === null || o === void 0 ? void 0 : o[1]) === null || p === void 0 ? void 0 : p.text) !== '' && ((r = (q = this.buttons) === null || q === void 0 ? void 0 : q[1]) === null || r === void 0 ? void 0 : r.text) !== void (0))) {
            s = 1;
        }
        else {
            s = 0;
        }
        return s;
    }

    getApplyMaxSize() {
        let k = undefined;
        let l = undefined;
        let m = undefined;
        let n = display.getDefaultDisplaySync();
        if (px2vp(n.width) > 400) {
            k = 400;
        }
        else {
            k = px2vp(n.width) - 40 - 40;
        }
        if (px2vp(n.height) > 480) {
            l = 480;
        }
        else {
            l = px2vp(n.height) - 40 - 40;
        }
        m = { maxWidth: k, maxHeight: l };
        this.messageMaxWeight = this.getMessageMaxWeight();
        return m;
    }

    initialRender() {
        this.observeComponentCreation2((b, c) => {
            Row.create();
            Row.alignItems(VerticalAlign.Top);
            Row.padding(this.getWindowsPadding());
            Row.constraintSize(ObservedObject.GetRawObject(this.applySizeOptions));
            Row.onAreaChange((i, j) => {
                this.applyHeight = j.height;
            });
        }, Row);
        this.observeComponentCreation2((b, c) => {
            If.create();
            if (this.icon.image !== '' && this.icon.image !== void (0)) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((b, c) => {
                        Image.create(this.getIconImage());
                        Image.width(this.getIconWidth());
                        Image.height(this.getIconHeight());
                        Image.margin(this.getIconMargin());
                        Image.fillColor(this.getIconFillColor());
                        Image.borderRadius(this.getIconBorderRadius());
                    }, Image);
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                });
            }
        }, If);
        If.pop();
        this.observeComponentCreation2((b, c) => {
            If.create();
            if (this.title.text !== '' && this.title.text !== void (0)) {
                this.ifElseBranchUpdateFunction(0, () => {
                    this.observeComponentCreation2((b, c) => {
                        Column.create();
                        Column.layoutWeight(this.getLayoutWeight());
                    }, Column);
                    this.observeComponentCreation2((b, c) => {
                        Flex.create({ alignItems: ItemAlign.Start });
                        Flex.width("100%");
                        Flex.margin(this.getTitleMargin());
                        Flex.onAreaChange((i, j) => {
                            this.titleHeight = j.height;
                        });
                    }, Flex);
                    this.observeComponentCreation2((b, c) => {
                        Text.create(this.getTitleText());
                        Text.flexGrow(1);
                        Text.maxLines(2);
                        Text.align(Alignment.Start);
                        Text.padding(this.getTitlePadding());
                        Text.minFontSize(this.getTitleMinFontSize());
                        Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                        Text.fontWeight(this.getTitleFontWeight());
                        Text.fontSize(this.getTitleFontSize());
                        Text.fontColor(this.getTitleFontColor());
                        Text.constraintSize({ minHeight: this.getCloseButtonHeight() });
                    }, Text);
                    Text.pop();
                    this.observeComponentCreation2((b, c) => {
                        If.create();
                        if (this.showClose || this.showClose === void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.width(this.getCloseButtonWidth());
                                    Button.height(this.getCloseButtonHeight());
                                    Button.padding(this.getCloseButtonPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.closeButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.closeButtonBackgroundColor = this.getCloseButtonHoverColor();
                                        }
                                        else {
                                            this.closeButtonBackgroundColor = this.getCloseButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        if (this.onClose) {
                                            this.onClose();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Image.create(this.getCloseButtonImage());
                                    Image.focusable(true);
                                    Image.width(this.getCloseButtonImageWidth());
                                    Image.height(this.getCloseButtonImageHeight());
                                    Image.fillColor(this.getCloseButtonFillColor());
                                }, Image);
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    Flex.pop();
                    this.observeComponentCreation2((b, c) => {
                        Scroll.create();
                        Scroll.width("100%");
                        Scroll.align(Alignment.TopStart);
                        Scroll.padding(this.getMessagePadding());
                        Scroll.scrollBar(BarState.Auto);
                        Scroll.scrollable(ScrollDirection.Vertical);
                        Scroll.constraintSize({ maxHeight: this.getScrollMaxHeight() });
                    }, Scroll);
                    this.observeComponentCreation2((b, c) => {
                        Text.create(this.getMessageText());
                        Text.fontSize(this.getMessageFontSize());
                        Text.fontColor(this.getMessageFontColor());
                        Text.fontWeight(this.getMessageFontWeight());
                        Text.constraintSize({ minHeight: this.getCloseButtonHeight() });
                        Text.onAreaChange((i, j) => {
                            this.textHeight = j.height;
                        });
                    }, Text);
                    Text.pop();
                    Scroll.pop();
                    this.observeComponentCreation2((b, c) => {
                        Flex.create({ wrap: FlexWrap.Wrap });
                        Flex.margin(this.getButtonTextMargin());
                        Flex.flexGrow(1);
                        Flex.onAreaChange((i, j) => {
                            this.buttonHeight = j.height;
                        });
                    }, Flex);
                    this.observeComponentCreation2((b, c) => {
                        var d, e, f, g;
                        If.create();
                        if (((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.text) !== '' && ((g = (f = this.buttons) === null || f === void 0 ? void 0 : f[0]) === null || g === void 0 ? void 0 : g.text) !== void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.margin(this.getButtonMargin());
                                    Button.padding(this.getButtonTextPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.firstButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.firstButtonBackgroundColor = this.getButtonHoverColor();
                                        }
                                        else {
                                            this.firstButtonBackgroundColor = this.getButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        var d, e, f, g;
                                        if ((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.action) {
                                            (g = (f = this.buttons) === null || f === void 0 ? void 0 : f[0]) === null || g === void 0 ? void 0 : g.action();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Text.create(this.getFirstButtonText());
                                    Text.maxLines(2);
                                    Text.focusable(true);
                                    Text.fontSize(this.getFirstButtonFontSize());
                                    Text.fontColor(this.getFirstButtonFontColor());
                                    Text.fontWeight(this.getButtonFontWeight());
                                    Text.minFontSize(this.getButtonMinFontSize());
                                    Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                }, Text);
                                Text.pop();
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    this.observeComponentCreation2((b, c) => {
                        var d, e, f, g;
                        If.create();
                        if (((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.text) !== '' && ((g = (f = this.buttons) === null || f === void 0 ? void 0 : f[1]) === null || g === void 0 ? void 0 : g.text) !== void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.margin(this.getButtonMargin());
                                    Button.padding(this.getButtonTextPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.secondButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.secondButtonBackgroundColor = this.getButtonHoverColor();
                                        }
                                        else {
                                            this.secondButtonBackgroundColor = this.getButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        var d, e, f, g;
                                        if ((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.action) {
                                            (g = (f = this.buttons) === null || f === void 0 ? void 0 : f[1]) === null || g === void 0 ? void 0 : g.action();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Text.create(this.getSecondButtonText());
                                    Text.maxLines(2);
                                    Text.focusable(true);
                                    Text.fontSize(this.getSecondButtonFontSize());
                                    Text.fontColor(this.getSecondButtonFontColor());
                                    Text.fontWeight(this.getButtonFontWeight());
                                    Text.minFontSize(this.getButtonMinFontSize());
                                    Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                }, Text);
                                Text.pop();
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    Flex.pop();
                    Column.pop();
                });
            }
            else {
                this.ifElseBranchUpdateFunction(1, () => {
                    this.observeComponentCreation2((b, c) => {
                        Column.create();
                        Column.layoutWeight(this.getLayoutWeight());
                    }, Column);
                    this.observeComponentCreation2((b, c) => {
                        Row.create();
                        Row.alignItems(VerticalAlign.Top);
                        Row.margin(this.getTitleMargin());
                    }, Row);
                    this.observeComponentCreation2((b, c) => {
                        Scroll.create();
                        Scroll.layoutWeight(this.getLayoutWeight());
                        Scroll.align(Alignment.TopStart);
                        Scroll.padding(this.getMessagePadding());
                        Scroll.scrollBar(BarState.Auto);
                        Scroll.scrollable(ScrollDirection.Vertical);
                        Scroll.constraintSize({ maxHeight: this.getScrollMaxHeight() });
                    }, Scroll);
                    this.observeComponentCreation2((b, c) => {
                        Text.create(this.getMessageText());
                        Text.fontSize(this.getMessageFontSize());
                        Text.fontColor(this.getMessageFontColor());
                        Text.fontWeight(this.getMessageFontWeight());
                        Text.constraintSize({
                            maxWidth: this.messageMaxWeight,
                            minHeight: this.getCloseButtonHeight()
                        });
                        Text.onAreaChange((i, j) => {
                            this.textHeight = j.height;
                        });
                    }, Text);
                    Text.pop();
                    Scroll.pop();
                    this.observeComponentCreation2((b, c) => {
                        If.create();
                        if (this.showClose || this.showClose === void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.width(this.getCloseButtonWidth());
                                    Button.height(this.getCloseButtonHeight());
                                    Button.padding(this.getCloseButtonPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.closeButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.closeButtonBackgroundColor = this.getCloseButtonHoverColor();
                                        }
                                        else {
                                            this.closeButtonBackgroundColor = this.getCloseButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        if (this.onClose) {
                                            this.onClose();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Image.create(this.getCloseButtonImage());
                                    Image.focusable(true);
                                    Image.width(this.getCloseButtonImageWidth());
                                    Image.height(this.getCloseButtonImageHeight());
                                    Image.fillColor(this.getCloseButtonFillColor());
                                }, Image);
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    Row.pop();
                    this.observeComponentCreation2((b, c) => {
                        Flex.create({ wrap: FlexWrap.Wrap });
                        Flex.margin(this.getButtonTextMargin());
                        Flex.flexGrow(1);
                        Flex.onAreaChange((i, j) => {
                            this.buttonHeight = j.height;
                        });
                    }, Flex);
                    this.observeComponentCreation2((b, c) => {
                        var d, e, f, g;
                        If.create();
                        if (((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.text) !== '' && ((g = (f = this.buttons) === null || f === void 0 ? void 0 : f[0]) === null || g === void 0 ? void 0 : g.text) !== void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.margin(this.getButtonMargin());
                                    Button.padding(this.getButtonTextPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.firstButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.firstButtonBackgroundColor = this.getButtonHoverColor();
                                        }
                                        else {
                                            this.firstButtonBackgroundColor = this.getButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        var d, e, f, g;
                                        if ((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[0]) === null || e === void 0 ? void 0 : e.action) {
                                            (g = (f = this.buttons) === null || f === void 0 ? void 0 : f[0]) === null || g === void 0 ? void 0 : g.action();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Text.create(this.getFirstButtonText());
                                    Text.maxLines(2);
                                    Text.focusable(true);
                                    Text.fontSize(this.getFirstButtonFontSize());
                                    Text.fontColor(this.getFirstButtonFontColor());
                                    Text.fontWeight(this.getButtonFontWeight());
                                    Text.minFontSize(this.getButtonMinFontSize());
                                    Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                }, Text);
                                Text.pop();
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    this.observeComponentCreation2((b, c) => {
                        var d, e, f, g;
                        If.create();
                        if (((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.text) !== '' && ((g = (f = this.buttons) === null || f === void 0 ? void 0 : f[1]) === null || g === void 0 ? void 0 : g.text) !== void (0)) {
                            this.ifElseBranchUpdateFunction(0, () => {
                                this.observeComponentCreation2((b, c) => {
                                    Button.createWithChild();
                                    Button.margin(this.getButtonMargin());
                                    Button.padding(this.getButtonTextPadding());
                                    Button.backgroundColor(ObservedObject.GetRawObject(this.secondButtonBackgroundColor));
                                    Button.onHover((h) => {
                                        if (h) {
                                            this.secondButtonBackgroundColor = this.getButtonHoverColor();
                                        }
                                        else {
                                            this.secondButtonBackgroundColor = this.getButtonBackgroundColor();
                                        }
                                    });
                                    Button.onClick(() => {
                                        var d, e, f, g;
                                        if ((e = (d = this.buttons) === null || d === void 0 ? void 0 : d[1]) === null || e === void 0 ? void 0 : e.action) {
                                            (g = (f = this.buttons) === null || f === void 0 ? void 0 : f[1]) === null || g === void 0 ? void 0 : g.action();
                                        }
                                    });
                                }, Button);
                                this.observeComponentCreation2((b, c) => {
                                    Text.create(this.getSecondButtonText());
                                    Text.maxLines(2);
                                    Text.focusable(true);
                                    Text.fontSize(this.getSecondButtonFontSize());
                                    Text.fontColor(this.getSecondButtonFontColor());
                                    Text.fontWeight(this.getButtonFontWeight());
                                    Text.minFontSize(this.getButtonMinFontSize());
                                    Text.textOverflow({ overflow: TextOverflow.Ellipsis });
                                }, Text);
                                Text.pop();
                                Button.pop();
                            });
                        }
                        else {
                            this.ifElseBranchUpdateFunction(1, () => {
                            });
                        }
                    }, If);
                    If.pop();
                    Flex.pop();
                    Column.pop();
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
export default { Popup };