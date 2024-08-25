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

/**
 *  SDK API of Repeat and its attribute functions.
 */

interface RepeatItem<T> {
    readonly item: T,
    readonly index?: number
}

type RepeatItemGenFunc<T> = (i: RepeatItem<T>) => void;
type RepeatKeyGenFunc<T> = (item: T, index?: number) => string;
type OnMoveHandler = (from: number, to: number) => void;

/*
    global function Repeat()
    returns an object that retains the state of Repeat instance between render calls
    exec attribute functions on this instance.
*/
const Repeat: <T>(arr: Array<T>, owningView?: PUV2ViewBase) => RepeatAPI<T> =
    <T>(arr: Array<T>, owningView?: PUV2ViewBase): RepeatAPI<T> => {
        if (!owningView) {
            throw new Error("Transpilation error, Repeat lacks 2nd parameter owningView");
        }
        return owningView!.__mkRepeatAPI(arr);
    }

/*
    repeat attribute function and internal function render()
*/
interface RepeatAPI<T> {
    each: (itemGenFunc: RepeatItemGenFunc<T>) => RepeatAPI<T>;  // chainable, call in this order
    key: (keyGenFunc: RepeatKeyGenFunc<T>) => RepeatAPI<T>;
    virtualScroll: () => RepeatAPI<T>;
    onMove: (handler: OnMoveHandler) => RepeatAPI<T>;

    // do NOT use in app, transpiler adds as last of chained call
    render(isInitialRender: boolean): void;       
}
